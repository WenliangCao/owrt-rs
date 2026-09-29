#!/usr/bin/env python3
"""Assemble and audit a native nine-component image. Never contacts a router.

The existing SDK builds remain the binary provenance source. One APK owns the
nine standard paths using APK's explicit file-replacement metadata; official
packages still supply their libraries, init scripts, helpers and configuration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request


REPO = Path(__file__).resolve().parent.parent
STOCK = "usr/libexec/owrt-stock"
METADATA = "usr/share/owrt-control-plane"
LEGACY = {"owrt-" + c for c in
          ("uci", "reload-config", "logd", "httpd", "fw4", "rpcd", "switch", "ubusd")}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True).strip()


def packages(apk, root):
    return {p["name"]: p for p in json.loads(run(
        apk, "--root", root, "--no-network", "query", "--from", "installed",
        "--format", "json", "--fields", "name,version,license", "*"))}


def install(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)


def preserve_directory_modes(payload, base):
    # APK applies directory modes too. Match the original image instead of
    # letting the builder's umask silently change shared /usr or /etc paths.
    for path in [payload, *payload.rglob("*")]:
        reference = base / path.relative_to(payload)
        if path.is_dir() and not path.is_symlink() and reference.is_dir():
            path.chmod(reference.stat().st_mode & 0o7777)


def fetch(work, spec, apk):
    del apk
    native = work / "native"
    native.mkdir(exist_ok=False)
    for key, filename in (("stock_image", spec["stock_image"]["file"]),
                          ("luci_source", "luci-" + spec["luci_source"]["revision"] + ".tar.gz")):
        source = spec[key]
        target = work / "dl" / filename
        if not target.exists():
            with urllib.request.urlopen(source["url"], timeout=90) as response, target.open("wb") as stream:
                shutil.copyfileobj(response, stream)
        assert sha(target) == source["sha256"], f"immutable input mismatch: {key}"
    subprocess.run(["tar", "-xf", str(work / "dl" / ("luci-" + spec["luci_source"]["revision"] + ".tar.gz")),
                    "-C", str(native)], check=True)


def prepare(work, spec, apk):
    out = work / "out"
    root = work / "native/base-rootfs"
    binary_root = work / "verify/rootfs"
    image = read(out / "manifest.json")
    core = read(out / "core-manifest.json")
    assert image["source_commit"] == core["source_commit"]
    assert image["openwrt"] == core["openwrt"] == spec["openwrt"]
    assert core["image_manifest_sha256"] == sha(out / "manifest.json")
    hashes = image["binary_sha256"] | core["binary_sha256"]
    assert set(hashes) == {c["binary"] for c in spec["components"].values()}
    installed = packages(apk, root)
    owners = sorted({c["stock_package"] for c in spec["components"].values()})
    payload = work / "native/payload"
    payload.mkdir(parents=True, exist_ok=False)
    components = {}
    rust_sums, stock_sums = [], []
    for name, c in spec["components"].items():
        path = c["path"].lstrip("/")
        original = root / path
        assert sha(original) == c["stock_sha256"], f"stock identity drift: {path}"
        owner = run(apk, "--root", root, "--no-network", "info", "--who-owns", c["path"])
        assert owner.endswith(" is owned by " + c["stock_package"] + "-" + installed[c["stock_package"]]["version"])
        binary = (out / "core-binaries" if name in ("procd", "ubusd", "netifd")
                  else binary_root / "usr/sbin") / c["binary"]
        assert sha(binary) == hashes[c["binary"]], f"Rust identity drift: {name}"
        install(binary, payload / path)
        install(original, payload / STOCK / path)
        components[name] = dict(c, rust_sha256=sha(binary), rust_bytes=binary.stat().st_size,
                                recovery_path="/" + STOCK + "/" + path)
        rust_sums.append(f"{sha(binary)}  /{path}\n")
        stock_sums.append(f"{sha(original)}  /{STOCK}/{path}\n")
    manifest = {
        "schema": 1, "layout": "native-nine", "source_commit": image["source_commit"],
        "openwrt": spec["openwrt"], "profile": spec["profile"],
        "package": spec["package"], "version": spec["version"],
        "components": components,
        "stock_image": spec["stock_image"],
        "luci_source": spec["luci_source"], "translations": spec["translations"],
        "stock_packages": {p: installed[p] for p in owners},
        "recovery": "owrt-recover-c stages all nine stock programs; reboot separately",
    }
    write(payload / METADATA / "release.json", manifest)
    (payload / METADATA / "rust.sha256").write_text("".join(rust_sums))
    (payload / METADATA / "stock.sha256").write_text("".join(stock_sums))
    install(REPO / "packaging/image/owrt-recover-c", payload / "usr/sbin/owrt-recover-c")
    install(REPO / "packaging/image/05-owrt-native", payload / "etc/uci-defaults/05-owrt-native")
    keep = payload / "lib/upgrade/keep.d/owrt-control-plane"
    keep.parent.mkdir(parents=True, exist_ok=True)
    keep.write_text("/etc/owrt-control-plane-layout\n")
    # OpenWrt's conffile tooling also expects its package file list.
    listing = payload / "lib/apk/packages" / (spec["package"] + ".list")
    listing.parent.mkdir(parents=True, exist_ok=True)
    listing.write_text("\n".join(sorted("/" + str(p.relative_to(payload))
                       for p in payload.rglob("*") if p.is_file())) + "\n")
    preserve_directory_modes(payload, root)
    epoch = int(run("git", "-C", REPO, "show", "-s", "--format=%ct", image["source_commit"]))
    for path in [*payload.rglob("*"), payload]:
        os.utime(path, (epoch, epoch))
    # Explicit root ownership; the payload is disposable and contains no
    # machine configuration. Do not rely on the builder's uid leaking into APK.
    subprocess.run(["sudo", "-n", "chown", "-R", "0:0", str(payload)], check=True)
    package = work / "native" / f"{spec['package']}-{spec['version']}.apk"
    dependencies = [p + "=" + installed[p]["version"] for p in owners]
    dependencies += ["!" + p for p in sorted(LEGACY)]
    licenses = sorted({installed[p]["license"] for p in owners})
    info = {"name": spec["package"], "version": spec["version"],
            "arch": spec["architecture"], "description": "Nine native Rust OpenWrt control-plane components",
            "license": " AND ".join(["(MIT OR Apache-2.0)", *licenses]),
            "origin": "owrt-control-plane-rs", "url": "https://github.com/WenliangCao/owrt-control-plane-rs",
            "depends": " ".join(dependencies), "replaces": " ".join(owners), "replaces-priority": "100"}
    args = [str(apk), "mkpkg", "--files", str(payload), "--output", str(package)]
    for key, value in info.items():
        args += ["--info", key + ":" + value]
    subprocess.run(args, check=True)
    # Match the four Chinese catalogs already in production, from the exact
    # LuCI source revision. Rolling feeds would silently upgrade unrelated code.
    luci = work / "native" / ("luci-" + spec["luci_source"]["revision"])
    compiler = luci / "modules/luci-base/src/po2lmo"
    subprocess.run(["make", "-C", str(compiler.parent), "po2lmo"], check=True)
    for name, translation in spec["translations"].items():
        package_name = "luci-i18n-" + name + "-zh-cn"
        files = work / "native/translations" / package_name
        catalog = files / "usr/lib/lua/luci/i18n" / (name + ".zh-cn.lmo")
        catalog.parent.mkdir(parents=True, exist_ok=True)
        run(compiler, luci / translation["source"] / "po/zh_Hans" / (name + ".po"), catalog)
        assert sha(catalog) == translation["sha256"], f"production translation drift: {name}"
        defaults = files / "etc/uci-defaults" / package_name
        defaults.parent.mkdir(parents=True, exist_ok=True)
        defaults.write_text("uci set luci.languages.zh_cn='简体中文 (Simplified Chinese)'; uci commit luci\n")
        listing = files / "lib/apk/packages" / (package_name + ".list")
        listing.parent.mkdir(parents=True, exist_ok=True)
        listing.write_text("/" + str(defaults.relative_to(files)) + "\n/" + str(catalog.relative_to(files)) + "\n")
        preserve_directory_modes(files, root)
        for path in [*files.rglob("*"), files]:
            os.utime(path, (epoch, epoch))
        subprocess.run(["sudo", "-n", "chown", "-R", "0:0", str(files)], check=True)
        run(apk, "mkpkg", "--files", files,
            "--output", work / "native" / (package_name + "-" + spec["luci_source"]["version"] + ".apk"),
            "--info", "name:" + package_name, "--info", "version:" + spec["luci_source"]["version"],
            "--info", "arch:noarch", "--info", "license:" + translation["license"],
            "--info", "description:Chinese translation for " + translation["package"],
            "--info", "depends:libc " + translation["package"] + "=" + installed[translation["package"]]["version"])
    write(work / "native/build-inputs.json", {"image": image, "core": core,
          "package_metadata": info, "package_sha256": sha(package)})
    print(f"Prepared {package.name}: nine native paths, nine verified stock recovery copies")


def verify(work, spec, apk):
    root = work / "native/rootfs"
    before = work / "native/base-rootfs"
    manifest = read(work / "native/payload" / METADATA / "release.json")
    assert read(root / METADATA / "release.json") == manifest
    installed, previous = packages(apk, root), packages(apk, before)
    translations = {"luci-i18n-" + n + "-zh-cn" for n in spec["translations"]}
    assert set(installed) == set(previous) | {spec["package"]} | translations
    for name, pkg in previous.items():
        assert installed[name] == pkg, f"execution-plane package drift: {name}"
    for name, translation in spec["translations"].items():
        assert sha(root / "usr/lib/lua/luci/i18n" / (name + ".zh-cn.lmo")) == translation["sha256"]
        assert installed["luci-i18n-" + name + "-zh-cn"]["version"] == spec["luci_source"]["version"]
    for c in manifest["components"].values():
        assert sha(root / c["path"].lstrip("/")) == c["rust_sha256"]
        assert sha(root / c["recovery_path"].lstrip("/")) == c["stock_sha256"]
        owner = run(apk, "--root", root, "--no-network", "info", "--who-owns", c["path"])
        assert owner.endswith(" is owned by " + spec["package"] + "-" + spec["version"]), owner
        assert not (root / "usr/sbin" / c["binary"]).exists()
    assert not list((root / "etc").glob("owrt-*.boot-enable"))
    assert not list((root / "etc/init.d").glob("owrt-*"))
    assert not list((root / "etc/rc.d").glob("*owrt-*"))
    assert not list((root / "root").iterdir())
    for service in ("log", "rpcd", "uhttpd", "network"):
        assert (root / "etc/init.d" / service).read_bytes() == (before / "etc/init.d" / service).read_bytes()
        assert any((root / "etc/rc.d").glob("S[0-9][0-9]" + service)), service
    for name in ("shadow", "passwd"):
        assert (root / "etc" / name).read_bytes() == (before / "etc" / name).read_bytes()
    for path in (before / "etc/config").iterdir():
        assert path.read_bytes() == (root / "etc/config" / path.name).read_bytes(), path.name
    # Compare the entire original filesystem, not another image assembled from
    # today's feed. Package versions alone do not prove unchanged content.
    replaced = {c["path"].lstrip("/") for c in manifest["components"].values()}
    excluded = {"etc/apk/world"}
    checked = 0
    for src in before.rglob("*"):
        relative = str(src.relative_to(before))
        if relative in replaced or relative in excluded or relative.startswith("lib/apk/db/"):
            continue
        dst = root / relative
        assert dst.lstat().st_mode == src.lstat().st_mode, relative
        assert (dst.lstat().st_uid, dst.lstat().st_gid) == (src.lstat().st_uid, src.lstat().st_gid), relative
        if src.is_symlink():
            assert dst.is_symlink() and os.readlink(src) == os.readlink(dst), relative
        elif src.is_file():
            assert dst.is_file() and sha(src) == sha(dst), relative
            checked += 1
    # Keep raw intermediate artifacts outside the final release directory.
    output = work / "native/out"
    output.mkdir(exist_ok=False)
    image = next((work / "native/bin").glob("*-sysupgrade.bin"))
    apks = sorted((work / "native").glob("*.apk"))
    for source in (image, *apks):
        shutil.copy2(source, output / source.name)
    inputs = read(work / "native/build-inputs.json")
    hashes = {c["binary"]: c["rust_sha256"] for c in manifest["components"].values()}
    result = dict(inputs["image"], schema_version=2, deployment_layout="native-nine",
                  packages={n: installed[n]["version"] for n in translations | {spec["package"]}}, components=manifest["components"],
                  binary_sha256=hashes, stock_packages=manifest["stock_packages"],
                  image={"file": image.name, "size": image.stat().st_size, "sha256": sha(image)},
                  apk_sha256={p.name: sha(p) for p in apks}, stock_image=spec["stock_image"],
                  luci_source=spec["luci_source"], translations=spec["translations"],
                  kernel_sha256=sha(next((work / "native/base-image").glob("sysupgrade-*/kernel"))),
                  imagebuilder_args={"assembly": "verified stock rootfs + offline APK install + official image tools",
                                     "rolling_feeds_used_for_final_rootfs": False},
                  validation={"nine_native_paths": True, "package_ownership": True,
                              "stock_recovery_hashes": True, "stock_service_scripts": True,
                              "stock_config_defaults": True, "unchanged_execution_files": checked,
                              "stock_package_versions_unchanged": len(previous),
                              "production_Chinese_catalogs_identical": len(translations),
                              "physical_boot_tested": False},
                  recovery=manifest["recovery"], flashed=False)
    write(output / "manifest.json", result)
    write(output / "build-inputs.json", inputs)
    (output / "binary-sha256.txt").write_text("".join(f"{h}  {n}\n" for n, h in sorted(hashes.items())))
    for source in (work / "out").glob("*.log"):
        shutil.copy2(source, output / source.name)
    for source in (work / "native").glob("*.log"):
        shutil.copy2(source, output / source.name)
    (output / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n"
        for p in sorted(output.iterdir()) if p.is_file()))
    print(json.dumps(result["validation"], indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "prepare", "verify"))
    parser.add_argument("work", type=Path)
    parser.add_argument("spec", type=Path)
    parser.add_argument("apk", type=Path)
    args = parser.parse_args()
    {"fetch": fetch, "prepare": prepare, "verify": verify}[args.action](
        args.work.resolve(), read(args.spec), args.apk.resolve())


if __name__ == "__main__":
    main()
