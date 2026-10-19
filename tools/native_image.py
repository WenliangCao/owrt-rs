#!/usr/bin/env python3
"""Assemble and audit an explicitly selected native image. Never contacts a router.

The existing SDK builds remain the binary provenance source. One APK owns the
standard paths using APK's explicit file-replacement metadata; official
packages supply their libraries, helpers and configuration. Two precisely
pinned dnsmasq integration files accompany its accepted SDK binary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request


REPO = Path(__file__).resolve().parent.parent
STOCK = "usr/libexec/owrt-stock"
METADATA = "usr/share/owrt-control-plane"
LEGACY = {"owrt-" + c for c in
          ("uci", "reload-config", "logd", "httpd", "fw4", "rpcd", "switch", "ubusd")}
NATIVE_TEN = {
    "fw4": ("/sbin/fw4", "fw4-rs", "firewall4"),
    "httpd": ("/usr/sbin/uhttpd", "httpd-rs", "uhttpd"),
    "logd": ("/sbin/logd", "logd-rs", "logd"),
    "netifd": ("/sbin/netifd", "netifd-rs", "netifd"),
    "procd": ("/sbin/procd", "procd-rs", "procd"),
    "reload-config": ("/sbin/reload_config", "reload_config_rs", "procd"),
    "rpcd": ("/sbin/rpcd", "rpcd-rs", "rpcd"),
    "ubusd": ("/sbin/ubusd", "ubusd-rs", "ubusd"),
    "uci": ("/sbin/uci", "uci-rs", "uci"),
    "dnsmasq": ("/usr/sbin/dnsmasq", "dnsmasq-rs", "dnsmasq"),
}
ODHCPD = {"odhcpd": ("/usr/sbin/odhcpd", "odhcpd-rs", "odhcpd-ipv6only")}


def native_layout(components):
    """Only the two reviewed complete inventories are valid, not arbitrary counts."""
    if set(components) == set(NATIVE_TEN):
        expected, layout = NATIVE_TEN, "native-ten"
    else:
        expected, layout = NATIVE_TEN | ODHCPD, "native-eleven"
        assert set(components) == set(expected), "unsupported native component inventory"
    for name, identity in expected.items():
        assert tuple(components[name].get(key) for key in ("path", "binary", "stock_package")) == identity, \
            f"native path/binary/owner mismatch: {name}"
    return layout


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True).strip()


def verify_ax3000t_fit(kernel, original, metadata):
    """Audit the FIT extracted from the final image against the pinned stock FIT."""
    expected = {
        "change": "disable-absent-mt7531-and-quiet-console", "hardware_variant": "AN8855-only",
        "bootargs_append": " loglevel=4",
        "node": "/soc/ethernet@15100000/mdio-bus/switch@1f", "status": "disabled",
        "source_date_epoch": 1782737960,
        "kernel_payload_sha1": "a422b6a6bfff051626511cdaf910bdae50365105",
        "original_dtb_sha256": "adcd474fcad52f62b210e87bcbc97b6f6486810d1807e7728fca6c247989faf0",
        "original_fit_sha256": "c20bee280c72744dd203a1832c968156480da6b6f92c210d295fd8c63940d1c6",
    }
    for key, value in expected.items():
        assert metadata[key] == value, f"AX3000T FIT manifest mismatch: {key}"
    assert sha(original) == metadata["original_fit_sha256"], "stock FIT identity drift"
    assert sha(kernel) == metadata["fit_sha256"], "final image does not contain the repacked FIT"
    assert run("fdtget", "-t", "u", kernel, "/", "timestamp") == str(metadata["source_date_epoch"])
    with tempfile.TemporaryDirectory(prefix="ax3000t-fit-") as directory:
        files = Path(directory)
        payload, dtb, original_dtb = (files / name for name in ("kernel.lzma", "final.dtb", "original.dtb"))
        original_payload, expected_dtb = files / "original-kernel.lzma", files / "expected.dtb"
        run("dumpimage", "-T", "flat_dt", "-p", "0", "-o", payload, kernel)
        run("dumpimage", "-T", "flat_dt", "-p", "1", "-o", dtb, kernel)
        run("dumpimage", "-T", "flat_dt", "-p", "0", "-o", original_payload, original)
        run("dumpimage", "-T", "flat_dt", "-p", "1", "-o", original_dtb, original)
        assert payload.read_bytes() == original_payload.read_bytes(), "Linux payload bytes changed in final FIT"
        assert hashlib.sha1(payload.read_bytes()).hexdigest() == metadata["kernel_payload_sha1"], \
            "Linux payload changed in final FIT"
        assert sha(original_dtb) == metadata["original_dtb_sha256"], "stock DTB identity drift"
        assert sha(dtb) == metadata["dtb_sha256"], "final FIT DTB identity mismatch"
        shutil.copyfile(original_dtb, expected_dtb)
        run("fdtput", "-t", "s", expected_dtb, metadata["node"], "status", "disabled")
        run("fdtput", "-t", "s", expected_dtb, "/chosen", "bootargs-append", metadata["bootargs_append"])
        assert dtb.read_bytes() == expected_dtb.read_bytes(), "unexpected DTB change in final FIT"
        assert run("fdtget", "-t", "s", dtb, metadata["node"], "compatible") == "mediatek,mt7531"
        assert run("fdtget", "-t", "s", dtb, metadata["node"], "status") == "disabled"
        assert run("fdtget", "-t", "s", dtb, "/chosen", "bootargs-append") == "loglevel=4"


def packages(apk, root):
    return {p["name"]: p for p in json.loads(run(
        apk, "--root", root, "--no-network", "query", "--from", "installed",
        "--format", "json", "--fields", "name,version,license", "*"))}


def install(source, target, mode=0o755):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def integration_files(payload, base, dnsmasq, spec, apk, installed):
    """Install only the accepted init/ACL changes, preserving stock recovery."""
    expected = {"etc/init.d/dnsmasq", "usr/share/acl.d/dnsmasq_acl.json"}
    assert set(spec["integration_files"]) == expected
    result = {}
    for path, item in spec["integration_files"].items():
        assert item["path"] == "/" + path and item["stock_package"] == "dnsmasq"
        original, candidate = base / path, dnsmasq / path
        assert sha(original) == item["stock_sha256"], f"stock integration identity drift: {path}"
        assert sha(candidate) == item["replacement_sha256"], f"accepted integration identity drift: {path}"
        assert (original.stat().st_mode & 0o7777) == item["mode"]
        assert (candidate.stat().st_mode & 0o7777) == item["mode"]
        owner = run(apk, "--root", base, "--no-network", "info", "--who-owns", item["path"])
        assert owner.endswith(" is owned by dnsmasq-" + installed["dnsmasq"]["version"]), owner
        install(candidate, payload / path, item["mode"])
        install(original, payload / STOCK / path, item["mode"])
        result[path] = dict(item, recovery_path="/" + STOCK + "/" + path)
    # The SDK package is an intermediate, not an invitation to overwrite its
    # remaining defaults/helpers. They must equal the exact stock image.
    for path in ("etc/config/dhcp", "etc/dnsmasq.conf", "etc/hotplug.d/ntp/25-dnsmasqsec",
                 "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
                 "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
                 "usr/lib/dnsmasq/dhcp-script.sh", "usr/share/dnsmasq/dhcpbogushostname.conf",
                 "usr/share/dnsmasq/rfc6761.conf"):
        assert (base / path).read_bytes() == (dnsmasq / path).read_bytes(), path
    return result


def preserve_directory_modes(payload, base):
    # APK applies directory modes too. Match the original image instead of
    # letting the builder's umask silently change shared /usr or /etc paths.
    for path in [payload, *payload.rglob("*")]:
        reference = base / path.relative_to(payload)
        if path.is_dir() and not path.is_symlink() and reference.is_dir():
            path.chmod(reference.stat().st_mode & 0o7777)


def fetch(work, spec, apk):
    del apk
    native_layout(spec["components"])
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


def verify_component_references(hashes, spec):
    """Rebuilds of the other nine programs must equal their accepted ELFs."""
    components = {name: item for name, item in spec["components"].items() if name != "dnsmasq"}
    # Historic native recipes did not carry separate accepted references.
    # v0.2.2 and later must bind every component; a partial map is never valid.
    version = tuple(int(part) for part in spec["version"].split("-", 1)[0].split("."))
    has_references = any("reference_elf_sha256" in item for item in components.values())
    if version < (0, 2, 2) and not has_references:
        return
    for name, item in components.items():
        expected = item.get("reference_elf_sha256")
        assert isinstance(expected, str) and len(expected) == 64 and all(
            byte in "0123456789abcdef" for byte in expected), f"missing accepted ELF identity: {name}"
        assert hashes[item["binary"]] == expected, f"accepted ELF identity drift: {name}"


def verify_dnsmasq_reference(report, spec):
    """Only an exact accepted use ELF may enter the native release payload."""
    assert report["status"] == "built-and-audited"
    assert report["source_digest"] == spec["source_digest"]
    assert report["accepted_product_commit"] == spec["source_commit"]
    elf = report["elf"]
    assert elf["matches_accepted_reference"] is True, "unqualified dnsmasq ELF"
    assert elf["reference_sha256"] == elf["sha256"] == spec["reference_elf_sha256"], "dnsmasq reference hash differs"
    assert elf["size"] == spec["reference_elf_bytes"], "dnsmasq reference size differs"
    assert report.get("release_qualified") is not False, "diagnostic candidate is not an accepted release"
    if "source_date_epoch" in spec:
        assert str(report["source_date_epoch"]) == str(spec["source_date_epoch"]), "dnsmasq product epoch differs"
    if "pgo" in spec:
        pgo = report["pgo"]
        assert pgo["mode"] == "use" and not pgo["profile_diagnostics"], "invalid release PGO mode/diagnostics"
        for key in ("profile_url", "profile_sha256", "profile_bytes", "build_slot", "training"):
            if key in spec["pgo"]:
                assert pgo[key] == spec["pgo"][key], f"dnsmasq PGO identity differs: {key}"


def prepare(work, spec, apk):
    assert os.geteuid() == 0, "native image prepare requires root to verify protected stock configuration"
    layout = native_layout(spec["components"])
    out = work / "out"
    root = work / "native/base-rootfs"
    binary_root = work / "verify/rootfs"
    image = read(out / "manifest.json")
    core = read(out / "core-manifest.json")
    dnsmasq = read(out / "dnsmasq/manifest.json")
    assert image["source_commit"] == core["source_commit"] == dnsmasq["source_commit"]
    verify_dnsmasq_reference(dnsmasq, spec["dnsmasq_build"])
    assert image["openwrt"] == core["openwrt"] == spec["openwrt"]
    assert core["image_manifest_sha256"] == sha(out / "manifest.json")
    hashes = image["binary_sha256"] | core["binary_sha256"] | dnsmasq["binary_sha256"]
    assert set(hashes) == {c["binary"] for c in spec["components"].values()}
    verify_component_references(hashes, spec)
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
        binary = (out / "core-binaries" if name in ("procd", "ubusd", "netifd", "odhcpd")
                  else binary_root / "usr/sbin") / c["binary"]
        if name == "dnsmasq":
            binary = out / "dnsmasq/payload/usr/sbin/dnsmasq"
        assert sha(binary) == hashes[c["binary"]], f"Rust identity drift: {name}"
        install(binary, payload / path)
        install(original, payload / STOCK / path)
        components[name] = dict(c, rust_sha256=sha(binary), rust_bytes=binary.stat().st_size,
                                recovery_path="/" + STOCK + "/" + path)
        rust_sums.append(f"{sha(binary)}  /{path}\n")
        stock_sums.append(f"{sha(original)}  /{STOCK}/{path}\n")
    integration = integration_files(payload, root, out / "dnsmasq/payload", spec, apk, installed)
    for path, item in integration.items():
        rust_sums.append(f"{item['replacement_sha256']}  /{path}\n")
        stock_sums.append(f"{item['stock_sha256']}  {item['recovery_path']}\n")
    rust_text, stock_text = "".join(rust_sums), "".join(stock_sums)
    manifest = {
        "schema": 2, "layout": layout, "source_commit": image["source_commit"],
        "openwrt": spec["openwrt"], "profile": spec["profile"],
        "package": spec["package"], "version": spec["version"],
        "components": components,
        "integration_files": integration,
        "stock_manifest_sha256": hashlib.sha256(stock_text.encode()).hexdigest(),
        "stock_image": spec["stock_image"],
        "luci_source": spec["luci_source"], "translations": spec["translations"],
        "stock_packages": {p: installed[p] for p in owners},
        "recovery": f"owrt-recover-c stages all {len(components)} stock programs and exact dnsmasq init/ACL; reboot separately",
    }
    write(payload / METADATA / "release.json", manifest)
    (payload / METADATA / "rust.sha256").write_text(rust_text)
    (payload / METADATA / "stock.sha256").write_text(stock_text)
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
    # prepare runs as root while Actions' checkout belongs to the runner.
    # Trust only this invocation's repository, never a global wildcard.
    epoch = int(run("git", "-c", "safe.directory=" + str(REPO), "-C", REPO,
                    "show", "-s", "--format=%ct", image["source_commit"]))
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
            "arch": spec["architecture"], "description": f"{len(components)} native Rust OpenWrt control-plane components",
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
    write(work / "native/build-inputs.json", {"image": image, "core": core, "dnsmasq": dnsmasq,
          "package_metadata": info, "package_sha256": sha(package)})
    print(f"Prepared {package.name}: {len(components)} native paths, paired dnsmasq init/ACL, {len(components) + len(integration)} stock recovery files")


def verify(work, spec, apk):
    root = work / "native/rootfs"
    before = work / "native/base-rootfs"
    inputs = read(work / "native/build-inputs.json")
    kernel = work / "native/unpacked/sysupgrade-xiaomi_mi-router-ax3000t/kernel"
    verify_ax3000t_fit(kernel, work / "native/base-image/sysupgrade-xiaomi_mi-router-ax3000t/kernel",
                       inputs["image"]["ax3000t_fit"])
    manifest = read(work / "native/payload" / METADATA / "release.json")
    assert read(root / METADATA / "release.json") == manifest
    layout = native_layout(manifest["components"])
    assert manifest["layout"] == layout == native_layout(spec["components"])
    assert sha(root / METADATA / "stock.sha256") == manifest["stock_manifest_sha256"]
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
    for path, item in manifest["integration_files"].items():
        assert sha(root / path) == item["replacement_sha256"]
        assert sha(root / item["recovery_path"].lstrip("/")) == item["stock_sha256"]
        assert (root / path).stat().st_mode & 0o7777 == item["mode"]
        owner = run(apk, "--root", root, "--no-network", "info", "--who-owns", item["path"])
        assert owner.endswith(" is owned by " + spec["package"] + "-" + spec["version"]), owner
    assert not list((root / "etc").glob("owrt-*.boot-enable"))
    assert not list((root / "etc/init.d").glob("owrt-*"))
    assert not list((root / "etc/rc.d").glob("*owrt-*"))
    assert not list((root / "root").iterdir())
    for service in ("log", "rpcd", "uhttpd", "network"):
        assert (root / "etc/init.d" / service).read_bytes() == (before / "etc/init.d" / service).read_bytes()
        assert any((root / "etc/rc.d").glob("S[0-9][0-9]" + service)), service
    if "odhcpd" in manifest["components"]:
        for path in ("etc/init.d/odhcpd", "usr/sbin/odhcpd-update", "etc/uci-defaults/15_odhcpd"):
            assert (root / path).read_bytes() == (before / path).read_bytes(), path
        assert any((root / "etc/rc.d").glob("S[0-9][0-9]odhcpd"))
    assert any((root / "etc/rc.d").glob("S[0-9][0-9]dnsmasq"))
    for name in ("shadow", "passwd"):
        assert (root / "etc" / name).read_bytes() == (before / "etc" / name).read_bytes()
    for path in (before / "etc/config").iterdir():
        assert path.read_bytes() == (root / "etc/config" / path.name).read_bytes(), path.name
    # Compare the entire original filesystem, not another image assembled from
    # today's feed. Package versions alone do not prove unchanged content.
    replaced = {c["path"].lstrip("/") for c in manifest["components"].values()}
    replaced |= set(manifest["integration_files"])
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
    hashes = {c["binary"]: c["rust_sha256"] for c in manifest["components"].values()}
    result = dict(inputs["image"], schema_version=3, deployment_layout=layout,
                  packages={n: installed[n]["version"] for n in sorted(translations | {spec["package"]})}, components=manifest["components"],
                  integration_files=manifest["integration_files"], stock_manifest_sha256=manifest["stock_manifest_sha256"],
                  binary_sha256=hashes, stock_packages=manifest["stock_packages"],
                  image={"file": image.name, "size": image.stat().st_size, "sha256": sha(image)},
                  apk_sha256={p.name: sha(p) for p in apks}, stock_image=spec["stock_image"],
                  luci_source=spec["luci_source"], translations=spec["translations"],
                  kernel_sha256=sha(kernel),
                  imagebuilder_args={"assembly": "verified stock rootfs + offline APK install + official image tools",
                                     "rolling_feeds_used_for_final_rootfs": False},
                  validation={layout.removeprefix("native-") + "_native_paths": True, "package_ownership": True,
                              "stock_recovery_hashes": True, "stock_service_scripts_except_qualified_dnsmasq": True,
                              "qualified_dnsmasq_init_and_acl": True, "dnsmasq_source_recipe_identical": True,
                              "dnsmasq_reference_elf_identical": inputs["dnsmasq"]["elf"]["matches_accepted_reference"],
                              "stock_config_defaults": True, "unchanged_execution_files": checked,
                              "stock_package_versions_unchanged": len(previous),
                              "production_Chinese_catalogs_identical": len(translations),
                              "an8855_fit_verified": True, "kernel_payload_identical": True,
                              "physical_boot_tested": False},
                  recovery=manifest["recovery"], flashed=False)
    write(output / "manifest.json", result)
    write(output / "build-inputs.json", inputs)
    (output / "binary-sha256.txt").write_text("".join(f"{h}  {n}\n" for n, h in sorted(hashes.items())))
    for source in (work / "out").glob("*.log"):
        shutil.copy2(source, output / source.name)
    shutil.copy2(work / "out/dnsmasq/manifest.json", output / "dnsmasq-build-manifest.json")
    for source in (work / "out/dnsmasq").glob("*.log"):
        shutil.copy2(source, output / ("dnsmasq-" + source.name))
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
