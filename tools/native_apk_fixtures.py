#!/usr/bin/env python3
"""Rebuild stock package payloads for isolated APK file-ownership tests.

Old feed APKs need not remain online. These unsigned fixtures reproduce the
installed version, dependencies and file payload from the pinned stock image;
they are not original signed packages and do not contain lifecycle scripts.
The gate explicitly uses --no-scripts, as does final image construction.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from native_image import native_layout, preserve_directory_modes, run, sha


STOCK_OWNERS = ("procd", "ubusd", "netifd", "rpcd", "logd", "uhttpd", "firewall4", "uci", "dnsmasq")


def stock_owners(spec):
    native_layout(spec["components"])
    return STOCK_OWNERS + (("odhcpd-ipv6only",) if "odhcpd" in spec["components"] else ())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock_rootfs", type=Path)
    parser.add_argument("native_apk", type=Path)
    parser.add_argument("apk_tool", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--spec", type=Path, default=Path(__file__).resolve().parent.parent / "packaging/image/native-25.12.5.json")
    args = parser.parse_args()
    assert os.geteuid() == 0 and not Path("/etc/openwrt_release").exists()
    root, out, apk = args.stock_rootfs.resolve(), args.output.resolve(), args.apk_tool.resolve()
    out.mkdir(parents=True, exist_ok=False)
    names = stock_owners(json.loads(args.spec.read_text()))
    packages = json.loads(run(apk, "--root", root, "--no-network", "query", "--from", "installed",
                             "--format", "json", "--fields", "name,version,license,arch,depends,provides,origin", *names))
    assert {p["name"] for p in packages} == set(names)
    provenance = {"purpose": "unsigned exact-image payload fixtures; --no-scripts tests only", "packages": {}}
    for p in packages:
        name = p["name"]
        files = out / "payloads" / name
        listing = root / "lib/apk/packages" / (name + ".list")
        paths = set(listing.read_text().splitlines())
        paths.update("/" + str(f.relative_to(root)) for f in listing.parent.glob(name + ".*"))
        hashes = {}
        for relative in sorted(paths):
            source, target = root / relative.lstrip("/"), files / relative.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                os.symlink(os.readlink(source), target)
            else:
                assert source.is_file(), relative
                shutil.copy2(source, target)
                hashes[relative] = sha(target)
        preserve_directory_modes(files, root)
        output = out / f"{name}-{p['version']}.apk"
        command = [str(apk), "mkpkg", "--files", str(files), "--output", str(output)]
        for key, value in p.items():
            command += ["--info", key + ":" + (" ".join(value) if isinstance(value, list) else value)]
        subprocess.run(command, check=True)
        provenance["packages"][name] = {"version": p["version"], "payload_sha256": hashes, "apk_sha256": sha(output)}
    shutil.copy2(args.native_apk, out / args.native_apk.name)
    (out / "fixture-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    subprocess.run([str(apk), "--allow-untrusted", "mkndx", "--output", str(out / "packages.adb"),
                    *map(str, sorted(out.glob("*.apk")))], check=True)
    print(f"Prepared {len(names)} original payload fixtures plus native APK and offline index")


if __name__ == "__main__":
    main()
