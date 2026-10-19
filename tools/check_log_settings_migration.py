#!/usr/bin/env python3
"""Replay logging UCI migration and sysupgrade retention in disposable chroots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


MARKER = "etc/owrt-log-settings-v1"
DEFAULT = "etc/uci-defaults/06-owrt-log-settings"
KEEP = "lib/upgrade/keep.d/owrt-log-settings"


def run(root, *args, check=True):
    return subprocess.run(["chroot", str(root), *args], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)


def values(root):
    return {key: run(root, "uci", "-q", "get", "system.@system[0]." + key,
                     check=False).stdout.strip() for key in ("log_size", "conloglevel")}


def configure(root, log_size="128", conloglevel="8"):
    (root / MARKER).unlink(missing_ok=True)
    config = "config system\n option hostname 'unchanged'\n"
    for key, value in (("log_size", log_size), ("conloglevel", conloglevel)):
        if value is not None:
            config += f" option {key} '{value}'\n"
    (root / "etc/config/system").write_text(config)


def migrate(root, enabled):
    if enabled:
        run(root, "/bin/sh", "/" + DEFAULT)


def trial(source, script, keep, side, enabled, output):
    with tempfile.TemporaryDirectory(prefix="log-settings-") as directory:
        root = Path(directory) / "root"
        subprocess.run(["cp", "-a", source, root], check=True)
        shutil.rmtree(root / "dev")
        (root / "dev").mkdir()
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        for name in ("tmp/.uci", "tmp/lock", "tmp/run", "tmp/state", "etc/config"):
            (root / name).mkdir(parents=True, exist_ok=True)
        if side == "c":
            shutil.copy2(root / "usr/libexec/owrt-stock/sbin/uci", root / "sbin/uci")
        shutil.copy2(script, root / DEFAULT)
        shutil.copy2(keep, root / KEEP)
        results = {}
        configure(root)
        migrate(root, enabled)
        results["legacy"] = values(root)
        results["unrelated"] = run(root, "uci", "-q", "get", "system.@system[0].hostname").stdout.strip()
        assert results["legacy"] == ({"log_size": "2048", "conloglevel": "4"} if enabled
                                      else {"log_size": "128", "conloglevel": "8"})
        assert results["unrelated"] == "unchanged"

        configure(root, "4096", "5")
        migrate(root, enabled)
        results["custom"] = values(root)
        assert results["custom"] == {"log_size": "4096", "conloglevel": "5"}

        configure(root, None, None)
        migrate(root, enabled)
        results["missing_options"] = values(root)
        assert results["missing_options"] == ({"log_size": "2048", "conloglevel": "4"}
                                               if enabled else {"log_size": "", "conloglevel": ""})

        (root / MARKER).unlink(missing_ok=True)
        (root / "etc/config/system").unlink()
        # Exercise the exact image's generator without hardware board detection.
        (root / "etc/board.json").write_text('{"system":{"hostname":"fixture"}}\n')
        (root / "etc/config/network").write_text("config interface 'loopback'\n option device 'lo'\n")
        run(root, "/bin/config_generate")
        results["stock_generated"] = values(root)
        assert results["stock_generated"] == {"log_size": "128", "conloglevel": ""}
        migrate(root, enabled)
        results["stock_migrated"] = values(root)
        assert results["stock_migrated"] == ({"log_size": "2048", "conloglevel": "4"}
                                              if enabled else results["stock_generated"])

        configure(root)
        migrate(root, enabled)
        run(root, "uci", "set", "system.@system[0].log_size=128")
        run(root, "uci", "set", "system.@system[0].conloglevel=8")
        run(root, "uci", "commit", "system")
        migrate(root, enabled)
        results["later_choice"] = values(root)
        assert results["later_choice"] == {"log_size": "128", "conloglevel": "8"}

        # Use the unchanged stock sysupgrade keep.d collector. No upgrade or
        # service command runs; only this read-only function executes in chroot.
        upgrade = (root / "sbin/sysupgrade").read_text()
        start = upgrade.index("list_static_conffiles() {")
        end = upgrade.index("\nbuild_list_of_backup_config_files()", start)
        (root / "tmp/collect.sh").write_text(upgrade[start:end] + "\nlist_static_conffiles | sort -u\n")
        listed = run(root, "/bin/sh", "/tmp/collect.sh").stdout.splitlines()
        results["marker_in_backup"] = "/" + MARKER in listed
        assert results["marker_in_backup"] is enabled
        # Save exactly the system config and listed migration marker, discard
        # their active copies, and restore to model a preserved-config upgrade.
        saved = {name: (root / name).read_bytes() for name in ("etc/config/system", MARKER)
                 if "/" + name in listed}
        assert "etc/config/system" in saved
        for name in ("etc/config/system", MARKER):
            (root / name).unlink(missing_ok=True)
        for name, contents in saved.items():
            (root / name).write_bytes(contents)
        migrate(root, enabled)
        results["next_upgrade"] = values(root)
        assert results["next_upgrade"] == {"log_size": "128", "conloglevel": "8"}
        if enabled:
            (root / MARKER).unlink()
            (root / "etc/config/system").unlink()
            failed = run(root, "/bin/sh", "/" + DEFAULT, check=False)
            results["missing_section_retries"] = failed.returncode != 0 and not (root / MARKER).exists()
            assert results["missing_section_retries"]
        output.write_text(json.dumps(results, indent=2) + "\n")
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("script", type=Path)
    parser.add_argument("keep", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.uname().sysname == "Linux"
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for enabled in (False, True):
        for repeat in range(1, 5):
            for side in ("c", "rust"):
                name = f"{'green' if enabled else 'red'}-{repeat}-{side}"
                row = dict(name=name, checks=trial(args.rootfs, args.script, args.keep, side,
                                                   enabled, args.output / (name + ".json")))
                results.append(row)
                print(json.dumps(row), flush=True)
    identities = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in (args.script, args.keep, args.rootfs / "sbin/uci",
                               args.rootfs / "usr/libexec/owrt-stock/sbin/uci",
                               args.rootfs / "bin/config_generate", args.rootfs / "sbin/sysupgrade")}
    (args.output / "results.json").write_text(json.dumps({"passed": True, "identities": identities,
                                                         "rows": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
