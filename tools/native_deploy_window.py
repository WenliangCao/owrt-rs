#!/usr/bin/env python3
"""Stage or explicitly activate an authorized native firmware deployment.

The Mac-side observer survives Wi-Fi loss. Device recovery is independently
armed by the configuration archive. Requires the verified private gate record.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time

from r84_device_probe import probe, require


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("stage", "activate"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", default="en0")
    args = parser.parse_args()
    base = args.directory.resolve()
    gate = json.loads((base / "recovery-gate.json").read_text())
    require(gate["ready_for_staging"] is True, "recovery gate incomplete")
    image = Path(gate["image_path"])
    config = base / "trial-config.tar.gz"
    trial = json.loads((base / "trial-config.tar.json").read_text())
    manifest = json.loads(Path(gate["manifest_path"]).read_text())
    require(sha(image) == trial["image"]["sha256"], "local image changed")
    require(sha(config) == trial["archive_sha256"], "configuration archive changed")
    require(sha(base / "guard-evidence.tar.gz") == gate["guard_evidence_sha256"], "guard evidence changed")
    for name, expected in gate["backup_sha256"].items():
        require(sha(base / name) == expected, "backup changed: " + name)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
           "-o", "ServerAliveInterval=4", "-o", "ServerAliveCountMax=1", args.host]
    remote_image, remote_config = "/tmp/owrt-native-image.bin", "/tmp/owrt-native-config.tar.gz"

    def remote(command, timeout=15):
        r = subprocess.run(ssh + [command], text=True, capture_output=True, timeout=timeout)
        require(r.returncode == 0, "SSH command failed: " + r.stderr.strip()[:180])
        return r.stdout.strip()

    def log(event, **fields):
        row = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "event": event, **fields}
        with (base / "window.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)

    def configurations():
        for filename in ("config-before.sha256", "protected-before.sha256"):
            entries = dict(line.split(None, 1)[::-1] for line in (base / filename).read_text().splitlines())
            observed = remote("sha256sum " + " ".join(shlex.quote(p) for p in entries))
            actual = dict(line.split(None, 1)[::-1] for line in observed.splitlines())
            require(actual == entries, "configuration changed: " + filename)

    def staged_files():
        actual = remote("sha256sum " + remote_image + " " + remote_config).splitlines()
        require(actual[0].split()[0] == trial["image"]["sha256"], "device image changed")
        require(actual[1].split()[0] == trial["archive_sha256"], "device config changed")

    def native_identities():
        code = '''set -eu
sha256sum -c /usr/share/owrt-control-plane/rust.sha256 >/dev/null
sha256sum -c /usr/share/owrt-control-plane/stock.sha256 >/dev/null
for name in procd ubusd netifd rpcd logd uhttpd; do
    if [ "$name" = procd ]; then pid=1; else pid=$(pidof "$name"); fi
    case "$pid" in ''|*[!0-9]*) exit 1;; esac
    printf '%s %s\n' "$name" "$(sha256sum /proc/$pid/exe | cut -d' ' -f1)"
done
'''
        observed = dict(line.split() for line in remote(code).splitlines())
        for name, component in manifest["components"].items():
            if name in ("uci", "fw4", "reload-config"):
                continue
            process = "uhttpd" if name == "httpd" else name
            require(observed[process] == component["rust_sha256"], "running identity mismatch: " + name)
        paths = [c["path"] for c in manifest["components"].values()]
        actual = dict(line.split(None, 1)[::-1] for line in remote("sha256sum " + " ".join("/rom" + p for p in paths)).splitlines())
        require(actual == {"/rom" + c["path"]: c["rust_sha256"] for c in manifest["components"].values()}, "ROM identity mismatch")
        release = json.loads(remote("cat /usr/share/owrt-control-plane/release.json"))
        require(release["source_commit"] == manifest["source_commit"], "wrong installed firmware release")
        mounts = json.loads(remote("ubus -S -t 3 call luci getMountPoints"))["result"]
        require(not any(m["mount"] in paths for m in mounts), "executable bind mount remains")
        remote('''set -eu
for s in log rpcd uhttpd network; do /etc/init.d/$s enabled; done
for name in uci fw4 reload-config rpcd logd httpd; do
    test ! -e /etc/owrt-$name.boot-enable
    test ! -e /etc/init.d/owrt-$name
done
kill -0 "$(cat /tmp/owrt-native-guard-lock/pid)"
test ! -e /root/owrt-native-trial/restored
/sbin/fw4 check >/dev/null 2>&1
''')
        return {"runtime_daemons": observed, "ROM_components_verified": 9, "executable_bind_mounts": 0}

    require(remote("cat /proc/sys/kernel/random/boot_id") == gate["previous_boot_id"], "pre-upgrade boot changed")
    configurations()
    if args.phase == "stage":
        for local, dest in ((image, remote_image), (config, remote_config)):
            subprocess.run(["scp", "-O", "-q", str(local), args.host + ":" + dest], check=True, timeout=90)
        staged_files()
        check = remote("/sbin/sysupgrade -T -f " + remote_config + " " + remote_image, timeout=60)
        (base / "sysupgrade-test.log").write_text(check + "\n")
        health = probe(host=args.host, interface=args.interface)
        ready = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "boot_id": health["boot_id"],
                 "image_sha256": sha(image), "config_sha256": sha(config), "sysupgrade_test_passed": True,
                 "driver_sha256": sha(Path(__file__).resolve()), "client_health": health}
        (base / "stage-ready.json").write_text(json.dumps(ready, indent=2) + "\n")
        log("staged_and_checked", image_sha256=sha(image), client_health=health)
        return

    ready = json.loads((base / "stage-ready.json").read_text())
    require(ready["sysupgrade_test_passed"] and ready["driver_sha256"] == sha(Path(__file__).resolve()), "staging gate changed")
    require(ready["image_sha256"] == sha(image) and ready["config_sha256"] == sha(config), "staged artifacts changed")
    staged_files()
    probe(host=args.host, interface=args.interface)
    with (base / "ACTIVATION_STARTED").open("x") as stamp:
        stamp.write(datetime.datetime.now(datetime.timezone.utc).isoformat() + "\n")
    log("flash_requested", image_sha256=sha(image), preserve_config=True)
    with (base / "sysupgrade-activation.log").open("w") as output:
        upgrade = subprocess.Popen(ssh + ["/sbin/sysupgrade -f " + remote_config + " " + remote_image],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
    start = time.monotonic()
    stable = None
    verified_boot = None
    while time.monotonic() - start < 850:
        try:
            boot = remote("cat /proc/sys/kernel/random/boot_id")
            require(boot != gate["previous_boot_id"], "waiting for new boot")
            pid1 = remote("sha256sum /proc/1/exe").split()[0]
            if pid1 == manifest["components"]["procd"]["stock_sha256"]:
                (base / "guard-after-fallback.log").write_text(remote("cat /root/owrt-native-trial/guard.log"))
                log("automatic_C_fallback", boot_id=boot)
                raise SystemExit(1)
            health = probe(host=args.host, interface=args.interface)
            require(health["boot_id"] == boot, "boot changed during health probe")
            if verified_boot != boot:
                identity = native_identities()
                configurations()
                (base / "native-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
                verified_boot = boot
                stable = None
            if stable is None:
                stable = time.monotonic()
            held = time.monotonic() - stable
            log("health_pass", elapsed_s=round(time.monotonic() - start, 1), continuous_s=round(held, 1), health=health)
            if held >= 180:
                native_identities()
                configurations()
                remote("/bin/sh /root/owrt-native-trial/native_trial_guard.sh confirm " + shlex.quote(trial["token"]) + " " + shlex.quote(boot), timeout=25)
                result = {"status": "native_image_healthy_and_client_confirmed", "boot_id": boot,
                          "continuous_client_health_s": held, "image_sha256": sha(image),
                          "source_commit": manifest["source_commit"], "health": health,
                          "automatic_guard_remains_armed": True, "physical_power_cycle_tested": False}
                (base / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                log("confirmed", result=result)
                if upgrade.poll() is None:
                    upgrade.terminate()
                return
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            stable = None
            log("health_not_confirmed", elapsed_s=round(time.monotonic() - start, 1), error=str(exc))
        time.sleep(10)
    log("window_expired", automatic_recovery_left_armed=True)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
