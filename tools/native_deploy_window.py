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
import re
import shlex
import subprocess
import time

from r84_device_probe import probe, require


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dnsmasq_runtime(remote, expected, ujail_sha256, diagnostics):
    """Verify every supervised instance by executable bytes, not d_path."""
    evidence = {"processes": []}
    try:
        services = json.loads(remote("ubus -S -t 3 call service list '{\"name\":\"dnsmasq\"}'"))
        instances = services.get("dnsmasq", {}).get("instances", {})
        require(instances and all(value.get("running") is True and value.get("jail")
                                 for value in instances.values()), "dnsmasq instances are not running under ujail")
        evidence["instances"] = instances
        inventory = remote('''set -eu
for process in /proc/[0-9]*; do
    value=$(sha256sum "$process/exe" 2>/dev/null) || continue
    printf '%s %s\n' "${process#/proc/}" "${value%% *}"
done
''', timeout=30)
        evidence["inventory"] = inventory
        pids = [line.split()[0] for line in inventory.splitlines() if line.split()[1] == expected]
        require(len(pids) == len(instances) and len(set(pids)) == len(pids),
                "dnsmasq executable count differs from configured instances")
        matched = set()
        for pid in pids:
            require(re.fullmatch(r"[0-9]+", pid) is not None, "invalid runtime PID")
            # FS separates fields while the command lines retain their NULs.
            script = '''set -eu
pid=PID_VALUE
parent=$(awk '$1 == "PPid:" { print $2 }' /proc/$pid/status)
field() { printf '\\034'; "$@"; }
cat /proc/$pid/stat
field readlink /proc/$pid/exe
field sha256sum /proc/$pid/exe
field cat /proc/$pid/cmdline
field cat /proc/$pid/status
field cat /proc/$parent/stat
field readlink /proc/$parent/exe
field sha256sum /proc/$parent/exe
field cat /proc/$parent/cmdline
field cat /proc/$parent/stat
field cat /proc/$pid/stat
field sha256sum /proc/$pid/exe
'''.replace("PID_VALUE", pid)
            fields = remote(script).split("\x1c")
            require(len(fields) == 12, "invalid runtime snapshot framing")
            before, exe, digest, command, status, parent_before, parent_exe, parent_digest, parent_command, parent_after, after, final_digest = fields
            first = before.rsplit(")", 1)[1].split()
            last = after.rsplit(")", 1)[1].split()
            parent = int(first[1])
            require(first[19] == last[19] and first[1] == last[1], "dnsmasq PID changed during capture")
            require(parent_before.rsplit(")", 1)[1].split()[19] == parent_after.rsplit(")", 1)[1].split()[19],
                    "dnsmasq supervisor changed during capture")
            require(digest.split()[0] == final_digest.split()[0] == expected, "dnsmasq runtime executable changed")
            require(parent_digest.split()[0] == ujail_sha256, "dnsmasq supervisor is not the exact image ujail")
            names = [name for name, value in instances.items() if value.get("pid") == parent]
            require(len(names) == 1 and names[0] not in matched, "dnsmasq process is not a unique supervised instance")
            require(command.endswith("\0"), "truncated dnsmasq command line")
            argv = command[:-1].split("\0")
            require(argv == instances[names[0]]["command"], "dnsmasq argv differs from the init submission")
            matched.add(names[0])
            evidence["processes"].append({"instance": names[0], "pid": int(pid), "exe": exe.strip(),
                "sha256": expected, "cmdline": argv, "status": status, "start_ticks": int(first[19]),
                "parent_pid": parent, "parent_exe": parent_exe.strip(), "parent_sha256": parent_digest.split()[0],
                "parent_cmdline": parent_command.rstrip("\0").split("\0"),
                "parent_start_ticks": int(parent_before.rsplit(")", 1)[1].split()[19])})
        require(matched == set(instances), "not every dnsmasq instance was verified")
        current = json.loads(remote("ubus -S -t 3 call service list '{\"name\":\"dnsmasq\"}'"))["dnsmasq"]["instances"]
        require(set(current) == set(instances) and all(current[name].get("running") is True and
                current[name].get("pid") == value["pid"] and current[name].get("command") == value["command"]
                for name, value in instances.items()), "dnsmasq instances changed during capture")
        evidence["passed"] = True
        return evidence["processes"]
    except Exception as error:
        evidence["passed"], evidence["error"] = False, str(error)
        raise
    finally:
        with diagnostics.open("a") as stream:
            stream.write(json.dumps(evidence) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("stage", "activate", "observe"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--previous-boot-id", help="required for observe; this tool never initiates a reboot")
    parser.add_argument("--label", default="initial", help="separate receipt name for normal/power reboot observation")
    args = parser.parse_args()
    base = args.directory.resolve()
    require(re.fullmatch(r"[a-z0-9-]+", args.label) is not None, "invalid observation label")
    require(args.phase != "observe" or args.previous_boot_id is not None, "observe requires previous boot ID")
    gate = json.loads((base / "recovery-gate.json").read_text())
    require(gate["ready_for_staging"] is True, "recovery gate incomplete")
    require(re.fullmatch(r"[0-9a-f]{40}", gate["rollback_source_commit"]) is not None,
            "verified rollback source identity is missing")
    require(re.fullmatch(r"[0-9a-f]{64}", gate["ujail_sha256"]) is not None,
            "exact candidate image ujail identity is missing")
    image = Path(gate["image_path"])
    config = base / "trial-config.tar.gz"
    trial = json.loads((base / "trial-config.tar.json").read_text())
    manifest = json.loads(Path(gate["manifest_path"]).read_text())
    require(manifest["deployment_layout"] == "native-ten" and len(manifest["components"]) == 10,
            "deployment requires the accepted ten-component image")
    previous_boot = args.previous_boot_id if args.phase == "observe" else gate["previous_boot_id"]
    require(re.fullmatch(r"[0-9a-f-]{36}", previous_boot) is not None, "invalid previous boot ID")
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
        with (base / ("window-" + args.label + ".jsonl")).open("a") as stream:
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
        observed = {}
        for line in remote(code).splitlines():
            process, digest = line.split()
            observed.setdefault(process, []).append(digest)
        dns = dnsmasq_runtime(remote, manifest["components"]["dnsmasq"]["rust_sha256"],
                              gate["ujail_sha256"], base / ("dnsmasq-runtime-" + args.label + ".jsonl"))
        observed["dnsmasq"] = [row["sha256"] for row in dns]
        for name, component in manifest["components"].items():
            if name in ("uci", "fw4", "reload-config"):
                continue
            process = "uhttpd" if name == "httpd" else name
            require(observed.get(process) and all(digest == component["rust_sha256"] for digest in observed[process]),
                    "running identity mismatch: " + name)
        paths = [c["path"] for c in manifest["components"].values()]
        actual = dict(line.split(None, 1)[::-1] for line in remote("sha256sum " + " ".join("/rom" + p for p in paths)).splitlines())
        require(actual == {"/rom" + c["path"]: c["rust_sha256"] for c in manifest["components"].values()}, "ROM identity mismatch")
        integration = manifest["integration_files"].values()
        expected = {prefix + c["path"]: c["replacement_sha256"]
                    for c in integration for prefix in ("", "/rom")}
        actual = dict(line.split(None, 1)[::-1] for line in remote(
            "sha256sum " + " ".join(shlex.quote(path) for path in expected)).splitlines())
        require(actual == expected, "dnsmasq init/ACL identity mismatch")
        release = json.loads(remote("cat /usr/share/owrt-control-plane/release.json"))
        require(release["source_commit"] == manifest["source_commit"], "wrong installed firmware release")
        mounts = json.loads(remote("ubus -S -t 3 call luci getMountPoints"))["result"]
        require(not any(m["mount"] in paths for m in mounts), "executable bind mount remains")
        remote('''set -eu
for s in log rpcd uhttpd network dnsmasq; do /etc/init.d/$s enabled; done
for name in uci fw4 reload-config rpcd logd httpd; do
    test ! -e /etc/owrt-$name.boot-enable
    test ! -e /etc/init.d/owrt-$name
done
kill -0 "$(cat /tmp/owrt-native-guard-lock/pid)"
test ! -e /root/owrt-native-trial/rollback-requested
test ! -e /root/owrt-native-trial/c-bridge-used
/sbin/fw4 check >/dev/null 2>&1
''')
        payload = "".join(digest + "  /" + path + "\n" for path, digest in trial["payload_sha256"].items())
        remote("printf %s " + shlex.quote(payload) + " | sha256sum -c - >/dev/null", timeout=60)
        return {"runtime_daemons": observed, "dnsmasq_runtime": dns, "ROM_components_verified": len(manifest["components"]),
                "dnsmasq_integration_files_verified": len(manifest["integration_files"]), "executable_bind_mounts": 0}

    if args.phase != "observe":
        require(remote("cat /proc/sys/kernel/random/boot_id") == previous_boot, "pre-upgrade boot changed")
        configurations()
    if args.phase == "stage":
        for local, dest in ((image, remote_image), (config, remote_config)):
            subprocess.run(["scp", "-O", "-q", str(local), args.host + ":" + dest], check=True, timeout=90)
        staged_files()
        check = remote("/sbin/sysupgrade -T -f " + remote_config + " " + remote_image, timeout=60)
        (base / "sysupgrade-test.log").write_text(check + "\n")
        health = probe(host=args.host, interface=args.interface, require_client_egress=True)
        ready = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "boot_id": health["boot_id"],
                 "image_sha256": sha(image), "config_sha256": sha(config), "sysupgrade_test_passed": True,
                 "driver_sha256": sha(Path(__file__).resolve()), "client_health": health}
        (base / "stage-ready.json").write_text(json.dumps(ready, indent=2) + "\n")
        log("staged_and_checked", image_sha256=sha(image), client_health=health)
        return

    ready = json.loads((base / "stage-ready.json").read_text())
    require(ready["sysupgrade_test_passed"] and ready["driver_sha256"] == sha(Path(__file__).resolve()), "staging gate changed")
    require(ready["image_sha256"] == sha(image) and ready["config_sha256"] == sha(config), "staged artifacts changed")
    upgrade = None
    if args.phase == "activate":
        staged_files()
        probe(host=args.host, interface=args.interface, require_client_egress=True)
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
            require(boot != previous_boot, "waiting for new boot")
            release = json.loads(remote("cat /usr/share/owrt-control-plane/release.json"))
            if release["source_commit"] == gate["rollback_source_commit"]:
                log("rollback_firmware_detected_requires_final_checks", boot_id=boot)
                raise SystemExit(1)
            pid1 = remote("sha256sum /proc/1/exe").split()[0]
            if pid1 == manifest["components"]["procd"]["stock_sha256"]:
                (base / "guard-after-fallback.log").write_text(remote("cat /root/owrt-native-trial/guard.log"))
                log("C_bridge_detected_not_a_completed_firmware_rollback", boot_id=boot)
                raise RuntimeError("C bridge is requesting the complete rollback")
            health = probe(host=args.host, interface=args.interface, require_client_egress=True)
            require(health["boot_id"] == boot, "boot changed during health probe")
            if verified_boot != boot:
                identity = native_identities()
                configurations()
                (base / ("native-identity-" + args.label + ".json")).write_text(json.dumps(identity, indent=2) + "\n")
                verified_boot = boot
                stable = None
            if stable is None:
                stable = time.monotonic()
            held = time.monotonic() - stable
            log("health_pass", elapsed_s=round(time.monotonic() - start, 1), continuous_s=round(held, 1), health=health)
            if held >= 180:
                native_identities()
                configurations()
                remote("/bin/sh /root/owrt-native-trial/native_trial_guard.sh confirm " + shlex.quote(trial["token"]) + " " + shlex.quote(boot), timeout=40)
                result = {"status": "native_image_healthy_and_client_confirmed", "boot_id": boot,
                          "observation_label": args.label,
                          "continuous_client_health_s": held, "image_sha256": sha(image),
                          "source_commit": manifest["source_commit"], "health": health,
                          "automatic_guard_remains_armed": True, "physical_power_cycle_tested": False}
                (base / ("result-" + args.label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
                log("confirmed", result=result)
                if upgrade is not None and upgrade.poll() is None:
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
