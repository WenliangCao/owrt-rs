#!/usr/bin/env python3
"""Compare live host hints via a temporary, separate original ubus/rpcd pair.

Run after all timed experiments. Only read methods are invoked; the active stack
and radio configuration are unchanged. Raw output contains private identifiers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import uuid

from r84_device_probe import probe

SCENARIO = r'''set -eu
umask 077
scratch=$1
bus=
rpc=
watch=
cleanup() {
    trap - EXIT HUP INT TERM
    for pid in "$rpc" "$bus" "$watch"; do
        [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    done
    for pid in "$rpc" "$bus" "$watch"; do
        [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT HUP INT TERM
owner=$$
(sleep 45; kill -TERM "$owner") </dev/null >/dev/null 2>&1 &
watch=$!
/rom/sbin/ubusd -s "$scratch/ubus.sock" >"$scratch/ubusd.log" 2>&1 &
bus=$!
i=0
while [ ! -S "$scratch/ubus.sock" ]; do
    i=$((i+1)); [ "$i" -le 10 ]; sleep 1
done
/rom/sbin/rpcd -s "$scratch/ubus.sock" -t 3 >"$scratch/rpcd.log" 2>&1 &
rpc=$!
ubus -s "$scratch/ubus.sock" -t 5 wait_for luci-rpc
sha256sum "/proc/$bus/exe" "/proc/$rpc/exe" >"$scratch/original-identities.txt"
for n in 1 2 3; do
    ip -6 neigh show >"$scratch/$n-neighbors-before.txt"
    if [ "$n" = 2 ]; then
        ubus -S -t 5 call luci-rpc getHostHints '{}' >"$scratch/$n-candidate.json"
        ubus -s "$scratch/ubus.sock" -S -t 5 call luci-rpc getHostHints '{}' >"$scratch/$n-original.json"
    else
        ubus -s "$scratch/ubus.sock" -S -t 5 call luci-rpc getHostHints '{}' >"$scratch/$n-original.json"
        ubus -S -t 5 call luci-rpc getHostHints '{}' >"$scratch/$n-candidate.json"
    fi
    ip -6 neigh show >"$scratch/$n-neighbors-after.txt"
done
cleanup
rm -f "$scratch/ubus.sock"
touch "$scratch/COMPLETE"
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--recovery-gate", type=Path, required=True)
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", default="en0")
    a = p.parse_args()
    gate = json.loads(a.recovery_gate.read_text())
    assert gate["offline_backup_verified"] and gate["configuration_matches_backup"]
    assert gate["automatic_rollback_seconds"] == 900
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", a.host]

    def remote(command, timeout=30):
        return subprocess.check_output(ssh + [command], timeout=timeout)

    def save(name, value):
        (a.output / name).write_text(json.dumps(value, indent=2) + "\n")

    before = probe(host=a.host, mode="rust", interface=a.interface)
    save("health-before.json", before)
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify rust")
    config = remote("sha256sum /etc/config/*")
    manifest_bytes = remote("cat /root/r84/manifest.json")
    assert hashlib.sha256(manifest_bytes).hexdigest() == gate["candidate_manifest_sha256"]
    manifest = json.loads(manifest_bytes)
    scratch = "/tmp/r92-host-hints-" + uuid.uuid4().hex
    remote("mkdir " + scratch)
    save("owned-temporary.json", {"directory": scratch})
    script = a.output / "scenario.sh"
    script.write_text(SCENARIO)
    subprocess.run(["scp", "-O", "-q", str(script), a.host + ":" + scratch + "/scenario.sh"], check=True)
    assert remote("sha256sum " + scratch + "/scenario.sh").decode().split()[0] == hashlib.sha256(script.read_bytes()).hexdigest()
    with (a.output / "driver.log").open("xb") as log:
        result = subprocess.run(ssh + ["sh " + scratch + "/scenario.sh " + scratch],
                                stdout=log, stderr=log, timeout=60)
    archive = a.output / "raw.tar.gz"
    with archive.open("xb") as stream:
        subprocess.run(ssh + ["tar -czf - -C " + scratch + " ."], stdout=stream, check=True, timeout=60)
    raw = a.output / "raw"
    raw.mkdir(mode=0o700)
    with tarfile.open(archive) as tar:
        tar.extractall(raw, filter="data")
    hashes = remote("cd " + scratch + " && find . -type f -exec sha256sum '{}' ';'")
    (a.output / "raw.sha256").write_bytes(hashes)
    verified = set()
    for line in hashes.decode().splitlines():
        expected, name = line.split(None, 1)
        path = (raw / name).resolve()
        assert path.is_relative_to(raw.resolve()) and hashlib.sha256(path.read_bytes()).hexdigest() == expected
        assert path not in verified, "duplicate archive member"
        verified.add(path)
    assert verified == {p.resolve() for p in raw.rglob("*") if p.is_file()}
    result.check_returncode()
    assert (raw / "COMPLETE").exists()
    original = [line.split()[0] for line in (raw / "original-identities.txt").read_text().splitlines()]
    assert original == [manifest["components"][c]["original"]["sha256"] for c in ("ubusd", "rpcd")]
    rows = []
    for n in (1, 2, 3):
        old, new = [json.loads((raw / f"{n}-{side}.json").read_text()) for side in ("original", "candidate")]
        # No address, record, ordering or name mask: both read the same boot.
        assert old == new, f"live pair {n} differs"
        rows.append({"pair": n, "records": len(new), "exact_json_equal": True,
            "ipv6_addresses": sum(len(r["ip6addrs"]) for r in new.values()),
            "reply_sha256": {side: hashlib.sha256((raw / f"{n}-{side}.json").read_bytes()).hexdigest()
                             for side in ("original", "candidate")},
            "neighbor_snapshot_unchanged": (raw / f"{n}-neighbors-before.txt").read_bytes() ==
                                            (raw / f"{n}-neighbors-after.txt").read_bytes()})
    after = probe(host=a.host, mode="rust", interface=a.interface)
    assert after["boot_id"] == before["boot_id"]
    assert remote("sha256sum /etc/config/*") == config
    assert remote("/bin/sh /root/r84/stack-switch.sh verify rust") == identity
    save("health-after.json", after)
    save("summary.json", {"schema": 1, "passed": True, "pairs": rows,
        "original_sha256": dict(zip(("ubusd", "rpcd"), original)),
        "candidate_rpcd_sha256": manifest["components"]["rpcd"]["rust"]["sha256"],
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "configuration_and_identities_unchanged": True, "client_health_passed": True,
        "limitations": ["Three adjacent read-only pairs in one boot; historical neighbor snapshots were not collected."]})
    remote("rm -rf -- " + shlex.quote(scratch))
    (a.output / "COMPLETE").touch()
    print(json.dumps({"passed": True, "pairs": 3, "exact_json_equal": True}), flush=True)


if __name__ == "__main__":
    main()
