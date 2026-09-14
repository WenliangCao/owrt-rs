#!/usr/bin/env python3
"""Compare real-radio flags with zeroed/poisoned buffers in exact libiwinfo.

Physical use requires the previously authorized recovery gate. Queries are
read-only, serialized outside measured workloads; output stays under private/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import uuid

from r84_device_probe import probe

FLAGS = ("no_10mhz", "no_20mhz", "no_ht40+", "no_ht40-", "no_80mhz",
         "no_160mhz", "no_he", "no_ir", "indoor_only")
BANDS = {1: 2, 2: 5, 4: 6, 8: 60}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("helper", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", default="en0")
    p.add_argument("--recovery-gate", type=Path, required=True)
    a = p.parse_args()
    gate = json.loads(a.recovery_gate.read_text())
    assert gate["offline_backup_verified"] and gate["configuration_matches_backup"]
    assert gate["automatic_rollback_seconds"] == 900
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", a.host]

    def remote(command):
        return subprocess.check_output(ssh + [command], timeout=30)

    def save(name, data):
        (a.output / name).write_text(json.dumps(data, indent=2) + "\n")

    before = probe(host=a.host, mode="rust", interface=a.interface)
    save("health-before.json", before)
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify rust")
    config = remote("sha256sum /etc/config/*")
    library = "/usr/lib/libiwinfo.so.20230701"
    hashes = remote("sha256sum " + library + " /rom" + library).decode().splitlines()
    assert len(hashes) == 2 and hashes[0].split()[0] == hashes[1].split()[0]
    executable = "/tmp/r92-iwinfo-flags-" + uuid.uuid4().hex
    subprocess.run(["scp", "-O", "-q", str(a.helper), a.host + ":" + executable], check=True)
    helper_sha = hashlib.sha256(a.helper.read_bytes()).hexdigest()
    assert remote("sha256sum " + executable).decode().split()[0] == helper_sha
    rows = []
    for device in sorted(before["ap_bridges"]):
        controls = [json.loads(remote(" ".join(map(shlex.quote, (executable, device, preset)))))
                    for preset in ("0", "511", "0")]
        zero, poison, again = controls
        assert zero == again and zero["entry_bytes"] == 16 and zero["known_mask"] == 511
        expected = [{"band": BANDS[e["band_mask"]], "channel": e["channel"], "mhz": e["mhz"],
                     "restricted": e["restricted"],
                     "flags": [flag for i, flag in enumerate(FLAGS) if e["flags_mask"] & (1 << i)]}
                    for e in zero["entries"]]
        assert any(e["flags_mask"] != 511 for e in zero["entries"])
        assert len(poison["entries"]) == len(expected)
        for clean, dirty in zip(zero["entries"], poison["entries"]):
            assert all(clean[k] == dirty[k] for k in ("band_mask", "channel", "mhz"))
            assert dirty["flags_mask"] == 511 and dirty["restricted"] is True
        command = " ".join(shlex.quote(s) for s in ("ubus", "-S", "call", "iwinfo", "freqlist", json.dumps({"device": device})))
        actual = json.loads(remote(command))["results"]
        # Active channel is queried separately by rpcd; all backend fields
        # including every regulatory flag must equal the zeroed C control.
        assert all(set(e) == set(expected[0]) | {"active"} and isinstance(e["active"], bool) for e in actual)
        assert [{k: v for k, v in e.items() if k != "active"} for e in actual] == expected
        rows.append({"device": device, "zeroed": zero, "poisoned": poison,
                     "repeated_zeroed": again, "candidate": actual,
                     "candidate_matches_zeroed_exact_library": True, "original_buffer_dependency_reproduced": True})
        save("results.json", rows)
    after = probe(host=a.host, mode="rust", interface=a.interface)
    assert after["boot_id"] == before["boot_id"]
    assert remote("sha256sum /etc/config/*") == config
    assert remote("/bin/sh /root/r84/stack-switch.sh verify rust") == identity
    save("health-after.json", after)
    save("identities.json", {"helper_sha256": helper_sha, "original_library_sha256": hashes[0].split()[0],
                            "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    remote("rm -- " + executable)
    (a.output / "COMPLETE").touch()
    print(json.dumps({"radios": len(rows), "candidate_matches_zeroed_exact_library": True,
                      "original_buffer_dependency_reproduced": True, "client_health": "passed"}))


if __name__ == "__main__":
    main()
