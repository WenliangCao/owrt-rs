#!/usr/bin/env python3
"""Measure inactive bundle cache advice separately from normal router windows.

Explicitly exclude active executable inodes. Alternate clean-page advice and
hash rereads of the nine current reference copies; retain all raw observations.
This diagnostic is serialized after performance trials and changes no file bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe  # noqa: E402
from analyze import SYSTEM_MEMORY_KEYS, stats  # noqa: E402


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("advice", type=Path)
    p.add_argument("residency", type=Path)
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

    def remote(command, timeout=60):
        return subprocess.check_output(ssh + [command], timeout=timeout)

    def save(name, value):
        (a.output / name).write_text(json.dumps(value, indent=2) + "\n")

    health = probe(host=a.host, mode="rust", interface=a.interface)
    save("health-before.json", health)
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify rust")
    config = remote("sha256sum /etc/config/*")
    manifest_bytes = remote("cat /root/r84/manifest.json")
    assert hashlib.sha256(manifest_bytes).hexdigest() == gate["candidate_manifest_sha256"]
    manifest = json.loads(manifest_bytes)
    references = ["/root/r84/bins/" + c["rust"]["binary"] for c in manifest["components"].values()]
    expected = {"/root/r84/bins/" + c["rust"]["binary"]: c["rust"]["sha256"] for c in manifest["components"].values()}
    active, pids = [], []
    for line in identity.decode().splitlines():
        component, pid, digest = line.split()
        assert digest == manifest["components"][component]["rust"]["sha256"]
        active.append("/proc/" + pid + "/exe" if pid != "-" else manifest["components"][component]["original"]["path"])
        if pid != "-":
            pids.append(pid)
    scratch = "/tmp/r92-reference-cache-" + uuid.uuid4().hex
    remote("mkdir " + scratch)
    save("owned-temporary.json", {"directory": scratch})
    for file, name in ((a.advice, "advice"), (a.residency, "residency")):
        subprocess.run(["scp", "-O", "-q", str(file), a.host + ":" + scratch + "/" + name], check=True)
        assert remote("sha256sum " + scratch + "/" + name).decode().split()[0] == sha(file)

    def pages(paths, name):
        data = remote(" ".join(map(shlex.quote, [scratch + "/residency", *paths])))
        (a.output / (name + ".tsv")).write_bytes(data)
        entries = [line.split("\t") for line in data.decode().splitlines()]
        assert len(entries) == len(paths)
        unique = {(e[0], e[1]): e for e in entries}
        assert len(unique) == len(paths)
        return {"identities": set(unique), "resident_kib": sum(int(e[4]) * int(e[5]) // 1024 for e in unique.values()),
                "total_kib": sum(int(e[3]) * int(e[5]) // 1024 for e in unique.values())}

    active_pages = pages(active, "active")
    reference_pages = pages(references, "references-initial")
    assert active_pages["identities"].isdisjoint(reference_pages["identities"])
    assert len(active_pages["identities"]) == len(reference_pages["identities"]) == 9

    def warm(name):
        hashes = remote(" ".join(map(shlex.quote, ["sha256sum", *references])))
        (a.output / (name + ".sha256")).write_bytes(hashes)
        actual = {line.split()[1]: line.split()[0] for line in hashes.decode().splitlines()}
        assert actual == expected

    phases = []

    def measure(name):
        before = pages(references, name + "-pages-before")
        data = remote("/root/r84/bins/owrt-benchmark idle 30 " + ",".join(pids))
        (a.output / (name + ".jsonl")).write_bytes(data)
        samples = [json.loads(line) for line in data.splitlines()]
        assert len(samples) == 31 and 29 <= samples[-1]["uptime_s"] - samples[0]["uptime_s"] <= 32
        first = {r["pid"]: r["start_ticks"] for r in samples[0]["processes"]}
        assert all({r["pid"]: r["start_ticks"] for r in s["processes"]} == first for s in samples)
        after = pages(references, name + "-pages-after")
        assert before["identities"] == after["identities"] == reference_pages["identities"]
        phases.append({"phase": name, "samples": len(samples), "duration_seconds": 30,
                       "reference_resident_kib_before": before["resident_kib"],
                       "reference_resident_kib_after": after["resident_kib"],
                       "system_memory_kib": {key: stats(s["memory_kib"][key] for s in samples) for key in SYSTEM_MEMORY_KEYS},
                       "daemon_rss_kib": stats(sum(r["VmRSS"] for r in s["processes"]) for s in samples),
                       "source_sha256": sha(a.output / (name + ".jsonl"))})
        save("phases.json", phases)
        print(json.dumps({"phase_complete": name, "reference_resident_kib": after["resident_kib"]}), flush=True)

    warm("initial-warm")
    measure("warm-0")
    for index in (1, 2):
        current_active = pages(active, f"active-before-advice-{index}")
        assert current_active["identities"].isdisjoint(reference_pages["identities"])
        response = remote(" ".join(map(shlex.quote, [scratch + "/advice", *references])))
        assert len(response.splitlines()) == 9
        (a.output / f"advice-{index}.txt").write_bytes(response)
        measure(f"advised-{index}")
        warm(f"reread-{index}")
        measure(f"warm-{index}")
    after = probe(host=a.host, mode="rust", interface=a.interface)
    assert after["boot_id"] == health["boot_id"]
    assert remote("sha256sum /etc/config/*") == config
    assert remote("/bin/sh /root/r84/stack-switch.sh verify rust") == identity
    save("health-after.json", after)
    save("summary.json", {"schema": 1, "inactive_files": 9, "active_inodes_excluded": True,
        "reference_file_pages_kib": reference_pages["total_kib"], "phases": phases,
        "identities": {"advice_sha256": sha(a.advice), "residency_sha256": sha(a.residency),
                       "driver_sha256": sha(Path(__file__)), "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest()},
        "files_and_configuration_unchanged": True, "client_health_passed": True,
        "limitations": ["Only the current inactive reference copies receive POSIX_FADV_DONTNEED advice.",
                        "The kernel may retain pages; mincore records what actually happened.",
                        "MemAvailable is a kernel estimate and also changes with unrelated router activity.",
                        "This causal diagnostic is separate from normal cold-window measurements."]})
    remote("rm -rf -- " + scratch)
    (a.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
