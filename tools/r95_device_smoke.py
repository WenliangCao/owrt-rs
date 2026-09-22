#!/usr/bin/env python3
"""Run one candidate in a disposable router namespace; production must be C.

Defaults to a correctness smoke. Explicit pilots gather exploratory data,
never a confirmation verdict. The candidate is never installed. A router-side
timeout bounds the namespace lifetime, and finally removes owned processes
and the temporary directory.
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


def archive_raw(ssh, base, output, name='raw'):
    """Keep transfer stderr and any partial archive, including on failure."""
    with (output / f'{name}.tar.gz').open('wb') as archive, \
            (output / f'{name}-archive.log').open('wb') as log:
        subprocess.run(ssh + [f'tar -czf - -C {base}/out .'], stdout=archive,
                       stderr=log, check=True, timeout=30)
    with tarfile.open(output / f'{name}.tar.gz') as archive:
        archive.extractall(output / name, filter='data')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("component", choices=("uci", "reload-config", "fw4", "logd", "rpcd",
                                         "httpd", "procd", "ubusd", "netifd"))
    p.add_argument("candidate", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--recovery-gate", type=Path, required=True)
    p.add_argument("--guard", type=Path, required=True, help="SDK-built tools/testsrc/r95_guard.c")
    p.add_argument("--benchmark", type=Path, help="explicit diagnostic client override; identity recorded, never installed")
    p.add_argument("--event-benchmark", type=Path, help="optional separate event caller; copied as /tmp/bin/event-benchmark")
    p.add_argument("--unit-tests", type=Path, help="SDK-built Rust test executable")
    p.add_argument("--unit-filter", default="file::read_tests", help="test name filter, recorded in evidence")
    p.add_argument("--workload-script", type=Path, help="isolated.sh-compatible correctness probe")
    p.add_argument("--before-candidate", type=Path, help="optional failing-version control for the probe")
    p.add_argument("--implementation", choices=("c", "rs"), default="rs")
    p.add_argument("--iterations", type=int, default=10)
    p.add_argument("--pilot", action="store_true", help="exploration only; requires an explicit workload or matrix")
    p.add_argument("--matrix", action="store_true", help="existing expanded daemon workload matrix")
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", default="en0")
    a = p.parse_args()
    if a.iterations <= 0 or (a.pilot and not (a.workload_script or a.matrix)):
        p.error("iterations must be positive; pilots require --workload-script or --matrix")
    if a.matrix and (a.workload_script or a.component not in ("ubusd", "procd", "netifd", "rpcd", "httpd")):
        p.error("matrix requires a supported daemon and no custom workload script")
    a.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", a.host]

    def remote(command, timeout=30):
        return subprocess.check_output(ssh + [command], timeout=timeout)

    def save(name, value):
        (a.output / name).write_text(json.dumps(value, indent=2) + "\n")

    gate = json.loads(a.recovery_gate.read_text())
    assert gate["offline_backup_verified"] and gate["configuration_matches_backup"]
    before = probe(host=a.host, mode="stock", interface=a.interface)
    assert before["boot_id"] == gate["boot_id"], "recovery gate is for another boot"
    save("health-before.json", before)
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify stock")
    config = remote("sha256sum /etc/config/*")
    mounts = remote("cat /proc/self/mountinfo")
    base = "/tmp/r95-check-" + uuid.uuid4().hex
    binary = "reload_config_rs" if a.component == "reload-config" else a.component + "-rs"
    harness = Path(__file__).parent / "benchmark/isolated.sh"
    workload = a.workload_script or harness
    remote_script = f"{base}/probe.sh" if a.workload_script else f"{base}/isolated.sh"
    digest = hashlib.sha256(a.candidate.read_bytes()).hexdigest()
    result = {"component": a.component, "candidate_sha256": digest,
              "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "workload_sha256": hashlib.sha256(workload.read_bytes()).hexdigest(),
              "guard_sha256": hashlib.sha256(a.guard.read_bytes()).hexdigest(),
              "recovery_gate_sha256": hashlib.sha256(a.recovery_gate.read_bytes()).hexdigest(),
              "correctness_smoke_only": not a.pilot, "pilot_only": a.pilot,
              "implementation": a.implementation, "iterations": a.iterations, "installed": False,
              "matrix": a.matrix,
              "production_mode": "stock", "remote": base,
              "passed": False, "cleanup_verified": False}
    failure = None
    try:
        remote(f"test ! -e {base} && mkdir -p {base}/bundle {base}/out {base}/work")
        remote(f"cp /root/r84/bins/ns-exec /root/r84/bins/owrt-benchmark {base}/bundle/")
        if a.benchmark:
            result["benchmark_sha256"] = hashlib.sha256(a.benchmark.read_bytes()).hexdigest()
            subprocess.run(["scp", "-q", "-O", str(a.benchmark.resolve()),
                            a.host + f":{base}/bundle/owrt-benchmark"], check=True)
        if a.event_benchmark:
            result["event_benchmark_sha256"] = hashlib.sha256(a.event_benchmark.read_bytes()).hexdigest()
            subprocess.run(["scp", "-q", "-O", str(a.event_benchmark.resolve()),
                            a.host + f":{base}/bundle/event-benchmark"], check=True)
        for local, destination in [(a.candidate, f"{base}/bundle/{binary}"),
                                   (a.guard, f"{base}/guard"),
                                   (harness, f"{base}/isolated.sh")]:
            subprocess.run(["scp", "-q", "-O", str(local.resolve()), a.host + ":" + destination], check=True)
        assert remote(f"sha256sum {base}/bundle/{binary}").decode().split()[0] == digest
        assert remote(f"sha256sum {base}/guard").decode().split()[0] == result["guard_sha256"]
        remote(f"cp {base}/guard {base}/bundle/guard")
        if a.workload_script:
            subprocess.run(["scp", "-q", "-O", str(workload.resolve()), a.host + ":" + remote_script], check=True)
        assert remote(f"sha256sum {remote_script}").decode().split()[0] == result["workload_sha256"]
        if a.before_candidate:
            old_sha = hashlib.sha256(a.before_candidate.read_bytes()).hexdigest()
            subprocess.run(["scp", "-q", "-O", str(a.before_candidate.resolve()), a.host + f":{base}/bundle/before-rs"], check=True)
            assert remote(f"sha256sum {base}/bundle/before-rs").decode().split()[0] == old_sha
            result["before_candidate_sha256"] = old_sha
        manifest = json.loads(remote("cat /root/r84/manifest.json"))
        if a.implementation == "c":
            assert digest == manifest["components"][a.component]["original"]["sha256"]
        for tool in ("ns-exec", "owrt-benchmark"):
            expected = (result["benchmark_sha256"] if tool == "owrt-benchmark" and a.benchmark
                        else manifest["tools"][tool]["sha256"])
            assert remote(f"sha256sum {base}/bundle/{tool}").decode().split()[0] == expected
        if a.event_benchmark:
            assert remote(f"sha256sum {base}/bundle/event-benchmark").decode().split()[0] == result["event_benchmark_sha256"]
        if a.unit_tests:
            unit_sha = hashlib.sha256(a.unit_tests.read_bytes()).hexdigest()
            subprocess.run(["scp", "-q", "-O", str(a.unit_tests.resolve()), a.host + f":{base}/unit-tests"], check=True)
            assert remote(f"sha256sum {base}/unit-tests").decode().split()[0] == unit_sha
            remote(f"mkdir {base}/unit-tmp")
            command = (f"TMPDIR={base}/unit-tmp {base}/guard 120 {base}/bundle/ns-exec "
                       f"{base}/unit-tests {shlex.quote(a.unit_filter)} --test-threads=1 --nocapture")
            with (a.output / "unit-tests.log").open("wb") as log:
                unit = subprocess.run(ssh + [command], stdout=log, stderr=subprocess.STDOUT, timeout=150)
            result["unit_tests"] = {"sha256": unit_sha, "filter": a.unit_filter, "exit": unit.returncode}
            unit.check_returncode()
        # Kill the namespace launcher itself on timeout: its init has PDEATHSIG
        # and owns every descendant, including detached child processes.
        command = (f"{base}/guard 120 {base}/bundle/ns-exec /bin/sh {remote_script} "
                   f"--namespace /rom {base}/bundle {a.component} {a.implementation} {base}/out {a.iterations} "
                   f"{base}/work {remote_script}")
        if a.matrix:
            command = "OWRT_" + a.component.upper() + "_MATRIX=1 " + command
        with (a.output / "run.log").open("wb") as log:
            run = subprocess.run(ssh + [command], stdout=log, stderr=subprocess.STDOUT, timeout=150)
        result["exit"] = run.returncode
        archive_raw(ssh, base, a.output)
        run.check_returncode()
        assert (a.output / "raw/COMPLETE").is_file()
        assert (a.output / "raw/binary-sha256.txt").read_text().split()[0] == digest
        result["passed"] = True
    except BaseException as error:
        failure = error
        result["error"] = {"type": type(error).__name__, "message": str(error)}
        # A timeout can occur before the normal archive step. Preserve what is
        # available before deleting the owned remote directory; never replace
        # the original failure or overwrite an earlier (possibly partial) tar.
        try:
            archive_raw(ssh, base, a.output, 'failed-raw')
            result["failure_archive"] = "failed-raw.tar.gz"
        except BaseException as archive_error:
            result["failure_archive_error"] = {"type": type(archive_error).__name__,
                                                "message": str(archive_error)}
        raise
    finally:
        # Limit cleanup strictly to the fresh UUID-owned namespace/bundle.
        cleanup = f"""set -eu
for p in /proc/[0-9]*; do
    for what in exe root; do
        target=$(readlink "$p/$what" 2>/dev/null || true)
        case "$target" in {base}/*) kill -KILL "${{p##*/}}" 2>/dev/null || true ;; esac
    done
done
live=1
for attempt in 1 2 3 4 5; do
    live=
    for p in /proc/[0-9]*; do
        for what in exe root; do
            target=$(readlink "$p/$what" 2>/dev/null || true)
            case "$target" in {base}/*) live=1 ;; esac
        done
    done
    [ -n "$live" ] || break
    sleep 1
done
test -z "$live"
rm -rf -- {shlex.quote(base)}
test ! -e {shlex.quote(base)}
"""
        cleanup_failure = None
        try:
            remote(cleanup)
            after = probe(host=a.host, mode="stock", interface=a.interface)
            save("health-after.json", after)
            result["cleanup_verified"] = True
            result["same_boot"] = before["boot_id"] == after["boot_id"]
            result["same_config"] = config == remote("sha256sum /etc/config/*")
            result["same_production_identity"] = identity == remote("/bin/sh /root/r84/stack-switch.sh verify stock")
            result["same_host_mounts"] = mounts == remote("cat /proc/self/mountinfo")
            assert all(result[k] for k in ("same_boot", "same_config", "same_production_identity", "same_host_mounts"))
        except BaseException as error:
            cleanup_failure = error
            result["passed"] = False
            result["cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
            if failure is None:
                raise
        finally:
            try:
                save("result.json", result)
            except BaseException as error:
                original = failure or cleanup_failure
                if original is None:
                    raise
                original.add_note(f"Could not save result.json: {error}")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
