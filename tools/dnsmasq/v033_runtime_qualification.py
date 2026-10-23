#!/usr/bin/env python3
"""Bind one v0.3.3 CI ELF to existing isolated runtime qualification tools.

The comparison is a fresh v0.3.2 regression control, not the historical K
performance experiment. No product build, router access or kernel-log read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

BASELINE_SHA = "2a22f6327d81e25c8bf9e891d21842e5ef0d33ec074e5004506388f3b616e2a2"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(argv, log, timeout=300, allow_failure=False):
    with log.open("xb") as stream:
        process = subprocess.Popen([str(arg) for arg in argv], stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    if not allow_failure and code != 0:
        raise RuntimeError(f"{argv[0]} exited {code}: {log}")
    return code


def isolated(argv):
    return ["env", "DNSMASQ_TEST_ISOLATED=1", "unshare", "--mount", "--net", "sh", "-c",
            'mount --make-rprivate / && ip link set lo up && exec "$@"', "isolated", *argv]


def shipping(source, image, binary, output):
    sys.path.insert(0, str(source / "tools/dnsmasq"))
    from audit_20261011_static_pie import observe
    value = observe(image, binary, output)
    assert value["elf_type"] == 3 and value["distinct_bases"] == 3
    assert all(row["relro_readonly"] and not row["stack_executable"] for row in value["runs"])
    save(output / "result.json", dict(passed=True, **value))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--shipping":
        shipping(*(Path(value) for value in sys.argv[2:]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("ci", "source", "image", "baseline", "helpers", "out"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-spec", type=Path, required=True)
    parser.add_argument("--source-spec-sha256", required=True)
    parser.add_argument("--run", action="store_true", help="execute after binding; default only prepares")
    args = parser.parse_args()
    assert sys.platform == "linux" and not sys.flags.optimize
    ci, source, image, baseline, helpers, out = (getattr(args, key).resolve()
        for key in ("ci", "source", "image", "baseline", "helpers", "out"))
    assert "private" in out.parts and not out.exists()
    manifest_path = ci / "manifest.json"
    assert sha(manifest_path) == args.manifest_sha256
    manifest = json.loads(manifest_path.read_text())
    assert sha(args.source_spec) == args.source_spec_sha256
    freeze = json.loads(args.source_spec.read_text())
    assert freeze["openwrt"] == "25.12.6" and freeze["pgo_stage"] == "candidate-use"
    commit, digest = freeze["source_commit"], freeze["source_digest"]
    assert manifest["source_commit"] == commit and manifest["source_digest"] == digest
    assert manifest["source_files"] == freeze["source_files"]
    assert manifest["sdk"]["archive_sha256"] == "1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e"
    for key in ("profile_sha256", "profile_bytes", "training"):
        assert manifest["pgo"][key] == freeze["pgo"][key]
    assert manifest["pgo_stage"] == "candidate-use" and manifest["pgo"]["mode"] == "use"
    assert manifest["status"] == "created-unqualified-pgo-candidate"
    assert len(manifest["source_files"]) == freeze["source_file_count"]
    assert hashlib.sha256(json.dumps(manifest["source_files"], sort_keys=True,
        separators=(",", ":")).encode()).hexdigest() == digest
    assert all(sha(source / path) == digest for path, digest in manifest["source_files"].items())
    assert manifest["warnings"]["strict_compiler_warnings_zero"]
    assert manifest["compiler_warnings"]["strict_compiler_warnings_zero"]
    assert manifest["pgo"]["profile_diagnostics"] == []
    binary = ci / "dnsmasq-rs"
    assert sha(binary) == manifest["elf"]["sha256"] and binary.stat().st_size == manifest["elf"]["size"]
    package = ci / manifest["artifact"]["name"]
    assert sha(package) == manifest["artifact"]["sha256"]
    assert binary.stat().st_size <= 2500000 and package.stat().st_size <= 1400000
    assert sha(baseline) == BASELINE_SHA
    assert sha(image / "usr/sbin/dnsmasq") == "097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87"
    tools = source / "tools/dnsmasq"
    observer = helpers / "device_selfexec_lifecycle"
    for name in ("device_selfexec_lifecycle", "m6a_upstream", "device_perf_netns", "nice10"):
        assert (helpers / name).is_file(), name
    identities = {str(path): sha(path) for path in [binary, package, baseline, manifest_path, args.source_spec, observer,
        *[tools / name for name in ("selfexec_jail_boundary.py", "selfexec_fd_headroom.py",
          "safe_v022_startup_case.sh", "safe_v022_startup_group.sh", "safe_v022_startup_run.py")],
        *[helpers / name for name in ("m6a_upstream", "device_perf_netns", "nice10")]]}
    out.mkdir(parents=True)
    report = {"status": "prepared-not-executed", "source_commit": commit, "source_digest": digest,
        "manifest_sha256": args.manifest_sha256, "elf_sha256": sha(binary), "baseline_sha256": BASELINE_SHA,
        "baseline": "fresh v0.3.2 shipped ELF control; no historical K receipts reused",
        "identities": identities, "checks": {}, "physical_router_touched": False,
        "prediction": "both no-proc modes pass; candidate has no new FD failures versus fresh v0.3.2; "
          "restore/recovery successes do not regress; candidate RELRO/NX and 3 ASLR bases pass; all 40 starts qualify",
        "scope": "behavior regression only; startup CPU/latency is retained but not a performance verdict"}
    save(out / "result.json", report)
    if not args.run:
        print(json.dumps(report))
        return
    assert os.geteuid() == 0
    report["status"] = "running"
    save(out / "result.json", report)
    try:
        fd_results = {}
        for role, executable, commit in (("baseline-v032", baseline, "v0.3.2"),
                                         ("candidate", binary, commit)):
            common = ["--image-root", str(image), "--binary", str(executable), "--sha256", sha(executable),
                      "--source-commit", commit]
            folder = out / (role + "-no-proc")
            command(isolated([sys.executable, str(tools / "selfexec_jail_boundary.py"), *common,
                              "--case", "both", "--expect", "success", "--output", str(folder)]),
                    out / (role + "-no-proc.log"))
            result = json.loads((folder / "result.json").read_text())
            assert result["passed"]
            report["checks"][role + "-no-proc"] = {"passed": True, "result_sha256": sha(folder / "result.json")}
            folder = out / (role + "-fd")
            code = command(isolated([sys.executable, str(tools / "selfexec_fd_headroom.py"), *common,
                            "--proc-mode", "visible", "--output", str(folder)]),
                           out / (role + "-fd.log"), allow_failure=True)
            assert code in (0, 1)
            result = json.loads((folder / "result.json").read_text())
            assert len(result["cases"]) == 8
            cases = {(case["mode"], case["fd_pressure"]["headroom"]): case for case in result["cases"]}
            assert len(cases) == 8
            for case in cases.values():
                change = case["fd_pressure"]["limit_change"]
                assert change["applied_exactly"]
                assert all(case["fd_pressure"][phase]["health_ok"] for phase in ("pressure", "recovery"))
            fd_results[role] = cases
            report["checks"][role + "-fd"] = {"result_sha256": sha(folder / "result.json"),
                "passing": [f"{mode}:{holes}" for (mode, holes), case in cases.items() if case["passed"]]}
            save(out / "result.json", report)
        regressions = [f"{mode}:{holes}" for (mode, holes), case in fd_results["baseline-v032"].items()
                       if case["passed"] and not fd_results["candidate"][(mode, holes)]["passed"]]
        # The released helper already has low-FD failure boundaries, including
        # exiting at two holes. Compare each observed success as well as the
        # whole-case result; do not turn those known failures into green rows.
        for key, baseline_case in fd_results["baseline-v032"].items():
            before, after = baseline_case["fd_pressure"], fd_results["candidate"][key]["fd_pressure"]
            for phase in ("pressure", "recovery"):
                for field in ("operation_ok", "health_ok"):
                    if before[phase][field] and not after[phase][field]:
                        regressions.append(f"{key}:{phase}:{field}")
            if before["limit_change"]["restore"].get("restored") and not after["limit_change"]["restore"].get("restored"):
                regressions.append(f"{key}:restore")
        assert not regressions
        assert all(case["passed"] for (mode, _), case in fd_results["candidate"].items() if mode == "resolver")
        report["checks"]["fd_regressions"] = regressions
        command(isolated([sys.executable, str(Path(__file__).resolve()), "--shipping", str(source),
                          str(image), str(binary), str(out / "shipping")]), out / "shipping.log")
        report["checks"]["shipping"] = json.loads((out / "shipping/result.json").read_text())

        # The frozen C observer explicitly requires a fresh /tmp root.
        runtime = Path(tempfile.mkdtemp(prefix="dnsmasq-v033-startup-", dir="/tmp"))
        runtime.chmod(0o755)
        report["startup_runtime"] = str(runtime)
        save(out / "result.json", report)
        (runtime / "runs").mkdir()
        for role, executable in (("k", baseline), ("candidate", binary)):
            target = runtime / ("artifact-" + role)
            shutil.copy2(executable, target)
            target.chmod(0o755)
            os.chown(target, 0, 0)
            if "security.capability" in os.listxattr(target):
                os.removexattr(target, "security.capability")
        for name in ("device_selfexec_lifecycle", "m6a_upstream", "device_perf_netns", "nice10"):
            shutil.copy2(helpers / name, runtime / name)
        for name in ("safe_v022_startup_case.sh", "safe_v022_startup_group.sh"):
            text = (tools / name).read_text()
            assert text.count("root=/tmp/dnsmasq-perf-v022-20261017") == 1
            (runtime / name).write_text(text.replace("root=/tmp/dnsmasq-perf-v022-20261017", "root=" + str(runtime)))
        sys.path.insert(0, str(tools))
        import safe_v022_startup_run as startup
        starts = []
        for mode, role in startup.ORDER:
            label = "startup-" + mode + "-" + role
            command([runtime / "nice10", runtime / "device_perf_netns", "/bin/sh",
                     runtime / "safe_v022_startup_case.sh", mode, role, label], out / (label + ".log"), timeout=90)
            value = startup.validate(runtime / "runs" / label, mode, role, sha(runtime / ("artifact-" + role)))
            starts.append({"role": "baseline-v032" if role == "k" else role, **value})
        callbacks = [[row["callback_count"] for row in value["starts"]]
                     for value in starts if value["mode"] == "helper"]
        assert callbacks[0] == callbacks[1]
        report["checks"]["startup"] = {"starts": sum(len(value["starts"]) for value in starts),
                                          "helper_callbacks": callbacks, "cases": starts}
        assert report["checks"]["startup"]["starts"] == 40
        assert all(sha(path) == digest for path, digest in identities.items())
        report["status"] = "passed-runtime-regression-vs-v032"
    except BaseException as error:
        report.update(status="failed-preserved", error=repr(error))
        raise
    finally:
        save(out / "result.json", report)
        print(json.dumps({key: report[key] for key in ("status", "elf_sha256", "baseline_sha256")}))


if __name__ == "__main__":
    main()
