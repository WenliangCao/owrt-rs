#!/usr/bin/env python3
"""Oracle-only ACK-bracketed registration profile or synchronous perf counts.

Print a plan template for review and freezing:
  python3 r132_registration_profile.py --template profile > profile-plan.json
Run only after verifying every identity and freezing the plan:
  sudo python3 r132_registration_profile.py --oracle-host-only --plan PLAN --out NEW

One plan selects profile OR stat. Exact release bytes are copied to the same
launch pathname for every window. Only the client enable/disable ACK protocol
controls measurement; socket startup polling never defines a counting window.
The matching r121 helper modules must be present beside this script, with their
hashes frozen by the plan. No router access, mounts, deployment or runtime edits.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

import r121_perf_record as base
import r121_symbolize as symbolize

LABELS = ("c", "r124", "r131")
EVENTS = ["{instructions:u,branches:u,branch-misses:u,cycles:u}", "context-switches", "cpu-migrations"]
COUNTERS = ["instructions:u", "branches:u", "branch-misses:u", "cycles:u", "context-switches", "cpu-migrations"]
require, sha, save = base.require, base.sha, base.save_json
HERE = Path(__file__).resolve().parent


def template(mode):
    rootfs = "/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files"
    subjects = {
        "c": {"path": rootfs + "/sbin/ubusd", "sha256": "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88", "kind": "dynamic",
              "symbols": {"kind": "symbols_elf", "path": "/home/ubuntu/r121-symbol-profile/c-symbols", "sha256": "51f91f7d548600ca56ff47516f0a4854c50fb5a1defb768dc8ffabb5a202723b"}},
        "r124": {"path": "/home/ubuntu/r131-event-batch/maps/r124", "sha256": "42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926", "kind": "static",
                 "symbols": {"kind": "linker_map", "path": "/home/ubuntu/r131-event-batch/maps/r124.map", "sha256": "789129b18238a4c473fa3ee933d91ce42cb050c1c324532d1c0451495da4c9dc"}},
        "r131": {"path": "/home/ubuntu/r131-event-batch/maps/r131", "sha256": "c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a", "kind": "static",
                 "symbols": {"kind": "linker_map", "path": "/home/ubuntu/r131-event-batch/maps/r131.map", "sha256": "d484cbd5933dac273ff0105e64254183dfbf5fa29e77ec3551a4676e2015d4cf"}},
    }
    n = 300000 if mode == "profile" else 100000
    plan = {
        "schema_version": 1, "mode": mode,
        "purpose": "R132 exact-release registration attribution; Oracle diagnostic, not router acceptance",
        "runner_sha256": sha(__file__),
        "support_sha256": {name: sha(HERE / name) for name in ("r121_perf_record.py", "r121_symbolize.py")},
        "rootfs": {"path": rootfs, "libraries": {
            "/lib/libubus.so.20251202": "2967f7ce6e29e290eac0b76e88fc6b5d639763fa78be1e1b889fb088d9acda04",
            "/lib/libubox.so.20260213": "a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063",
            "/lib/libc.so": "8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b",
            "/lib/libgcc_s.so.1": "33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c",
            "/lib/libblobmsg_json.so.20260213": "e6a2a2cdf07f453c28f703537c636516e92d17b63ad732ec606b5cd99bd5ef97",
            "/usr/lib/libjson-c.so.5.4.0": "830799c5682eff7f75800482dabd65a1fe2e925374a19da2a25a2da708d8a153"}},
        "client": {"path": "/home/ubuntu/r132-registration-caller/build-02/owrt-register-perf", "sha256": "ad707cee9684aeaccbddf548f59eda18c2b6ce3eb7590cee5436296e18251b4f", "kind": "static"},
        "perf": {"path": "/usr/bin/perf", "sha256": "2d0953085bf720a25efbe24f853e97d27b1f12f18a398255ff82cbafde254dad"},
        "subjects": subjects,
        "launch_directory": "/tmp/r132-registration-normalized",
        "timeout_seconds": 180,
        "runs": [{"subject": label, "methods": methods, "name_bytes": 8, "n": n, "warmup": 5000}
                 for methods in (1, 16) for label in ("c", "r124", "r131", "r131", "r124", "c")],
        "interpretation": "Fixed diagnostic sample count; no automatic extension or router performance verdict",
    }
    if mode == "profile":
        plan["profile"] = {"event": "cpu-clock", "frequency_hz": 997, "mmap_buffer": "8M", "callgraph": False}
    else:
        plan["stat"] = {"events": EVENTS, "counter_names": COUNTERS, "running_percent_required": 100.0}
    return plan


def verify_symbols(binary, spec):
    """Reject a diagnostic companion whose emitted .text differs."""
    exact = symbolize.ELF(binary)
    symbol_path = base.checked_path(spec["path"])
    base.check_hash(symbol_path, spec["sha256"])
    require(spec["kind"] in ("symbols_elf", "linker_map"), "unknown symbol source")
    companion = symbolize.ELF(symbol_path) if spec["kind"] == "symbols_elf" else exact
    text = companion.section(".text")
    require(text is not None and text.flags & 4, "symbol source has no executable .text")
    body = exact.virtual_bytes(text.address, text.size)
    require(exact.kind == companion.kind and body == companion.virtual_bytes(text.address, text.size),
            "symbol companion .text does not match exact release")
    ranges = (symbolize.elf_function_ranges(companion) if spec["kind"] == "symbols_elf" else
              symbolize.linker_map_ranges(symbol_path.read_text(), text.address, text.size))
    require(ranges, "symbol source provides no bounded function ranges")
    return {"elf_sha256": exact.sha256, "symbol_source_sha256": sha(symbol_path),
            "kind": spec["kind"], "text_start": text.address, "text_bytes": text.size,
            "text_sha256": hashlib.sha256(body).hexdigest(), "bounded_ranges": len(ranges)}


def load_plan(path):
    plan = json.loads(path.read_text())
    require(plan["schema_version"] == 1 and plan["mode"] in ("profile", "stat"), "plan schema/mode")
    base.check_hash(__file__, plan["runner_sha256"])
    require(set(plan["support_sha256"]) == {"r121_perf_record.py", "r121_symbolize.py"}, "support module set")
    for name, digest in plan["support_sha256"].items():
        base.check_hash(HERE / name, digest)
    require(set(plan["subjects"]) == set(LABELS), "subjects must be exact C/R124/R131")
    require(plan["client"]["kind"] in ("static", "dynamic"), "client kind")
    require(type(plan["timeout_seconds"]) is int and 1 <= plan["timeout_seconds"] <= 180, "timeout bound")
    launch = Path(plan["launch_directory"])
    require(launch.parent == Path("/tmp") and re.fullmatch(r"r132-registration-[a-zA-Z0-9_-]+", launch.name), "unsafe launch directory")
    require(plan["runs"] and len(plan["runs"]) <= 48, "run count")
    for item in plan["runs"]:
        require(set(item) == {"subject", "methods", "name_bytes", "n", "warmup"}, "run fields")
        require(item["subject"] in LABELS, "run subject")
        for key, minimum, maximum in (("methods", 1, 64), ("name_bytes", 8, 128), ("n", 1, 1000000), ("warmup", 0, 100000)):
            require(type(item[key]) is int and minimum <= item[key] <= maximum, f"run {key}")
    if plan["mode"] == "profile":
        profile = plan["profile"]
        require(set(profile) == {"event", "frequency_hz", "mmap_buffer", "callgraph"} and
                profile["event"] == "cpu-clock" and profile["mmap_buffer"] == "8M" and
                profile["callgraph"] is False and type(profile["frequency_hz"]) is int and
                profile["frequency_hz"] in (249, 499, 997), "profile settings")
        require("stat" not in plan, "profile and stat must use separate plans")
    else:
        require(plan["stat"] == {"events": EVENTS, "counter_names": COUNTERS, "running_percent_required": 100.0}, "stat settings")
        require("profile" not in plan, "profile and stat must use separate plans")
    return plan


def stat_counts(path, expected):
    counts = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        require("<not " not in line, "perf counter unavailable/not counted")
        parts = line.split(";")
        if len(parts) < 5:
            continue
        event = parts[2].strip()
        require(event in expected and event not in counts, f"unexpected/duplicate counter: {event}")
        value, enabled, running = float(parts[0]), float(parts[3]), float(parts[4])
        require(all(math.isfinite(v) for v in (value, enabled, running)) and value >= 0 and enabled > 0,
                "invalid counter values")
        require(running == 100.0, f"counter multiplexed: {event} {running}%")
        counts[event] = {"value": value, "enabled_ns": enabled, "running_percent": running}
    require(set(counts) == set(expected), "missing counters")
    require(counts["instructions:u"]["value"] > 0, "no user instructions counted")
    require(counts["cpu-migrations"]["value"] == 0, "pinned daemon migrated")
    return counts


def validate_client(data, item, daemon_pid, client_pid):
    expected = {**{key: item[key] for key in ("n", "warmup", "methods", "name_bytes")},
                "subject_pid": daemon_pid, "client_pid": client_pid, "subject_cpu": 1, "client_cpu": 0,
                "fixture": "rust_register_cycle", "successful": item["n"], "errors": 0,
                "latency_sample_count": item["n"]}
    for key, value in expected.items():
        require(data.get(key) == value, f"client {key} mismatch")
    for key in ("perf_controlled", "full_signature_checked", "warmup_empty", "final_empty"):
        require(data.get(key) is True, f"client {key} not validated")
    require(data.get("wire_reply_bytes_checked") is False, "caller contract misreported")
    samples = data["latency_ns"]
    require(len(samples) == item["n"] and all(type(v) is int and v > 0 for v in samples), "invalid latency samples")
    elapsed = {clock: data[f"{clock}_after_ns"] - data[f"{clock}_before_ns"] for clock in ("subject", "client", "wall")}
    require(all(type(v) is int and v > 0 for v in elapsed.values()) and sum(samples) <= elapsed["wall"], "invalid client clocks")
    require(elapsed["subject"] <= elapsed["wall"] and elapsed["client"] <= elapsed["wall"], "process CPU exceeds enclosing wall interval")
    require(data["subject_resolution_ns"] > 0 and data["client_resolution_ns"] > 0, "invalid resolution")
    return elapsed


def pid_start(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]


def client_identity(process, out, client, loader, libraries, spec):
    """Observe the owned caller after exec/pin; this is not a timing gate."""
    deadline = time.monotonic() + 5
    proc = Path(f"/proc/{process.pid}")
    dynamic = spec["kind"] == "dynamic"
    expected = {**(libraries if dynamic else {}), client: spec["sha256"]}
    while True:
        require(process.poll() is None, "caller exited before live identity observation")
        maps = (proc / "maps").read_text()
        if str(client) in maps and os.sched_getaffinity(process.pid) == {0}:
            break
        require(time.monotonic() < deadline, "caller exec/pin observation timeout")
        time.sleep(.001)
    base.check_hash(proc / "exe", expected[loader if dynamic else client])
    mapped = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        path = Path(fields[5]).resolve(strict=True)
        require(path in expected, f"unplanned caller mapping: {path}")
        st = path.stat(); major, minor = (int(v, 16) for v in fields[3].split(":"))
        require((st.st_ino, os.major(st.st_dev), os.minor(st.st_dev)) == (int(fields[4]), major, minor), "caller mapped inode changed")
        mapped[str(path)] = base.check_hash(path, expected[path])
    require(str(client) in mapped, "caller ELF not mapped")
    (out / "client-maps.txt").write_text(maps)
    (out / "client-status.txt").write_text((proc / "status").read_text())
    (out / "client-cmdline.bin").write_bytes((proc / "cmdline").read_bytes())
    save(out / "client-identity.json", {"pid": process.pid, "start_ticks": pid_start(process.pid),
                                        "affinity": [0], "mapped_sha256": mapped})


def perf_reports(out, plan, item, subject, original, loader, libraries, env, perf_path, info):
    prefix = [str(perf_path), "--buildid-dir", str(out / "empty-buildid-cache")]
    jobs = {
        "report": ["report", "-i", str(out / "perf.data"), "--stdio", "--header", "--no-children", "--show-nr-samples", "--show-total-period", "--show-cpu-utilization", "--percent-limit", "0", "--sort", "dso,symbol"],
        "samples": ["script", "-i", str(out / "perf.data"), "-F", "misc,ip,sym,dso"],
        "samples-detail": ["script", "-i", str(out / "perf.data"), "-F", "pid,tid,misc,time,event,ip,sym,dso"],
        "events": ["script", "-i", str(out / "perf.data"), "--show-lost-events", "--show-mmap-events", "-F", "misc,ip,sym,dso"],
        "stats": ["report", "-i", str(out / "perf.data"), "--stdio", "--stats", "--no-skip-empty"],
    }
    for stem, command in jobs.items():
        base.run_saved(prefix + command, out, stem, env)
    base.summarize_samples(out, info)
    command = [sys.executable, str(HERE / "r121_symbolize.py"), "--perf-script", str(out / "samples.txt"),
               "--proc-maps", str(out / "maps-before.txt"), "--elf", f"{subject}={original}",
               "--expected-sha256", f"{subject}={plan['subjects'][item['subject']]['sha256']}",
               "--output", str(out / "symbolized.json"), "--top", "100"]
    symbols = plan["subjects"][item["subject"]]["symbols"]
    verify_symbols(original, symbols)
    command += ["--symbols-elf" if symbols["kind"] == "symbols_elf" else "--linker-map", f"{subject}={symbols['path']}"]
    if plan["subjects"][item["subject"]]["kind"] == "dynamic":
        for index, (path, digest) in enumerate(libraries.items()):
            stem = f"library-{index}-dynsym"
            base.run_saved(["readelf", "--use-dynamic", "--symbols", "-W", str(path)], out, stem, env)
            command += ["--elf", f"{path}={path}", "--expected-sha256", f"{path}={digest}",
                        "--dynamic-symbols", f"{path}={out / (stem + '.txt')}"]
    base.run_saved(command, out, "symbolize", env)
    require((out / "symbolized.json").is_file(), "symbolizer did not produce results")


def sample(out, item, plan, subject, socket, paths, client, loader, libraries, env, perf_path, info):
    out.mkdir()
    original = paths[item["subject"]]
    base.check_hash(original, plan["subjects"][item["subject"]]["sha256"])
    shutil.copyfile(original, subject)
    subject.chmod(0o755)
    base.check_hash(subject, plan["subjects"][item["subject"]]["sha256"])
    socket.unlink(missing_ok=True)
    dynamic = plan["subjects"][item["subject"]]["kind"] == "dynamic"
    expected = {**libraries, subject: plan["subjects"][item["subject"]]["sha256"]}
    library_path = f"{plan['rootfs']['path']}/lib:{plan['rootfs']['path']}/usr/lib"
    daemon = perf = caller = None
    fds = []
    error = None
    meta = {"run": item, "mode": plan["mode"], "status": "starting", "subject_sha256": expected[subject],
            "normalized_subject_path": str(subject), "normalized_socket_path": str(socket), "program_argv0": "/sbin/ubusd",
            "measurement_control": "client enable/ACK after warmup; disable/ACK after timed loop; no timer-based bracket",
            "caller_identity": "planned ELF hash, direct Popen PID, live exe/map/inode/CPU0 snapshot after exec, final helper PID/affinity assertions",
            "scope": "Oracle-only attribution; does not validate router effect size"}
    save(out / "meta.json", meta)
    with (out / "daemon.log").open("wb") as daemon_log, (out / "perf.stdout").open("wb") as perf_stdout, \
            (out / "perf.stderr").open("wb") as perf_stderr, (out / "client.stderr").open("wb") as client_stderr, \
            (out / "client.json").open("wb") as client_json:
        try:
            command = ([str(loader), "--library-path", library_path, "--argv0", "/sbin/ubusd", str(subject), "-s", str(socket)] if dynamic else ["/sbin/ubusd", "-s", str(socket)])
            meta["daemon_command"] = command
            daemon = subprocess.Popen(command, executable=str(loader if dynamic else subject), env=env,
                                      stdout=daemon_log, stderr=subprocess.STDOUT, preexec_fn=base.pin_subject)
            meta["daemon_pid"] = daemon.pid
            deadline = time.monotonic() + 5
            while not socket.is_socket():
                require(daemon.poll() is None and time.monotonic() < deadline, "daemon socket readiness failed")
                time.sleep(.01)
            start = pid_start(daemon.pid)
            before = base.snapshot(daemon, out, "before", expected, subject, loader, dynamic)
            ctl_read, ctl_write = os.pipe(); ack_read, ack_write = os.pipe()
            fds.extend((ctl_read, ctl_write, ack_read, ack_write))
            control = ["-D", "-1", "--control", f"fd:{ctl_read},{ack_write}", "-p", str(daemon.pid)]
            if plan["mode"] == "profile":
                command = [str(perf_path), "record", *control, "-e", "cpu-clock", "-F", str(plan["profile"]["frequency_hz"]), "--strict-freq", "-m", "8M", "-T", "-P", "--no-buildid-cache", "-o", str(out / "perf.data")]
            else:
                command = [str(perf_path), "stat", *control, "-x", ";", "-o", str(out / "perf.csv")]
                for event in plan["stat"]["events"]:
                    command += ["-e", event]
            meta["perf_command"] = command
            perf = subprocess.Popen(command, pass_fds=(ctl_read, ack_write), stdout=perf_stdout, stderr=perf_stderr, env=env)
            for fd in (ctl_read, ack_write):
                os.close(fd); fds.remove(fd)
            client_args = [str(client), "register-cycle", str(socket), str(item["methods"]), str(item["name_bytes"]), str(item["n"]), str(item["warmup"]), str(daemon.pid)]
            command = ([str(loader), "--library-path", library_path, *client_args] if plan["client"]["kind"] == "dynamic" else client_args)
            meta["client_command"] = command
            client_env = dict(env, OWRT_PERF_CTL_FD=str(ctl_write), OWRT_PERF_ACK_FD=str(ack_read))
            caller = subprocess.Popen(command, env=client_env, pass_fds=(ctl_write, ack_read), stdout=client_json, stderr=client_stderr)
            meta["client_pid"] = caller.pid
            save(out / "meta.json", meta)
            client_identity(caller, out, client, loader, libraries, plan["client"])
            require(caller.wait(timeout=plan["timeout_seconds"]) == 0, "caller failed; see client.stderr")
            require(perf.poll() is None, "perf exited before controlled shutdown")
            base.stop(perf, signal.SIGINT)
            require(perf.returncode in (0, -signal.SIGINT), f"perf exit {perf.returncode}")
            after = base.snapshot(daemon, out, "after", expected, subject, loader, dynamic)
            require(before["mapped_sha256"] == after["mapped_sha256"] and pid_start(daemon.pid) == start, "daemon mapping/identity changed")
            require((out / "cmdline-before.bin").read_bytes() == (out / "cmdline-after.bin").read_bytes(), "daemon argv changed")
            if not dynamic:
                require((out / "cmdline-before.bin").read_bytes() == b"/sbin/ubusd\0-s\0" + os.fsencode(socket) + b"\0", "static subject argv0 mismatch")
            base.check_hash(client, plan["client"]["sha256"])
            base.check_hash(perf_path, plan["perf"]["sha256"])
            client_json.flush()
            data = json.loads((out / "client.json").read_text())
            meta["elapsed_ns"] = validate_client(data, item, daemon.pid, caller.pid)
            if plan["mode"] == "stat":
                meta["counters"] = stat_counts(out / "perf.csv", plan["stat"]["counter_names"])
            meta["status"] = "collected"
        except BaseException as exc:
            error = exc
            meta.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        finally:
            cleanup_errors = []
            for process, sig in ((caller, signal.SIGTERM), (perf, signal.SIGINT), (daemon, signal.SIGTERM)):
                try:
                    base.stop(process, sig)
                except Exception as exc:
                    cleanup_errors.append(str(exc))
            for fd in fds:
                os.close(fd)
            meta["returncodes"] = {name: proc.returncode if proc else None for name, proc in (("client", caller), ("perf", perf), ("daemon", daemon))}
            if cleanup_errors:
                meta["cleanup_errors"] = cleanup_errors
                error = error or RuntimeError("child cleanup failed")
            save(out / "meta.json", meta)
    if plan["mode"] == "profile" and (out / "perf.data").is_file():
        try:
            perf_reports(out, plan, item, subject, original, loader, libraries, env, perf_path, info)
        except Exception as exc:
            meta["report_error"] = f"{type(exc).__name__}: {exc}"
            error = error or exc
    elif plan["mode"] == "profile":
        error = error or RuntimeError("perf produced no recording")
    meta["status"] = "failed" if error else "complete"
    save(out / "meta.json", meta)
    if error:
        (out / "FAILED").write_text(f"{type(error).__name__}: {error}\n")
        raise error
    (out / "COMPLETE").touch()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--template", choices=("profile", "stat"))
    parser.add_argument("--oracle-host-only", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.template:
        require(not args.plan and not args.out and not args.oracle_host_only, "template is separate from execution")
        print(json.dumps(template(args.template), indent=2)); return
    require(args.oracle_host_only and args.plan and args.out, "execution requires --oracle-host-only --plan --out")
    require(platform.system() == "Linux" and platform.machine() == "aarch64" and os.geteuid() == 0, "requires root on aarch64 Oracle Linux")
    require(not Path("/etc/openwrt_release").exists() and "openwrt" not in Path("/etc/os-release").read_text().lower(), "never run on router/OpenWrt")
    require({0, 1}.issubset(os.sched_getaffinity(0)), "CPUs 0/1 unavailable")
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    plan = load_plan(args.plan)
    rootfs = base.checked_path(plan["rootfs"]["path"])
    require(rootfs != Path("/"), "rootfs must be extracted reference")
    require(str(rootfs) == plan["rootfs"]["path"], "rootfs path must be canonical")
    libraries = {}
    for name, digest in plan["rootfs"]["libraries"].items():
        require(name.startswith("/") and ".." not in Path(name).parts, "invalid library path")
        path = (rootfs / name.lstrip("/")).resolve(strict=True)
        require(path.is_relative_to(rootfs), "library escapes rootfs")
        base.check_hash(path, digest); libraries[path] = digest
    loader = (rootfs / "lib/libc.so").resolve(strict=True)
    require(loader in libraries, "exact musl loader not frozen")
    client, perf_path = (base.checked_path(plan[name]["path"]) for name in ("client", "perf"))
    base.check_hash(client, plan["client"]["sha256"]); base.check_hash(perf_path, plan["perf"]["sha256"])
    paths = {}
    symbols = {}
    for label, spec in plan["subjects"].items():
        require(spec["kind"] == ("dynamic" if label == "c" else "static"), "subject kind")
        paths[label] = base.checked_path(spec["path"])
        base.check_hash(paths[label], spec["sha256"])
        if plan["mode"] == "profile":
            symbols[label] = verify_symbols(paths[label], spec["symbols"])
    out = args.out.absolute()
    out.mkdir(parents=True, exist_ok=False)
    (out / "plan.json").write_bytes(args.plan.read_bytes())
    save(out / "symbol-identities.json", symbols)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("LD_", "OWRT_PERF_"))}
    env.update(LC_ALL="C", PERF_CONFIG="/dev/null", PERF_CONFIG_NOSYSTEM="1", DEBUGINFOD_URLS="")
    save(out / "host.json", {"machine": platform.machine(), "kernel": platform.release(), "perf_sha256": sha(perf_path),
                             "runner_sha256": sha(__file__), "plan_sha256": sha(args.plan), "scope": "Oracle diagnostic only"})
    launch = Path(plan["launch_directory"])
    launch.mkdir(mode=0o700, exist_ok=False)
    try:
        base.run_saved([str(perf_path), "version"], out, "perf-version", env)
        info = {label: base.elf_info(path, out, f"elf-{label}", env) for label, path in paths.items()}
        for label in LABELS:
            require(info[label]["interpreter_present"] == (plan["subjects"][label]["kind"] == "dynamic"), "ELF kind mismatch")
        client_info = base.elf_info(client, out, "elf-client", env)
        require(client_info["interpreter_present"] == (plan["client"]["kind"] == "dynamic"), "client ELF kind mismatch")
        for i, item in enumerate(plan["runs"], 1):
            print(f"START {i}/{len(plan['runs'])} {item['subject']} methods={item['methods']} {plan['mode']}", flush=True)
            sample(out / f"{i:03d}-{item['subject']}-{item['methods']}", item, plan, launch / "ubusd", launch / "ubus.sock",
                   paths, client, loader, libraries, env, perf_path, info[item["subject"]])
            print(f"VERIFIED {i}", flush=True)
    except BaseException as exc:
        (out / "FAILED").write_text(f"{type(exc).__name__}: {exc}\n")
        raise
    finally:
        shutil.rmtree(launch)
    (out / "COMPLETE").touch()


if __name__ == "__main__":
    main()
