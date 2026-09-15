#!/usr/bin/env python3
"""Three-side HTTP parking diagnostic through the existing Wi-Fi/namespace gates.

Run from the management Mac; only owned namespaces execute on the router.
--plan validates local inputs and writes a reviewable harness without SSH.
The frozen performance client is unchanged; http-diagnostics is a separate ELF.
"""
import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
import statistics
import struct
import subprocess
import sys
import tarfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import probe  # noqa: E402

GAPS = (0, 20, 40, 60, 80)
ORDERS = (("stock", "r89", "candidate"), ("candidate", "r89", "stock"),
          ("r89", "stock", "candidate"), ("candidate", "stock", "r89"))
RESOURCES = ("VmRSS", "RssAnon", "RssFile", "VmHWM", "fds", "Threads")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def check_elf(path):
    with path.open("rb") as stream:
        head = stream.read(64)
        require(len(head) == 64 and head[:6] == b"\x7fELF\x02\x01"
                and struct.unpack_from("<H", head, 18)[0] == 183,
                f"expected little-endian AArch64 ELF: {path}")
        offset = struct.unpack_from("<Q", head, 32)[0]
        size, count = struct.unpack_from("<HH", head, 54)
        require(size >= 56 and count < 1024, "invalid ELF program table")
        for i in range(count):
            stream.seek(offset + i * size)
            item = stream.read(size)
            require(len(item) == size and struct.unpack_from("<I", item)[0] != 3,
                    "candidate/client must be static ELF without PT_INTERP")


def schedule(rounds, count, hot_count):
    runs = []
    for repeat in range(rounds):
        gaps = GAPS[repeat % len(GAPS):] + GAPS[:repeat % len(GAPS)]
        if repeat % 2:
            gaps = gaps[::-1]
        for gap in gaps:
            for side in ORDERS[repeat % len(ORDERS)]:
                runs.append({"name": f"{len(runs)+1:03d}-r{repeat+1}-{side}-gap{gap}",
                             "repeat": repeat + 1, "side": side, "gap_ms": gap,
                             "iterations": hot_count if gap == 0 else count})
    return runs


def replace_once(text, old, new):
    require(text.count(old) == 1, "isolated.sh interface changed; review the harness insertion")
    return text.replace(old, new, 1)


def make_harness(base, fixture, budget):
    """Keep the existing namespace setup; annotate only its paced workload."""
    text = base
    old = '    image=$1; bundle=$2; component=$3; impl=$4; out=$5; n=$6; work=$7; script=$8'
    text = replace_once(text, old, old + f'''
    # ns-exec runs this command as namespace PID 2. Capture its PID before
    # exec chroot; an exit (normal or SIGKILL) makes namespace PID 1 exit and
    # the kernel destroys every remaining child, including this watchdog.
    # No host PID or production process is a possible target.
    gap_owner=$$
    [ "$gap_owner" -gt 1 ] || exit 125
    (
        sleep {budget}
        printf 'HTTP gap namespace deadline expired\\n' >&2
        kill -KILL "$gap_owner"
    ) &''')
    old = 'dd if=/dev/zero of=/tmp/www/static.dat bs=16384 count=1 2>/dev/null'
    fixture_command = ('cp /www/luci-static/bootstrap/cascade.css /tmp/www/static.dat'
                       if fixture == "image-css" else
                       f'dd if=/dev/zero of=/tmp/www/static.dat bs={fixture} count=1 2>/dev/null')
    # Retain the .css suffix because MIME lookup is part of the static path.
    fixture_command += '\n            sha256sum /tmp/www/static.dat > "$out/fixture-sha256.txt"\n'
    fixture_command += '            wc -c < /tmp/www/static.dat > "$out/fixture-bytes.txt"'
    text = replace_once(text, old, fixture_command)
    old = '                    /tmp/bin/http-diagnostics http-paced 127.0.0.1:18080 /static.dat /tmp/www/static.dat "$n" "${OWRT_HTTPD_DIAG_CLIENTS:-4}" "${OWRT_HTTPD_DIAG_GAP_MS:-0}" "$subject" > "$out/paced.json"'
    new = '''                    printf '{"httpd":%s,"rpcd":%s,"ubusd":%s}\\n' "$subject" "$rpc" "$bus" > "$out/roles.json"
                    sha256sum /proc/"$rpc"/exe /proc/"$bus"/exe > "$out/dependencies-sha256.txt"
                    "$bench" snapshot "$monitors" > "$out/outer-before.json"
''' + old + '''
                    "$bench" snapshot "$monitors" > "$out/outer-after.json"
                    sleep 1
                    "$bench" snapshot "$monitors" > "$out/idle-1s.json"
                    sleep 1
                    "$bench" snapshot "$monitors" > "$out/idle-2s.json"'''
    text = replace_once(text, old, new)
    if fixture == "image-css":
        text = text.replace("/tmp/www/static.dat", "/tmp/www/static.css")
        text = text.replace("127.0.0.1:18080 /static.dat ", "127.0.0.1:18080 /static.css ")
    return text


def proc_cpu(before, after, hz):
    require(before["pid"] == after["pid"] and before["start_ticks"] == after["start_ticks"],
            "process identity changed during sample")
    own = after["cpu_ticks"] - before["cpu_ticks"]
    children = after["child_cpu_ticks"] - before["child_cpu_ticks"]
    require(own >= 0 and children >= 0 and hz > 0, "invalid CPU counters")
    return {"own_ticks": own, "waited_child_ticks": children,
            "own_s": own / hz, "waited_child_s": children / hz,
            "total_s": (own + children) / hz}


def derive(raw, run, settings):
    require((raw / "COMPLETE").is_file(), "incomplete namespace sample")
    for name in ("binary-sha256.txt", "subject-sha256.txt"):
        require((raw / name).read_text().split()[0] == settings["subjects"][run["side"]],
                "subject checksum mismatch")
    for file, key in (("harness-sha256.txt", "harness_sha256"),
                      ("diagnostic-sha256.txt", "diagnostic_sha256")):
        require((raw / file).read_text().split()[0] == settings[key], "harness/client mismatch")
    require((raw / "boot-id.txt").read_text().strip() == settings["boot_id"], "boot changed")
    meta, data, roles = read(raw / "meta.json"), read(raw / "paced.json"), read(raw / "roles.json")
    n, clients = run["iterations"], settings["clients"]
    require(meta["component"] == "httpd" and meta["dependencies"] == "original OpenWrt"
            and meta["subject_pid"] == roles["httpd"] and meta["iterations"] == n,
            "invalid namespace metadata")
    require(data["diagnostic_only"] is True and data["errors"] == 0
            and data["successful"] == n == len(data["latency_ns"])
            and data["clients"] == clients and data["gap_ms"] == run["gap_ms"],
            "requests failed or workload changed")
    dependencies = {line.split()[1]: line.split()[0]
                    for line in (raw / "dependencies-sha256.txt").read_text().splitlines()}
    for role in ("rpcd", "ubusd"):
        require(dependencies[f'/proc/{roles[role]}/exe'] == settings["dependencies"][role],
                "dependency checksum mismatch")
    bench = {Path(line.split()[1]).name: line.split()[0]
             for line in (raw / "benchmark-sha256.txt").read_text().splitlines()}
    require(bench == settings["tools"], "frozen tool checksum mismatch")
    require((raw / "fixture-sha256.txt").read_text().split()[0] == settings["fixture_sha256"]
            and int((raw / "fixture-bytes.txt").read_text()) == settings["fixture_bytes"],
            "fixture changed")
    latency = sorted(data["latency_ns"])
    require(all(isinstance(v, int) and v > 0 for v in latency), "invalid latency samples")
    hz = data["ticks_per_second"]
    raw_snapshots = {phase: read(raw / (file + ".json"))
                     for phase, file in (("before", "outer-before"), ("after", "outer-after"),
                                         ("idle_1s", "idle-1s"), ("idle_2s", "idle-2s"))}
    require(all(s["clock_ticks_per_second"] == hz for s in raw_snapshots.values()),
            "snapshot/diagnostic clock frequency mismatch")
    snapshots = {phase: {p["pid"]: p for p in s["processes"]} for phase, s in raw_snapshots.items()}
    before, after = raw_snapshots["before"], raw_snapshots["after"]
    minimum_ns = n // clients * run["gap_ms"] * 1_000_000
    require(data["wall_ns"] >= minimum_ns, "paced wall time is shorter than configured sleeps")
    # /proc/uptime is printed to centiseconds; allow one centisecond of
    # endpoint quantization when enclosing CLOCK_MONOTONIC's precise interval.
    require(after["uptime_s"] - before["uptime_s"] + .010001 >= data["wall_ns"] / 1e9,
            "outer wall interval does not enclose diagnostic workload")
    outer_cpu, resources = {}, {}
    for role, pid in roles.items():
        outer_cpu[role] = proc_cpu(snapshots["before"][pid], snapshots["after"][pid], hz)
        resources[role] = {}
        for phase, samples in snapshots.items():
            proc_cpu(snapshots["before"][pid], samples[pid], hz)
            resources[role][phase] = {key: samples[pid][key] for key in RESOURCES}
    require(data["before"]["pid"] == data["after"]["pid"] == roles["httpd"], "inner PID mismatch")
    require(data["before"]["start_ticks"] == snapshots["before"][roles["httpd"]]["start_ticks"],
            "inner/outer process identity differs")
    for counter in ("cpu_ticks", "child_cpu_ticks"):
        require(snapshots["before"][roles["httpd"]][counter] <= data["before"][counter]
                <= data["after"][counter] <= snapshots["after"][roles["httpd"]][counter],
                "inner CPU counters are not enclosed by outer snapshots")
    inner = proc_cpu(data["before"], data["after"], hz)
    total = sum(item["total_s"] for item in outer_cpu.values())
    return {**run, "successful": n, "errors": 0, "warmup_successful": clients,
            "latency_us": {"mean": statistics.mean(latency) / 1000,
                **{label: latency[math.ceil(n * q)-1] / 1000
                   for label, q in (("p50", .5), ("p95", .95), ("p99", .99))}},
            "wall_s": data["wall_ns"] / 1e9, "ticks_per_second": hz,
            "subject_measured_cpu": {**inner, "us_per_request": inner["total_s"] * 1e6 / n},
            "outer_including_warmup": {"successful": n + clients, "roles": outer_cpu,
                "all_daemons_cpu_s": total, "us_per_request": total * 1e6 / (n + clients),
                "dependencies_cpu_s": sum(outer_cpu[k]["total_s"] for k in ("rpcd", "ubusd")),
                "wall_s": after["uptime_s"] - before["uptime_s"]},
            "resources": resources,
            "sampled_thread_births_lower_bound": data["thread_births_observed_lower_bound"],
            "observer_interval_ms": data["observer_interval_ms"]}


def verify_download(raw, checksums):
    seen = set()
    for line in checksums.decode().splitlines():
        digest, name = line.split(None, 1)
        path = (raw / name).resolve()
        require(path.is_relative_to(raw.resolve()) and path.is_file() and sha(path) == digest,
                "download checksum mismatch")
        seen.add(path)
    require(seen == {p.resolve() for p in raw.rglob("*") if p.is_file()}, "archive/hash file set mismatch")


def summary(rows, rounds):
    result = []
    for gap in GAPS:
        for side in ("stock", "r89", "candidate"):
            group = [r for r in rows if r["side"] == side and r["gap_ms"] == gap]
            require(len(group) == rounds, "missing repeated sample")
            metrics = {"subject_cpu_us_per_request": [r["subject_measured_cpu"]["us_per_request"] for r in group],
                       "all_daemons_outer_cpu_us_per_request": [r["outer_including_warmup"]["us_per_request"] for r in group]}
            metrics.update({"latency_" + key + "_us": [r["latency_us"][key] for r in group]
                            for key in ("mean", "p50", "p95", "p99")})
            result.append({"side": side, "gap_ms": gap, "rounds": rounds,
                           "successful": sum(r["successful"] for r in group),
                           "per_run_statistics": {key: {"median": statistics.median(values),
                               "min": min(values), "max": max(values)} for key, values in metrics.items()}})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("candidate", type=Path)
    p.add_argument("diagnostic", type=Path, help="static AArch64 http-diagnostics with existing http-paced mode")
    p.add_argument("output", type=Path)
    p.add_argument("--baseline-manifest", type=Path, required=True, help="reviewed local formal R89 manifest")
    p.add_argument("--baseline-bundle", default="/root/r89-before-r90")
    p.add_argument("--recovery-gate", type=Path, required=True)
    p.add_argument("--candidate-build-record", type=Path, help="optional release recipe/provenance evidence")
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", required=True)
    p.add_argument("--access", choices=("wifi", "wired"), default="wifi")
    p.add_argument("--rounds", type=int, default=4)
    p.add_argument("--iterations", type=int, default=1000, help="total successful requests per paced sample")
    p.add_argument("--hot-iterations", type=int, default=10000, help="total successful requests at gap 0")
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--fixture", choices=("512", "16384", "image-css"), default="16384")
    p.add_argument("--cpus", help="optional same numeric taskset list for each namespace")
    p.add_argument("--plan", action="store_true", help="local preparation only; performs no SSH or device action")
    a = p.parse_args()
    require(4 <= a.rounds <= 24 and 1 <= a.clients <= 64, "require 4..24 rounds and 1..64 clients")
    require(all(n >= a.clients and n % a.clients == 0 for n in (a.iterations, a.hot_iterations)),
            "each request count must be a positive multiple of clients")
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", a.baseline_bundle)
            and (not a.cpus or re.fullmatch(r"[0-9,-]+", a.cpus)), "invalid bundle path/CPU list")
    check_elf(a.candidate)
    check_elf(a.diagnostic)
    gate, baseline = read(a.recovery_gate), read(a.baseline_manifest)
    require(gate["offline_backup_verified"] and gate["configuration_matches_backup"]
            and gate["automatic_rollback_seconds"] > 0 and gate["boot_id"], "recovery gate incomplete")
    require(gate["client_interface"] == a.interface and gate["management"] == a.access,
            "recovery gate management path differs")
    backup_config = a.recovery_gate.parent / "config-before.sha256"
    require(backup_config.is_file(), "recovery gate must retain config-before.sha256")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    out = a.output.resolve()
    runs = schedule(a.rounds, a.iterations, a.hot_iterations)
    budget = math.ceil(max(a.iterations, a.hot_iterations) / a.clients * .08) + 330
    script = Path(__file__).with_name("isolated.sh")
    harness = out / "isolated-gap.sh"
    harness.write_text(make_harness(script.read_text(), a.fixture, budget))
    settings = {"schema": 1, "environment": "physical AX3000T; private namespace loopback; production stays active",
        "diagnostic_only": True, "management_access": a.access, "interface": a.interface,
        "clients": a.clients, "rounds": a.rounds, "fixture": a.fixture, "cpu_affinity": a.cpus,
        "namespace_workload_timeout_s": budget, "baseline_bundle": a.baseline_bundle,
        "subjects": {"r89": baseline["components"]["httpd"]["rust"]["sha256"], "candidate": sha(a.candidate)},
        "baseline_manifest_sha256": sha(a.baseline_manifest), "recovery_gate_sha256": sha(a.recovery_gate),
        "diagnostic_sha256": sha(a.diagnostic), "harness_sha256": sha(harness),
        "base_harness_sha256": sha(script), "driver_sha256": sha(Path(__file__)),
        "candidate_build_record_sha256": sha(a.candidate_build_record) if a.candidate_build_record else None,
        "minimum_pacing_seconds": sum(r["iterations"] / a.clients * r["gap_ms"] / 1000 for r in runs),
        "limitations": ["Private-loopback workload; Wi-Fi is management only, not the workload path.",
            "Client differs from frozen performance client; identical 2ms thread observation method may impose different overhead as thread counts vary.",
            "Daemon totals exclude load-generator/observer CPU; no claim of whole-system CPU reduction.",
            "Inner subject CPU excludes warmup; common outer daemon CPU includes one warmup per client. Do not add those intervals.",
            "CPU ticks quantize low-count runs; repeat medians are not pooled percentiles.",
            "Resources are snapshots and VmHWM, not continuously sampled peaks; RSS is not PSS/USS.",
            "Exact-image sleep supports integer seconds only; idle snapshots are at about 1s/2s, not the 200ms memory gate.",
            "Same publication recipe must be established from build evidence; binary hashes alone do not prove recipe equality."]}
    save(out / "settings.json", settings)
    save(out / "order.json", runs)
    (out / "recovery-gate.json").write_bytes(a.recovery_gate.read_bytes())
    (out / "baseline-manifest.json").write_bytes(a.baseline_manifest.read_bytes())
    if a.candidate_build_record:
        (out / "candidate-build-record").write_bytes(a.candidate_build_record.read_bytes())
    subprocess.run(["sh", "-n", str(harness)], check=True)
    if a.plan:
        (out / "PLAN_ONLY").touch()
        print(json.dumps({"plan_only": True, "samples": len(runs),
                          "minimum_pacing_seconds": settings["minimum_pacing_seconds"],
                          "harness": str(harness)}))
        return
    (out / "STARTED").touch()
    ssh_args = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "-o",
                "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", a.host]

    def ssh(command, timeout=40):
        return subprocess.check_output(ssh_args + [command], timeout=timeout)

    def digest_remote(path):
        return ssh("sha256sum " + shlex.quote(path)).decode().split()[0]

    before = probe(host=a.host, mode="rust", interface=a.interface)
    save(out / "health-before.json", before)
    require(before["boot_id"] == gate["boot_id"], "boot differs from recovery gate")
    config = ssh("sha256sum /etc/config/*")
    require(config == backup_config.read_bytes(), "configuration differs from verified offline backup")
    identity = ssh("/bin/sh /root/r84/stack-switch.sh verify rust")
    (out / "host-running-hashes.txt").write_bytes(identity)
    (out / "config-before.sha256").write_bytes(config)
    ssh("test ! -e /etc/r84-pending && test ! -e /etc/r84-reverting && test ! -e /etc/p6-pending && test ! -e /etc/p6-reverting")
    manifest_bytes = ssh("cat /root/r84/manifest.json")
    manifest = json.loads(manifest_bytes)
    require(json.loads(ssh("cat " + shlex.quote(a.baseline_bundle + "/manifest.json"))) == baseline,
            "remote baseline differs from reviewed formal R89 manifest")
    tools = {name: manifest["tools"][name]["sha256"] for name in ("ns-exec", "owrt-benchmark")}
    require(all(baseline["tools"][name]["sha256"] == digest for name, digest in tools.items()),
            "formal baseline/frozen harness tools differ")
    settings.update(boot_id=before["boot_id"], tools=tools,
        host_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        dependencies={k: manifest["components"][k]["original"]["sha256"] for k in ("rpcd", "ubusd")})
    settings["subjects"]["stock"] = manifest["components"]["httpd"]["original"]["sha256"]
    require(digest_remote("/rom/usr/sbin/uhttpd") == settings["subjects"]["stock"], "exact C identity mismatch")
    require(digest_remote(a.baseline_bundle + "/bins/httpd-rs") == settings["subjects"]["r89"], "R89 ELF mismatch")
    if a.fixture == "image-css":
        settings["fixture_sha256"] = digest_remote("/rom/www/luci-static/bootstrap/cascade.css")
        settings["fixture_bytes"] = int(ssh("wc -c < /rom/www/luci-static/bootstrap/cascade.css"))
    else:
        settings["fixture_bytes"] = int(a.fixture)
        settings["fixture_sha256"] = hashlib.sha256(bytes(int(a.fixture))).hexdigest()
    save(out / "settings.json", settings)
    remote = "/tmp/r93-http-gap-" + uuid.uuid4().hex[:12]
    save(out / "collector.json", {"remote": remote})
    ssh("mkdir " + remote + " && mkdir " + remote + "/bundle")
    bundle = remote + "/bundle"
    for name, digest in tools.items():
        require(digest_remote("/root/r84/bins/" + name) == digest, "host frozen tool mismatch")
        ssh("cp /root/r84/bins/" + name + " " + bundle + "/" + name)
        require(digest_remote(bundle + "/" + name) == digest, "copied tool mismatch")
    for local, name, digest in ((a.candidate, "candidate-httpd-rs", settings["subjects"]["candidate"]),
                                (a.diagnostic, "http-diagnostics", settings["diagnostic_sha256"]),
                                (harness, "isolated-gap.sh", settings["harness_sha256"])):
        target = bundle + "/" + name
        subprocess.run(["scp", "-O", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
                        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
                        str(local.resolve()), a.host + ":" + target], check=True, timeout=120)
        require(digest_remote(target) == digest, "upload checksum mismatch")
        ssh("chmod 700 " + target)
    monitors = ",".join(line.split()[1] for line in identity.decode().splitlines() if line.split()[1] != "-")
    host_snapshot = "/root/r84/bins/owrt-benchmark snapshot " + monitors
    rows = []
    try:
        for run in runs:
            folder = out / run["name"]
            folder.mkdir(mode=0o700)
            # One shared bundle keeps tools/client identical; only the owned subject changes.
            if run["side"] != "stock":
                source = (a.baseline_bundle + "/bins/httpd-rs" if run["side"] == "r89"
                          else bundle + "/candidate-httpd-rs")
                ssh("cp " + shlex.quote(source) + " " + bundle + "/httpd-rs")
                require(digest_remote(bundle + "/httpd-rs") == settings["subjects"][run["side"]], "selected ELF mismatch")
            run_out = remote + "/" + run["name"]
            (folder / "host-before.json").write_bytes(ssh(host_snapshot))
            command = (f"OWRT_HTTPD_DIAG=paced OWRT_HTTPD_DIAG_CLIENTS={a.clients} "
                       f"OWRT_HTTPD_DIAG_GAP_MS={run['gap_ms']} ")
            if a.cpus:
                command += "taskset -c " + shlex.quote(a.cpus) + " "
            command += " ".join(map(shlex.quote, ("/bin/sh", bundle + "/isolated-gap.sh", "/rom", bundle,
                                   "httpd", "c" if run["side"] == "stock" else "rs", run_out, str(run["iterations"]))))
            (folder / "command.txt").write_text(command + "\n")
            print(json.dumps({"event": "started", **run,
                              "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
            with (folder / "run.log").open("xb") as log:
                try:
                    result = subprocess.run(ssh_args + [command], stdout=log, stderr=log, timeout=budget + 120)
                except subprocess.TimeoutExpired:
                    save(folder / "TIMEOUT.json", {"ssh_timeout_s": budget + 120,
                        "namespace_workload_timeout_s": budget, "remote_output": run_out,
                        "complete": False})
                    raise
            (folder / "host-after.json").write_bytes(ssh(host_snapshot))
            archive = folder / "raw.tar.gz"
            with archive.open("xb") as stream:
                subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(run_out) + " ."],
                               stdout=stream, check=True, timeout=120)
            checksums = ssh("cd " + shlex.quote(run_out) + " && find . -type f -exec sha256sum '{}' ';'")
            (folder / "raw.sha256").write_bytes(checksums)
            raw = folder / "raw"
            raw.mkdir(mode=0o700)
            with tarfile.open(archive) as tar:
                tar.extractall(raw, filter="data")
            verify_download(raw, checksums)
            # Only checksummed owned raw output is removed; failed sample remains local.
            ssh("rm -rf -- " + shlex.quote(run_out))
            result.check_returncode()
            row = derive(raw, run, settings)
            row["archive_sha256"] = sha(archive)
            rows.append(row)
            save(out / "results.json", {"schema": 1, "complete": False, "settings": settings, "rows": rows})
            (folder / "COMPLETE").touch()
            print(json.dumps({"event": "complete", "name": run["name"]}), flush=True)
            if len(rows) % 15 == 0:
                health = probe(host=a.host, mode="rust", interface=a.interface)
                save(out / f"health-round-{run['repeat']}.json", health)
                require(health["boot_id"] == before["boot_id"], "router rebooted")
                require(ssh("sha256sum /etc/config/*") == config, "production config changed")
                require(ssh("/bin/sh /root/r84/stack-switch.sh verify rust") == identity, "production identities changed")
    finally:
        # Failure is never labelled complete. Leave exact owned evidence directory
        # recorded for recovery; namespace workload timeout independently kills descendants.
        try:
            after = probe(host=a.host, mode="rust", interface=a.interface)
            save(out / "health-after.json", after)
            require(after["boot_id"] == before["boot_id"], "router rebooted")
            require(ssh("sha256sum /etc/config/*") == config, "production config changed")
            require(ssh("/bin/sh /root/r84/stack-switch.sh verify rust") == identity, "production identities changed")
        except Exception as error:
            save(out / "post-health-error.json", {"error": str(error)})
            raise
    require(len(rows) == len(runs), "incomplete collection")
    ssh("rm -rf -- " + remote)
    save(out / "results.json", {"schema": 1, "complete": True, "settings": settings,
                               "summary": summary(rows, a.rounds), "rows": rows})
    (out / "COMPLETE").touch()
    print(json.dumps({"complete": True, "samples": len(rows)}), flush=True)


if __name__ == "__main__":
    main()
