#!/usr/bin/env python3
"""Exact-C checks of capability preflight, identities, signals and PID lifetime.

Run through run_isolated.sh on the build host. Fixtures and raw observations
must live under private/. This does not access a router.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

CASES = ("foreground-term", "broadcast", "broadcast-no-admin",
         "conditional-broadcast-no-admin", "foreground-int", "debug-int", "group-failure")
IDENTITY_KEYS = ("Uid", "Gid", "Groups", "CapEff", "CapPrm")
QUERY = bytes.fromhex("123401000001000000000000086964656e7469747904746573740000010001")
BASE_CONFIG = ("no-resolv\nno-hosts\nport=15353\nlisten-address=127.0.0.1\n"
               "host-record=identity.test,192.0.2.7\nuser=dnsmasq\ngroup=dnsmasq\n")
SERVICE_IDENTITY = {"Uid": ["453"] * 4, "Gid": ["453"] * 4, "Groups": [],
                    "CapEff": ["0000000000000000"], "CapPrm": ["0000000000000000"]}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def binary_identity(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def task_identities(pid, out):
    identities = []
    for task in sorted(Path(f"/proc/{pid}/task").iterdir()):
        text = (task / "status").read_text()
        (out / f"task-{task.name}.status").write_text(text)
        fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
        identities.append({key: fields[key].split() for key in IDENTITY_KEYS})
    return identities


def prepare_isolated(out):
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "startup-identity", "/etc"], check=True)
    Path("/etc/passwd").write_text("root:x:0:0:root:/:/bin/false\ndnsmasq:x:453:453:dnsmasq:/:/bin/false\n")
    Path("/etc/group").write_text("root:x:0:\ndnsmasq:x:453:\n")
    Path("/etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files\n")


def wait_ready(process, out, timeout=4):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.1)
        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            client.sendto(QUERY, ("127.0.0.1", 15353))
            try:
                reply = client.recv(4096)
                (out / "reply.hex").write_text(reply.hex() + "\n")
                if reply[:2] == QUERY[:2] and reply[-4:] == bytes([192, 0, 2, 7]):
                    return reply.hex()
            except socket.timeout:
                pass
    return None


def pid_snapshot(path):
    if not path.exists():
        return None
    metadata = path.stat()
    return {"text": path.read_text(), "owner": [metadata.st_uid, metadata.st_gid],
            "mode": metadata.st_mode & 0o777, "symlink": path.is_symlink()}


def normalize_pid(snapshot, process_pid):
    if snapshot is None:
        return None
    result = dict(snapshot)
    if result["text"] == f"{process_pid}\n":
        result["text"] = "own-process"
    elif result["text"] != "sentinel\n":
        raise ValueError("PID file is neither the exact child PID nor the seeded sentinel")
    return result


def run(binary, case, out):
    out.mkdir()
    out.chmod(0o777)
    pidfile = out / "daemon.pid"
    pidfile.write_text("sentinel\n")
    config = BASE_CONFIG
    if "broadcast" in case:
        config += "no-ping\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,600s\n"
        config += f"dhcp-leasefile={out / 'leases'}\n"
        config += "dhcp-broadcast=tag:needs-broadcast\n" if "conditional" in case else "dhcp-broadcast\n"
    config_path = out / "dnsmasq.conf"
    config_path.write_text(config)
    command = [str(binary), "-d" if case == "debug-int" else "-k", "-C", str(config_path), "-x", str(pidfile)]
    if "no-admin" in case:
        command = ["setpriv", "--bounding-set=-net_admin", "--"] + command
    elif case == "group-failure":
        command = ["setpriv", "--bounding-set=-setgid", "--"] + command
    result = {"command": command}
    with (out / "stdout").open("wb") as stdout, (out / "stderr").open("wb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        result["process_pid"] = process.pid
        try:
            reply = wait_ready(process, out)
            result["ready"] = reply is not None
            if reply is not None:
                result["ready_reply"] = reply
                result["threads"] = task_identities(process.pid, out)
                result["pid_at_ready"] = pid_snapshot(pidfile)
                if case.endswith("-int"):
                    process.send_signal(signal.SIGINT)
                    try:
                        result["exit_after_sigint"] = process.wait(timeout=0.7)
                    except subprocess.TimeoutExpired:
                        result["exit_after_sigint"] = None
                    result["pid_after_sigint"] = pid_snapshot(pidfile)
            elif process.poll() is None:
                result["harness_error"] = "readiness timeout"
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            result["exit"] = process.wait(timeout=4)
            result["pid_after_exit"] = pid_snapshot(pidfile)
        except Exception as error:
            result["harness_error"] = repr(error)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
                result["forced_kill"] = True
    save(out / "result.json", result)
    return result


def semantic_result(row, case, debug_identity):
    if "harness_error" in row or row.get("forced_kill"):
        raise ValueError("harness failure or forced termination")
    failed_start = case in ("conditional-broadcast-no-admin", "group-failure")
    expected_exit = 5 if failed_start or case == "debug-int" else 0
    if row["ready"] != (not failed_start) or row["exit"] != expected_exit:
        raise ValueError("unexpected startup or exit status")
    process_pid = row["process_pid"]
    if not isinstance(process_pid, int) or process_pid <= 0:
        raise ValueError("invalid child PID observation")
    result = {"ready": row["ready"], "exit": row["exit"],
              "pid_after_exit": normalize_pid(row["pid_after_exit"], process_pid)}
    wanted_pid = ("sentinel\n" if case in ("conditional-broadcast-no-admin", "debug-int")
                  else "own-process" if case == "group-failure" else None)
    if (result["pid_after_exit"] or {}).get("text") != wanted_pid:
        raise ValueError("PID lifetime differs from C termination/startup semantics")
    if not failed_start:
        wanted_identity = debug_identity if case == "debug-int" else SERVICE_IDENTITY
        if not row["threads"] or any(task != wanted_identity for task in row["threads"]):
            raise ValueError("a daemon task has incorrect credentials or capabilities")
        reply = bytes.fromhex(row["ready_reply"])
        if reply[:4] != b"\x12\x34\x85\x80" or reply[-4:] != bytes([192, 0, 2, 7]):
            raise ValueError("unexpected readiness DNS response identity/flags/address")
        result["ready_reply"] = row["ready_reply"]
        result["identity"] = wanted_identity
        result["pid_at_ready"] = normalize_pid(row["pid_at_ready"], process_pid)
        wanted_at_ready = "sentinel\n" if case == "debug-int" else "own-process"
        if (result["pid_at_ready"] or {}).get("text") != wanted_at_ready:
            raise ValueError("incorrect PID creation behavior")
        if case.endswith("-int"):
            expected_int = 5 if case == "debug-int" else None
            if row["exit_after_sigint"] != expected_int:
                raise ValueError("incorrect SIGINT behavior")
            result["exit_after_sigint"] = row["exit_after_sigint"]
            result["pid_after_sigint"] = normalize_pid(row["pid_after_sigint"], process_pid)
            if result["pid_after_sigint"] != result["pid_at_ready"]:
                raise ValueError("SIGINT changed the PID file")
    return result


def compare(result):
    errors = []
    if [row.get("case") for row in result["cases"]] != list(CASES):
        return ["case rows missing, duplicated, reordered or unexpected"]
    for row in result["cases"]:
        normalized = {}
        for side in ("c", "rust"):
            try:
                normalized[side] = semantic_result(row[side], row["case"], result["debug_identity"])
            except (KeyError, TypeError, ValueError) as error:
                errors.append(f"{row['case']} {side}: {error}")
        if len(normalized) == 2 and normalized["c"] != normalized["rust"]:
            errors.append(f"{row['case']}: C/Rust semantic observations differ")
    return errors


def check_saved_result(path, comparator):
    errors = comparator(json.loads(path.read_text()))
    print(json.dumps({"errors": errors}))
    return bool(errors)


def rejected_observation(changed, mutation, out, tool):
    path = out / f"negative-{mutation}.json"
    save(path, changed)
    process = subprocess.run([sys.executable, str(tool), "--check-result", str(path)],
                             capture_output=True, text=True)
    (out / f"negative-{mutation}.stdout").write_text(process.stdout)
    (out / f"negative-{mutation}.stderr").write_text(process.stderr)
    return {"mutation": mutation, "exit": process.returncode, "detected": process.returncode == 1}


def negative_controls(result, out):
    controls = []
    for mutation in ("missing-case", "changed-dns-flags", "wrong-worker-capability", "wrong-pid"):
        changed = copy.deepcopy(result)
        row = changed["cases"][0]["rust"]
        if mutation == "missing-case":
            changed["cases"].pop()
        elif mutation == "changed-dns-flags":
            packet = bytearray.fromhex(row["ready_reply"])
            packet[2] ^= 4
            row["ready_reply"] = packet.hex()
        elif mutation == "wrong-worker-capability":
            row["threads"][-1]["CapEff"] = ["0000000000001000"]
        else:
            row["pid_at_ready"]["text"] = f"{row['process_pid'] + 1}\n"
        controls.append(rejected_observation(changed, mutation, out, Path(__file__).resolve()))
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-result", type=Path, help="validate saved observations without starting a daemon")
    parser.add_argument("--c", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.check_result is not None:
        return check_saved_result(args.check_result, compare)
    if not all((args.c, args.rust, args.out)):
        parser.error("--c, --rust and --out are required for a live check")
    args.c, args.rust, args.out = args.c.resolve(), args.rust.resolve(), args.out.resolve()
    prepare_isolated(args.out)
    os.setgroups([0, 454])
    debug_identity = task_identities(os.getpid(), args.out)[0]
    result = {"binaries": {"c": binary_identity(args.c), "rust": binary_identity(args.rust)},
              "debug_identity": debug_identity, "cases": []}
    for case in CASES:
        out = args.out / case
        out.mkdir()
        result["cases"].append({"case": case, "c": run(args.c, case, out / "c"),
                                "rust": run(args.rust, case, out / "rust")})
    result["errors"] = compare(result)
    result["negative_controls"] = [] if result["errors"] else negative_controls(result, args.out)
    if any(not control["detected"] for control in result["negative_controls"]):
        result["errors"].append("a negative control was accepted")
    save(args.out / "result.json", result)
    print(json.dumps({key: result[key] for key in ("errors", "negative_controls")}))
    return bool(result["errors"])


if __name__ == "__main__":
    raise SystemExit(main())
