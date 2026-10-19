#!/usr/bin/env python3
"""Check raw SID, base64, empty LuCI name and UCI I/O boundaries in a cloned image.

Run on Oracle as root; each round owns its mount/network/PID namespaces.
Only imports the existing wire encoder/client, never its device fixtures.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from r92_compat_probe import Bus, integer, message, response_data, string


def inner(root, side):
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(root / "dev")], check=True)
    for name, minor in [("null", 3), ("zero", 5), ("urandom", 9)]:
        subprocess.run(["mknod", "-m", "666", str(root / "dev" / name), "c", "1", str(minor)], check=True)
    processes = []
    checks = {}
    def start(binary):
        log = (root / "tmp/out" / (Path(binary).name + ".log")).open("wb")
        process = subprocess.Popen(["chroot", str(root), binary], stdout=log, stderr=log)
        log.close()
        processes.append(process)
        return process
    def check(name, actual, expected):
        checks[name] = {"actual": actual, "expected": expected, "passed": actual == expected}
    start("/sbin/ubusd")
    socket = root / "var/run/ubus/ubus.sock"
    for _ in range(100):
        if socket.exists():
            break
        time.sleep(0.02)
    client = Bus(socket)
    subject = start("/sbin/rpcd" if side == "c" else "/tmp/rpcd-rs")
    try:
        for _ in range(100):
            if all(name in client.paths() for name in ["file", "uci", "luci"]):
                break
            assert subject.poll() is None, "rpcd exited before registration"
            time.sleep(0.02)
        file, uci, luci = [client.lookup(name) for name in ["file", "uci", "luci"]]
        sid = string("ubus_rpc_session", b"\xff")
        check("bad_sid_session_list", client.invoke(client.lookup("session"), "list", sid)[0], 4)
        for method in ["read", "stat", "md5"]:
            code, _ = client.invoke(file, method, sid + string("path", "/etc/config/v032static"))
            check("bad_sid_file_" + method, code, 6)
        check("bad_sid_exec", client.invoke(file, "exec", sid + string("command", "/bin/true"))[0], 6)
        check("bad_sid_uci", client.invoke(uci, "get", sid + string("config", "v032static"))[0], 6)
        check("local_root_control", client.invoke(file, "read", string("path", "/etc/config/v032static"))[0], 0)
        for value in ["QR==", "Qf==", "QUJ=", "Q U J =", "////QR==", "QQ==", "QUI=", "QUJD"]:
            code, _ = client.invoke(file, "write", string("path", "/tmp/base64") + string("data", value) + message("base64", 7, b"\1"))
            expected = {"QQ==": b"A", "QUI=": b"AB", "QUJD": b"ABC"}.get(value)
            check("base64_" + value, [code == 0, (root / "tmp/base64").read_bytes().hex()],
                  [expected is not None, (expected or b"").hex()])
            checks["base64_" + value]["status"] = code
        code, replies = client.invoke(luci, "getInitList")
        default = response_data(replies)
        empty_code, empty_replies = client.invoke(luci, "getInitList", string("name", ""))
        check("init_empty_name", [empty_code, response_data(empty_replies) == default], [code, True])
        check("init_control", bool(default and b"v032fixture" in default[0]), True)
        config = string("config", "v032static")
        section = string("section", "s")
        value = message("values", 2, string("o", "new"))
        delta = root / "tmp/.uci/v032static"
        delta.mkdir()
        for method, args in [
            ("set", section + value),
            ("add", string("type", "t") + string("name", "added")),
            ("delete", section + string("option", "o")),
            ("rename", section + string("name", "renamed")),
            ("order", message("sections", 1, string("", "second") + string("", "s"))),
        ]:
            check("save_failure_" + method, client.invoke(uci, method, config + args)[0], 9)
        delta.rmdir()
        check("set_control", client.invoke(uci, "set", config + section + value)[0], 0)
        target = root / "etc/config"
        original = (target / "v032static").read_bytes()
        subprocess.run(["mount", "--bind", str(target), str(target)], check=True)
        subprocess.run(["mount", "-o", "remount,bind,ro", str(target)], check=True)
        check("commit_failure", client.invoke(uci, "commit", config)[0], 9)
        check("commit_keeps_config", (target / "v032static").read_bytes() == original, True)
        check("commit_keeps_delta", delta.exists() and bool(delta.read_bytes()), True)
        subprocess.run(["mount", "-o", "remount,bind,rw", str(target)], check=True)
        check("commit_retry", client.invoke(uci, "commit", config)[0], 0)
        check("commit_retry_value", b"'new'" in (target / "v032static").read_bytes(), True)
        session = client.lookup("session")
        _, replies = client.invoke(session, "create", integer("timeout", 600))
        session_id = response_data(replies)[0][b"ubus_rpc_session"]
        session_arg = string("ubus_rpc_session", session_id)
        grant = message("objects", 1, message("", 1, string("", "v032static") + string("", "write")))
        check("apply_grant", client.invoke(session, "grant", session_arg + string("scope", "uci") + grant)[0], 0)
        check("apply_set", client.invoke(uci, "set", session_arg + config + section + message("values", 2, string("o", "applied")))[0], 0)
        before_apply = (target / "v032static").read_bytes()
        subprocess.run(["mount", "-o", "remount,bind,ro", str(target)], check=True)
        check("apply_commit_failure", client.invoke(uci, "apply", session_arg + message("rollback", 7, b"\1") + integer("timeout", 600))[0], 9)
        run_dir = "var/run/rpcd" if side == "c" else "var/run/rpcd-rs"
        check("apply_retains_snapshot", (root / run_dir / "snapshot-files/v032static").exists(), True)
        check("apply_keeps_config", (target / "v032static").read_bytes() == before_apply, True)
        subprocess.run(["mount", "-o", "remount,bind,rw", str(target)], check=True)
        check("apply_rollback", client.invoke(uci, "rollback", session_arg)[0], 0)
        check("apply_rollback_value", (target / "v032static").read_bytes() == before_apply, True)
        check("serving", subject.poll() is None and client.invoke(uci, "get", config)[0] == 0, True)
        result = {"side": side, "checks": checks}
        (root / "tmp/out/result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"side": side, "passed": sum(c["passed"] for c in checks.values()), "total": len(checks)}))
    finally:
        client.sock.close()
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        return inner(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sides", nargs="+", default=["c", "rust"])
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    args.output.mkdir(parents=True, exist_ok=False)
    libraries = re.findall(r"(/[^\s()]+)", subprocess.run(["ldd", str(args.binary)], capture_output=True, text=True).stdout)
    identities = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [args.binary, args.rootfs / "sbin/rpcd"]}
    (args.output / "identities.json").write_text(json.dumps(identities, indent=2) + "\n")
    failed = False
    for side in args.sides:
        for repeat in range(4):
            with tempfile.TemporaryDirectory(prefix="rpcd-static-") as tmp:
                root = Path(tmp) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ["tmp/out", "tmp/run/ubus", "tmp/lock", "tmp/state", "tmp/.uci"]:
                    (root / directory).mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.binary, root / "tmp/rpcd-rs")
                for library in libraries:
                    target = root / library.lstrip("/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.is_symlink():
                        target.unlink()
                    shutil.copy2(library, target)
                (root / "etc/config/v032static").write_text("config t 's'\n option o 'old'\nconfig t 'second'\n")
                shutil.rmtree(root / "etc/init.d")
                (root / "etc/init.d").mkdir()
                init = root / "etc/init.d/v032fixture"
                init.write_text("#!/bin/sh /etc/rc.common\nSTART=10\nSTOP=90\n")
                init.chmod(0o755)
                result = subprocess.run(["timeout", "-k", "3", "45", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                                         sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side], capture_output=True)
                dest = args.output / f"{side}-{repeat}"
                shutil.copytree(root / "tmp/out", dest)
                (dest / "driver.log").write_bytes(result.stdout + result.stderr)
                print(side, repeat, result.returncode, result.stdout.decode(), result.stderr.decode(), flush=True)
                if result.returncode:
                    raise SystemExit(result.returncode)
                checks = json.loads((dest / "result.json").read_text())["checks"]
                if side == "rust" and any(not row["passed"] for row in checks.values()):
                    failed = True
    raise SystemExit(failed)


if __name__ == "__main__":
    main()
