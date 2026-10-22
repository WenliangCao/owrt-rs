#!/usr/bin/env python3
"""Check 25.12.6 RPC filesystem/session contracts in disposable Linux namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

from r92_compat_probe import Fixture, integer, message, response_data, string


def inner(root, side):
    fixture = Fixture(root, side, "rpcd")
    try:
        fixture.start_bus()
        fixture.start_subject(obj="file")
        client = fixture.connect()
        session, file, uci = [client.lookup(name) for name in ("session", "file", "uci")]
        code, replies = client.invoke(session, "create", integer("timeout", 120))
        assert code == 0
        sid = response_data(replies)[0][b"ubus_rpc_session"]
        credential = string("ubus_rpc_session", sid)

        def grant(scope, path, permission):
            pair = message("", 1, string("", path) + string("", permission))
            assert client.invoke(session, "grant", credential + string("scope", scope)
                                 + message("objects", 1, pair))[0] == 0

        def call(method, path, extra=b""):
            return client.invoke(file, method, credential + string("path", path) + extra)

        private = root / "tmp/private"
        private.mkdir()
        (private / "secret").write_text("secret")
        (root / "tmp/link").symlink_to("private/secret")
        (root / "tmp/dirlink").symlink_to("private")
        (root / "tmp/dangling").symlink_to("private/missing")
        (root / "tmp/empty").write_text("")
        for path in ("/tmp/link", "/tmp/dirlink", "/tmp/dirlink/new", "/tmp/dangling", "/tmp/empty"):
            for permission in ("read", "write", "list"):
                grant("file", path, permission)
        for method in ("read", "md5", "stat"):
            fixture.check("link_denied_" + method, call(method, "/tmp/link")[0], 6)
        fixture.check("link_write_denied", call("write", "/tmp/link", string("data", "bad"))[0], 6)
        fixture.check("directory_list_denied", call("list", "/tmp/dirlink")[0], 6)
        fixture.check("new_target_denied", call("write", "/tmp/dirlink/new", string("data", "new"))[0], 6)
        fixture.check("dangling_denied", call("write", "/tmp/dangling", string("data", "bad"))[0], 6)
        fixture.check("denied_targets_unchanged", [(private / "secret").read_text(), (private / "new").exists(),
                                                   (private / "missing").exists()], ["secret", False, False])
        fixture.check("link_lstat", call("lstat", "/tmp/link")[0], 0)
        grant("file", "/tmp/private/secret", "read")
        code, replies = call("read", "/tmp/link")
        fixture.check("authorized_link_read", [code, response_data(replies)[0][b"data"].decode()], [0, "secret"])
        grant("file", "/tmp/private/secret", "list")
        code, replies = call("stat", "/tmp/link")
        fixture.check("authorized_stat_path", [code, response_data(replies)[0][b"path"].decode()], [0, "/tmp/private/secret"])
        grant("file", "/tmp/private/new", "write")
        fixture.check("authorized_new_target", call("write", "/tmp/dirlink/new", string("data", "new"))[0], 0)
        fixture.check("authorized_new_contents", (private / "new").read_text(), "new")
        fixture.check("unlink_final_link", call("remove", "/tmp/link")[0], 0)
        fixture.check("unlink_keeps_target", (private / "secret").read_text(), "secret")
        for base64 in (False, True):
            code, replies = call("read", "/tmp/empty", message("base64", 7, bytes([base64])))
            fixture.check("empty_base64_" + str(base64), [code, response_data(replies)[0][b"data"].decode()], [0, ""])
        grant("file", "/tmp/mode", "write")
        fixture.check("write_mode", call("write", "/tmp/mode", string("data", "x") + integer("mode", 0o7777))[0], 0)
        fixture.check("umask_and_special_bits", (root / "tmp/mode").stat().st_mode & 0o7777, 0o700)
        nested = root / "tmp/tree"
        nested.mkdir()
        (nested / "child").write_text("keep")
        grant("file", "/tmp/tree", "write")
        fixture.check("recursive_child_denied", call("remove", "/tmp/tree")[0], 6)
        fixture.check("recursive_child_intact", (nested / "child").read_text(), "keep")
        grant("file", "/tmp/tree/child", "write")
        fixture.check("recursive_child_authorized", call("remove", "/tmp/tree")[0], 0)
        # Upstream .6 skips resolving parent links for unlink/lstat. Rust also
        # protects that boundary; record this deliberate security difference.
        grant("file", "/tmp/dirlink/secret", "write")
        fixture.check("parent_link_remove", call("remove", "/tmp/dirlink/secret")[0],
                      0 if side == "original" else 6)
        fixture.check("parent_link_target", (private / "secret").exists(), side == "candidate")

        config = root / "etc/config/upgradeprobe"
        config.write_text("config test 's'\n option value 'before'\n")
        grant("uci", "upgradeprobe", "write")
        change = credential + string("config", "upgradeprobe") + string("section", "s")
        fixture.check("stage_config", client.invoke(uci, "set", change + message("values", 2, string("value", "after")))[0], 0)
        runtime = root / ("var/run/rpcd" if side == "original" else "var/run/rpcd-rs")
        deltas = [p for p in runtime.glob("uci-*") if (p / "upgradeprobe").is_file()]
        assert len(deltas) == 1
        delta = deltas[0]
        saved = (delta / "upgradeprobe").read_bytes()
        fixture.check("delta_name_not_token", delta.name != "uci-" + sid.decode())
        fixture.check("unknown_session_apply", client.invoke(uci, "apply", string("ubus_rpc_session", "f" * 32))[0], 4)
        fixture.check("unknown_session_has_no_directory", not (runtime / ("uci-" + "f" * 32)).exists())
        fixture.subject.send_signal(signal.SIGUSR1)
        fixture.subject.wait(timeout=5)
        frozen_dir = runtime / "sessions"
        frozen = [p for p in frozen_dir.iterdir() if re.fullmatch("[a-f0-9]{32}", p.name)]
        fixture.check("frozen_name_not_token", len(frozen) == 1 and frozen[0].name != sid.decode())
        with (fixture.output / "thaw.log").open("wb") as log:
            restarted = subprocess.Popen(["chroot", str(root), fixture.binary], stdout=log, stderr=log,
                                         env=dict(os.environ, RPC_HANGUP="1"))
        fixture.processes.append(restarted)
        assert fixture.wait(lambda: fixture.ready("session"))
        session = client.lookup("session")
        fixture.check("session_restored", client.invoke(session, "list", credential)[0], 0)
        fixture.check("delta_preserved_on_thaw", (delta / "upgradeprobe").read_bytes() == saved)
        fixture.check("destroy_session", client.invoke(session, "destroy", credential)[0], 0)
        fixture.check("destroy_removes_random_directory", not delta.exists())
        (fixture.output / "result.json").write_text(json.dumps(fixture.checks, indent=2) + "\n")
        assert all(row["passed"] for row in fixture.checks.values()), fixture.checks
        print(json.dumps({"side": side, "passed": len(fixture.checks)}))
    finally:
        fixture.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        return inner(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and sys.platform == "linux"
    args.output.mkdir(parents=True, exist_ok=False)
    identities = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for name, path in (("stock_rpcd", args.rootfs / "sbin/rpcd"), ("candidate", args.binary))}
    (args.output / "identities.json").write_text(json.dumps(identities, indent=2) + "\n")
    for side in ("original", "candidate"):
        with tempfile.TemporaryDirectory(prefix="rpcd-25126-") as temporary:
            root = Path(temporary) / "root"
            subprocess.run(["cp", "-a", str(args.rootfs), str(root)], check=True)
            for directory in ("tmp/out", "tmp/run/ubus", "tmp/lock", "tmp/state"):
                (root / directory).mkdir(parents=True, exist_ok=True)
            subprocess.run(["cp", str(args.binary), str(root / "tmp/rpcd-rs")], check=True)
            result = subprocess.run(["timeout", "-k", "3", "45", "unshare", "--mount", "--net", "--pid", "--fork",
                                     "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side],
                                    capture_output=True)
            subprocess.run(["cp", "-a", str(root / "tmp/out"), str(args.output / side)], check=True)
            (args.output / side / "driver.log").write_bytes(result.stdout + result.stderr)
            print(result.stdout.decode(errors="replace"), end="", flush=True)
            if result.returncode:
                print(result.stderr.decode(errors="replace"), file=sys.stderr)
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
