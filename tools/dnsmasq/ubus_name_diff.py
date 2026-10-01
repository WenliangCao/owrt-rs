#!/usr/bin/env python3
"""Real C and Rust controller registration of opaque byte object names."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from ubus_contract_diff import BUS, Fixture, digest, fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {"lo"}
    args.reference_build = args.reference_build.resolve()
    assert digest(args.reference_build / "dnsmasq/dnsmasq") == args.c_sha256
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "ubus-names", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Fixture(args, out)
    names = [b"dnsmasq", b" opaque name ", b"comma,colon:slash/path", b"opaque.\xff\xfe", b'quote"backslash\\', b"n" * 1024]
    expected, error = {}, None
    try:
        f.start_bus()
        for implementation in ["C", "Rust"]:
            for index, name in enumerate(names):
                if implementation == "C":
                    command = [bytes(args.reference_build / "dnsmasq/dnsmasq"), b"--keep-in-foreground",
                               b"--user=root", b"--group=root", b"--log-facility=-", b"--conf-file=/dev/null",
                               b"--no-resolv", b"--no-hosts", b"--port=0", b"--pid-file=" + bytes(out / "pid"),
                               b"--enable-ubus=" + name]
                else:
                    command = [str(args.probe.resolve()), "serve-hex", BUS, name.hex()]
                log = out / f"{implementation}-{index}.log"
                with log.open("wb") as stream:
                    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stream,
                                               stderr=subprocess.STDOUT, env=f.env)
                f.children.append(process)
                paths = []
                for suffix in [b"", b".dns"]:
                    deadline = time.monotonic() + 3
                    while True:
                        rows = f.client_call("lookup-hex", name + suffix)
                        found = [row for row in rows if row["event"] == "lookup"]
                        if found:
                            break
                        assert process.poll() is None and time.monotonic() < deadline, "registration failed"
                        time.sleep(.01)
                    f.check(f"{implementation}-{index}-one-path", len(found), 1)
                    row = found[0]
                    f.check(f"{implementation}-{index}-raw-name", row["path_hex"], (name + suffix).hex())
                    f.check(f"{implementation}-{index}-assigned-type", row["type"] > 0, True)
                    paths.append({"path_hex": row["path_hex"], "signature": fields(row["wire"])})
                if implementation == "C":
                    expected[index] = paths
                else:
                    f.check(f"paired-{index}-name-and-signature", paths, expected[index])
                f.stop(process)
        f.check("frozen-name-count", len(names), 6)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        f.close()
    report = {"scope": __doc__, "error": error, "checks": f.checks, "raw": f.raw,
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks)}
    (out / "result.json").write_text(json.dumps(report, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "failed", "error")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
