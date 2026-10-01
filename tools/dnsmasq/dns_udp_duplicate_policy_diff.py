#!/usr/bin/env python3
"""Compare the selected correct-client refusal with retained exact-C evidence.

The C bad-ID/question difference is counted explicitly. The policy expectation
uses the original input and the independently established REFUSED envelope;
it never comes from Rust output or treats the wrong client ID as random noise.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_udp_admission_diff import Upstream, query, receive
from dns_service_probe import read_name
from dns_udp_refusal_diff import verify_reference


def refusal(packet):
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    assert flags == 0x130 and (qd, an, ns, ar) == (1, 0, 0, 1)
    _, end = read_name(packet, 12)
    return (struct.pack("!6H", ident, 0x8195, 1, 0, 0, 1) + packet[12:end+4]
            + b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--c", type=Path, required=True); p.add_argument("--c-baseline", type=Path, required=True)
    p.add_argument("--rust", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    baseline = json.loads((args.c_baseline / "result.json").read_text())
    assert baseline["reference"] == verify_reference(args.c, None) and not baseline["failures"]
    original = baseline["rows"]
    assert len(original) == 5 and baseline["accepted_completed"] == 2 and baseline["upstream_queries"] == 1
    out = args.output.resolve(); assert "private" in out.parts and not out.exists(); out.mkdir(parents=True)
    config_text = (args.c_baseline / "dnsmasq.conf").read_text()
    port = int(next(line[5:] for line in config_text.splitlines() if line.startswith("port=")))
    upstream_port = int(next(line.split("#")[1] for line in config_text.splitlines() if line.startswith("server=127.0.0.1#")))
    config = out / "dnsmasq.conf"; config.write_text(config_text)
    requests = [bytes.fromhex(row["request"]) for row in original[:3]]
    expected = refusal(requests[2]); changed = bytearray(expected); changed[0] ^= 1
    assert bytes(changed) != expected and expected != bytes.fromhex(original[2]["response"])
    server = Upstream(upstream_port); clients = []; rows = []; process = None
    report = {"reference": baseline["reference"], "c_result_sha256": hashlib.sha256((args.c_baseline / "result.json").read_bytes()).hexdigest(),
              "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest(), "policy_failures": [], "rows": rows,
              "calibration": {"bad_id_detected": 1, "actual_c_defect_not_normalized": 1},
              "scope": "selected original-client REFUSED policy and survival of accepted recipients; actual C differences remain failures"}
    def client():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); clients.append(sock); return sock
    with (out / "stderr.log").open("w") as log:
        try:
            process = subprocess.Popen([str(args.rust.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
            ready = client(); deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None
                ready.sendto(query(1, "ready.test"), ("127.0.0.1", port))
                if receive(ready, .03) is not None: break
                assert time.monotonic() < deadline
            held = []
            for index, packet in enumerate(requests[:2]):
                sock = client(); sock.sendto(packet, ("127.0.0.1", port)); server.wait_for("hold-duplicate.test")
                assert receive(sock, .04) is None
                rows.append({"event": f"accepted-{index+1}", "request": packet.hex(), "response": None})
                held.append((sock, packet))
            rejected = client(); rejected.sendto(requests[2], ("127.0.0.1", port)); reply = receive(rejected, 1)
            assert reply is not None
            rows.append({"event": "rejected-third-recipient", "request": requests[2].hex(), "response": reply.hex()})
            assert reply == expected, "selected correct-client REFUSED envelope differs"
            assert server.names() == ["hold-duplicate.test"], "duplicate was forwarded again"
            server.release("hold-duplicate.test")
            for index, (sock, packet) in enumerate(held):
                reply = receive(sock, 1); assert reply is not None and reply[:2] == packet[:2]
                rows.append({"event": f"completed-{index+1}", "request": packet.hex(), "response": reply.hex()})
            assert len(rows) == 5 and len(server.events) == 1 and not server.failures
        except Exception as error: report["policy_failures"].append(repr(error))
        finally:
            for sock in clients: sock.close()
            if process is not None:
                if process.poll() is None: process.send_signal(signal.SIGTERM)
                try: process.wait(3)
                except subprocess.TimeoutExpired: process.kill(); process.wait(3)
                report.update(exit=process.returncode, reaped=not Path(f"/proc/{process.pid}").exists())
                if process.returncode or not report["reaped"]: report["policy_failures"].append("shutdown failed")
            server.close()
    report["compared"] = len(rows)
    report["c_rust_differences"] = [{"event": left["event"], "c": left["response"], "rust": right["response"]}
                                    for left, right in zip(original, rows) if left["response"] != right["response"]]
    if len(rows) != len(original): report["policy_failures"].append("completion count differs")
    report["upstream_queries"] = len(server.events)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in {"rows", "c_rust_differences"}}))
    return int(bool(report["policy_failures"] or report["c_rust_differences"]))


if __name__ == "__main__":
    raise SystemExit(main())
