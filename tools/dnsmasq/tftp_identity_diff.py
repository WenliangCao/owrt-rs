#!/usr/bin/env python3
"""Check ordinary TFTP file ownership after the foreground UID transition."""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess

from startup_privilege_diff import (BASE_CONFIG, SERVICE_IDENTITY, binary_identity,
                                    check_saved_result, prepare_isolated, rejected_observation,
                                    save, task_identities, wait_ready)

FILES = (("owned-private", 453, 0o600), ("owned-public", 453, 0o644), ("root-private", 0, 0o600))
CONTENT = b"M1 owned file fixture\n"


def run(binary, out):
    out.mkdir()
    out.chmod(0o755)
    files = out / "files"
    files.mkdir()
    rows = []
    for name, uid, mode in FILES:
        path = files / name
        path.write_bytes(CONTENT)
        os.chown(path, uid, uid)
        path.chmod(mode)
        rows.append({"name": name, "owner": uid, "mode": oct(mode)})
    config = out / "dnsmasq.conf"
    config.write_text(BASE_CONFIG + "pid-file=\nenable-tftp\ntftp-secure\n" + f"tftp-root={files}\n")
    command = [str(binary), "-k", "-C", str(config)]
    result = {"command": command, "files": rows}
    with (out / "stdout").open("wb") as stdout, (out / "stderr").open("wb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            result["ready_reply"] = wait_ready(process, out, timeout=5)
            if result["ready_reply"] is None:
                raise RuntimeError("daemon exited or timed out before DNS readiness")
            result["threads"] = task_identities(process.pid, out)
            for row in rows:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.bind(("127.0.0.1", 0))
                    client.settimeout(2)
                    request = b"\x00\x01" + row["name"].encode() + b"\x00octet\x00"
                    client.sendto(request, ("127.0.0.1", 69))
                    packet, peer = client.recvfrom(4096)
                    row["packet_hex"] = packet.hex()
                    (out / (row["name"] + ".reply.hex")).write_text(packet.hex() + "\n")
                    opcode, block = struct.unpack("!HH", packet[:4])
                    if opcode == 3:
                        client.sendto(struct.pack("!HH", 4, block), peer)
            process.send_signal(signal.SIGTERM)
            result["exit"] = process.wait(5)
        except Exception as error:
            result["harness_error"] = repr(error)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
                result["forced_kill"] = True
    save(out / "result.json", result)
    return result


def semantic_result(result):
    if "harness_error" in result or result.get("forced_kill"):
        raise ValueError("harness failure or forced termination")
    if result["exit"] != 0:
        raise ValueError("service did not exit normally")
    if not result["threads"] or any(task != SERVICE_IDENTITY for task in result["threads"]):
        raise ValueError("a daemon task has incorrect credentials or capabilities")
    if [row.get("name") for row in result["files"]] != [name for name, _, _ in FILES]:
        raise ValueError("file observations missing, duplicated, reordered or unexpected")
    rows = []
    for row, (name, owner, mode) in zip(result["files"], FILES):
        if row["owner"] != owner or row["mode"] != oct(mode):
            raise ValueError("file fixture identity changed")
        packet = bytes.fromhex(row["packet_hex"])
        opcode, value = struct.unpack("!HH", packet[:4])
        expected = (5, 2) if name == "root-private" else (3, 1)
        if (opcode, value) != expected:
            raise ValueError(f"{name}: unexpected TFTP opcode/block/error")
        if opcode == 3 and packet[4:] != CONTENT:
            raise ValueError(f"{name}: transferred bytes differ")
        if opcode == 5 and (len(packet) <= 4 or packet[-1] != 0):
            raise ValueError("malformed TFTP error")
        rows.append({"name": name, "opcode": opcode, "block_or_error": value,
                     "payload": packet[4:].hex() if opcode == 3 else None})
    return {"files": rows, "ready_reply": result["ready_reply"], "exit": result["exit"]}


def compare(result):
    errors, normalized = [], {}
    for side in ("c", "rust"):
        try:
            normalized[side] = semantic_result(result[side])
        except (KeyError, TypeError, ValueError, struct.error) as error:
            errors.append(f"{side}: {error}")
    if len(normalized) == 2 and normalized["c"] != normalized["rust"]:
        errors.append("C/Rust semantic observations differ")
    return errors


def negative_controls(result, out):
    controls = []
    for mutation in ("missing-file", "changed-opcode", "wrong-worker-uid"):
        changed = copy.deepcopy(result)
        if mutation == "missing-file":
            changed["rust"]["files"].pop()
        elif mutation == "changed-opcode":
            row = changed["rust"]["files"][0]
            packet = bytearray.fromhex(row["packet_hex"])
            packet[1] = 5
            row["packet_hex"] = packet.hex()
        else:
            changed["rust"]["threads"][-1]["Uid"] = ["0"] * 4
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
    result = {"binaries": {"c": binary_identity(args.c), "rust": binary_identity(args.rust)}}
    for side, binary in (("c", args.c), ("rust", args.rust)):
        result[side] = run(binary, args.out / side)
    result["errors"] = compare(result)
    result["negative_controls"] = [] if result["errors"] else negative_controls(result, args.out)
    if any(not control["detected"] for control in result["negative_controls"]):
        result["errors"].append("a negative control was accepted")
    save(args.out / "result.json", result)
    print(json.dumps({key: result[key] for key in ("errors", "negative_controls")}))
    return bool(result["errors"])


if __name__ == "__main__":
    raise SystemExit(main())
