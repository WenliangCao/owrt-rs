#!/usr/bin/env python3
"""Verify target PIE identity, ASLR and runtime protections inside the image."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import time

from m2_rootfs import command, prepare, sha256


def headers(binary):
    data = binary.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<HH", data, 16) == (3, 183), "AArch64 ET_DYN required"
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    return [struct.unpack_from("<IIQQQQQQ", data, offset + i * size) for i in range(count)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--static", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out, args.rust)
    binary = root / "usr/sbin/dnsmasq-rs"
    ph = headers(binary)
    assert not any(kind == 1 and flags & 3 == 3 for kind, flags, *_ in ph), "WX LOAD"
    assert any(kind == 0x6474e551 and flags & 1 == 0 for kind, flags, *_ in ph), "executable stack"
    relro = next(row for row in ph if row[0] == 0x6474e552)
    dynamic = subprocess.check_output(["readelf", "-d", str(binary)], text=True)
    assert "BIND_NOW" in dynamic and "PIE" in dynamic and "TEXTREL" not in dynamic
    needed = [line.split("[")[1].split("]")[0] for line in dynamic.splitlines() if "(NEEDED)" in line]
    assert set(needed) <= {"libc.so", "libgcc_s.so.1"}
    (args.out / "dynamic.txt").write_text(dynamic)
    runs = []
    for index in range(3):
        pidfile = root / "m2/pie.pid"
        with (args.out / f"run-{index}.log").open("wb") as log:
            process = subprocess.Popen(command(root, "rust", "-C", "/dev/null", "-k",
                "--user=root", "--group=root", "--port=0", "--no-hosts", "--no-resolv",
                "--pid-file=/m2/pie.pid", "--log-facility=-"), stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while not pidfile.exists():
                    assert process.poll() is None and time.monotonic() < deadline, "startup failed"
                    time.sleep(.01)
                assert sha256(Path(f"/proc/{process.pid}/exe")) == sha256(args.rust)
                # pidfile creation precedes the final loop; mappings and ELF
                # protections are already established by the image loader.
                maps = Path(f"/proc/{process.pid}/maps").read_text()
                (args.out / f"run-{index}.maps").write_text(maps)
                entries = []
                for line in maps.splitlines():
                    fields = line.split()
                    start, end = [int(part, 16) for part in fields[0].split("-")]
                    entries.append((start, end, fields[1], fields))
                base = next(start for start, _, _, fields in entries
                            if fields[-1].endswith("/usr/sbin/dnsmasq-rs") and int(fields[2], 16) == 0)
                begin = (base + relro[3]) & ~4095
                end = (base + relro[3] + relro[6]) & ~4095
                assert end > begin
                assert all(any(start <= page and stop >= page + 4096 and "w" not in permissions
                               for start, stop, permissions, _ in entries)
                           for page in range(begin, end, 4096)), "RELRO still writable"
                stack = next(permissions for _, _, permissions, fields in entries if fields[-1] == "[stack]")
                assert "x" not in stack
                runs.append({"base": hex(base), "relro_readonly": True, "stack_executable": False,
                             "actual_elf_sha256": sha256(Path(f"/proc/{process.pid}/exe"))})
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            assert process.returncode == 0
    result = {"scope": "isolated exact-image ASLR/RELRO/NX check; not a performance or package-install gate",
              "rust_sha256": sha256(args.rust), "static_sha256": sha256(args.static),
              "tool_sha256": sha256(Path(__file__)), "pie_bytes": args.rust.stat().st_size,
              "static_bytes": args.static.stat().st_size, "needed": needed,
              "image_libraries": {name: sha256(root / "lib" / name) for name in needed},
              "runs": runs, "aslr_observed": len({run["base"] for run in runs}) == len(runs)}
    result["passed"] = result["aslr_observed"] and result["pie_bytes"] <= result["static_bytes"] * 1.05
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
