#!/usr/bin/env python3
"""Observe static PIE ASLR and protections against the same-source static ELF."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import time

from m2_rootfs import command, prepare, sha256


def layout(binary):
    data = binary.read_bytes()
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    kind, machine = struct.unpack_from("<HH", data, 16)
    assert machine == 183 and kind in (2, 3)
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + i * size) for i in range(count)]
    assert not any(row[0] == 3 for row in headers), "static ELF must not have PT_INTERP"
    assert not any(row[0] == 1 and row[1] & 3 == 3 for row in headers), "WX LOAD"
    assert any(row[0] == 0x6474e551 and row[1] & 1 == 0 for row in headers), "NX stack required"
    relro = next(row for row in headers if row[0] == 0x6474e552)
    dynamic = subprocess.check_output(["readelf", "-W", "-d", str(binary)], text=True)
    assert "(NEEDED)" not in dynamic and "TEXTREL" not in dynamic
    if kind == 3:
        assert "PIE" in dynamic
    return kind, relro, dynamic


def observe(image, binary, out):
    out.mkdir()
    root = prepare(image, None, out, binary)
    installed = root / "usr/sbin/dnsmasq-rs"
    kind, relro, dynamic = layout(installed)
    (out / "dynamic.txt").write_text(dynamic)
    runs = []
    for index in range(3):
        pidfile = root / "m2/static-pie.pid"
        with (out / f"run-{index}.log").open("wb") as log:
            process = subprocess.Popen(command(root, "rust", "-C", "/dev/null", "-k",
                "--user=root", "--group=root", "--port=0", "--no-hosts", "--no-resolv",
                "--pid-file=/m2/static-pie.pid", "--log-facility=-"), stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while not pidfile.exists():
                    assert process.poll() is None and time.monotonic() < deadline, "startup failed"
                    time.sleep(.01)
                actual_sha = sha256(Path(f"/proc/{process.pid}/exe"))
                assert actual_sha == sha256(binary)
                maps = Path(f"/proc/{process.pid}/maps").read_text()
                (out / f"run-{index}.maps").write_text(maps)
                entries = []
                for line in maps.splitlines():
                    fields = line.split()
                    start, end = [int(value, 16) for value in fields[0].split("-")]
                    entries.append((start, end, fields[1], fields))
                mapped_files = sorted({fields[-1] for _, _, _, fields in entries
                                       if fields[-1].startswith("/")})
                assert mapped_files == [str(installed)], "external file-backed mappings in static daemon"
                start = next(start for start, _, _, fields in entries
                             if fields[-1] == str(installed) and int(fields[2], 16) == 0)
                bias = start if kind == 3 else 0
                begin = (bias + relro[3]) & ~4095
                end = (bias + relro[3] + relro[6]) & ~4095
                assert end > begin
                readonly = all(any(low <= page and high >= page + 4096 and "w" not in permissions
                                   for low, high, permissions, _ in entries)
                               for page in range(begin, end, 4096))
                stack = next(permissions for _, _, permissions, fields in entries if fields[-1] == "[stack]")
                assert "x" not in stack
                runs.append(dict(mapped_base=hex(start), load_bias=hex(bias), relro_readonly=readonly,
                                 stack_executable=False, actual_elf_sha256=actual_sha,
                                 mapped_files=mapped_files))
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            assert process.returncode == 0
    return dict(sha256=sha256(binary), bytes=binary.stat().st_size, elf_type=kind,
                interpreter=False, needed=[], runs=runs,
                distinct_bases=len({run["mapped_base"] for run in runs}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--static", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    args.out.mkdir(parents=True, exist_ok=False)
    candidate = observe(args.image_root, args.rust, args.out / "static-pie")
    baseline = observe(args.image_root, args.static, args.out / "static")
    assert candidate["elf_type"] == 3 and candidate["distinct_bases"] == 3
    assert baseline["elf_type"] == 2 and baseline["distinct_bases"] == 1
    # A GNU_RELRO header alone is not evidence of mprotect. Record the actual
    # static-musl behavior, requiring no loss relative to the old static ELF.
    assert not all(row["relro_readonly"] for row in baseline["runs"]) or all(
        row["relro_readonly"] for row in candidate["runs"])
    result = dict(scope="Static linkage, ASLR and observed protections in the isolated image; not full RELRO or router qualification",
                  tool_sha256=sha256(Path(__file__)), candidate=candidate, baseline=baseline,
                  full_relro=all(row["relro_readonly"] for row in candidate["runs"]), passed=True)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
