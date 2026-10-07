#!/usr/bin/env python3
"""Run the exact C local-answer oracle and compare a Rust probe.

The oracle is linked from a previously built, exact dnsmasq 2.93-r1 tree. It
accepts one hex DNS query per line and prints one hex response or ``NONE``.
The input/configuration and resulting JSON belong in ``private/``; only this
tool and its C driver are source artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name("local_answer_driver.c")
DEFAULT_WORK = ROOT / "private/dnsmasq-rewrite/local-answer-diff"
DEFAULT_SOURCES = ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
REFERENCE_COPTS = ["-DHAVE_UBUS", "-DHAVE_POLL_H", "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID"]
REFERENCE_CONFIG_SHA256 = "dacbe1f8d0e03d93e53a81901956b07ab7a5059d1e5db3225150a9688a1122da"
M6B_NATIVE_REFERENCE_SHA256 = "bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def find_objcopy() -> str:
    for name in ("objcopy", "llvm-objcopy", "gobjcopy"):
        value = shutil.which(name)
        if value:
            return value
    raise SystemExit("objcopy/llvm-objcopy is required to rename dnsmasq.o main")


def validate_reference_variant(build: Path) -> None:
    # This builder is for the exact source/config.h plus explicit recipe
    # COPTS. A previously modified native-host config.h is a different build
    # boundary; accepting it without a derived feature manifest risks using
    # a daemon struct layout inconsistent with the linked object files.
    if sha256(build / "config.h") != REFERENCE_CONFIG_SHA256:
        raise SystemExit("reference config.h differs; host-modified feature headers require a separately verified build")
    with (build / "dnsmasq.o").open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise SystemExit("this variant builder requires the verified Linux ELF object build; native Mach-O objects need a separate feature manifest")


def rename_main(build: Path, work: Path) -> Path:
    existing = build / "dnsmasq-renamed.o"
    if existing.exists():
        return existing
    source = build / "dnsmasq.o"
    if not source.exists():
        raise SystemExit(f"missing {source}; build the exact C reference first")
    target = work / "dnsmasq-renamed.o"
    shutil.copy2(source, target)
    subprocess.run(
        [find_objcopy(), "--redefine-sym", "main=reference_main", str(target)],
        check=True,
    )
    return target


def c_input_identity(paths: list[Path]) -> dict[str, object]:
    return {str(path.absolute()): {"resolved_path": str(path.resolve()),
                                 "bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in sorted(set(paths)) if path.is_file()}


def c_elf_identity(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"C primitive requires ELF64 little-endian: {path}")
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": sha256(path), "class": 64, "endianness": "little",
            "machine": struct.unpack_from("<H", header, 18)[0]}


def c_build_command(work: Path, label: str, argv: list[str], *, input_data=None):
    failure = None
    try:
        run = subprocess.run(argv, input=input_data, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        failure = {"kind": type(error).__name__, "message": str(error)}
        stdout = getattr(error, "stdout", None) or b""
        stderr = getattr(error, "stderr", None) or str(error).encode()
        run = subprocess.CompletedProcess(argv, -1, stdout, stderr)
    stdout, stderr = label + ".stdout", label + ".stderr"
    (work / stdout).write_bytes(run.stdout)
    (work / stderr).write_bytes(run.stderr)
    record = {"argv": argv, "exit": run.returncode, "stdout": stdout, "stderr": stderr,
              "command_file": label + ".command.json",
              "stdout_sha256": sha256(work / stdout), "stderr_sha256": sha256(work / stderr)}
    if failure is not None:
        record["failure"] = failure
    (work / (label + ".command.json")).write_text(json.dumps(record, indent=2) + "\n")
    return run, record


def compile_c_oracle(command: list[str], work: Path, build: Path, source: Path,
                     objects: list[Path], deps: Path, abi_flags: list[str],
                     *, expected_machine: int | None = None,
                     expected_native_sha: str | None = None) -> dict[str, object]:
    """Fresh driver compile/link receipts; the native reference objects are reused."""
    compiler_entry = Path(shutil.which(command[0]) or command[0]).absolute()
    compiler = compiler_entry.resolve()
    headers = sorted((deps.parent / "include").rglob("*.h"))
    sources = sorted(path for path in build.rglob("*") if path.suffix in {".c", ".h"} and path.is_file())
    libraries = sorted(path for path in deps.rglob("*") if path.is_file())
    generated = sorted(work.glob("*.inc"))
    original_main = build / "dnsmasq.o"
    paths = [source, compiler_entry, compiler, original_main, *objects, *sources, *headers, *libraries, *generated]
    native_daemon = build / "dnsmasq"
    if expected_native_sha is not None and (not native_daemon.is_file() or sha256(native_daemon) != expected_native_sha):
        raise ValueError("pinned native reference daemon identity differs; this is not the image daemon")
    if expected_native_sha is not None:
        for library in ["ubus", "ubox"]:
            if not any((deps / ("lib" + library + suffix)).is_file() for suffix in [".so", ".a"]):
                raise ValueError("explicit native reference dependency required: " + library)
    if native_daemon.is_file():
        paths.append(native_daemon)
    before = c_input_identity(paths)
    (work / "c-build-inputs-before.json").write_text(json.dumps(before, indent=2) + "\n")
    receipt = {"schema": 1, "kind": "native-c-primitive-build", "status": "preparing",
               "reference_build": str(build.resolve()), "compiler": str(compiler),
               "compiler_entry": str(compiler_entry), "compiler_argv0": command[0],
               "compiler_sha256": sha256(compiler), "compiler_probes": [],
               "variant": {"copts": REFERENCE_COPTS, "config_h_sha256": sha256(build / "config.h"),
                           "abi_flags": abi_flags, "expected_elf_machine": expected_machine,
                           "expected_native_sha256": expected_native_sha},
               "driver": c_input_identity([source]), "sources_and_headers": c_input_identity([*sources, *headers]),
               "objects": c_input_identity(objects), "libraries": c_input_identity(libraries),
               "reference_main_object": c_input_identity([original_main]),
               "generated_includes": c_input_identity(generated), "input_identity": before,
               "native_reference_objects_reused": True, "full_c_objects_rebuilt": False,
               "native_reference_daemon": c_elf_identity(native_daemon) if native_daemon.is_file() else None,
               "tool_sha256": sha256(Path(__file__)), "image_daemon_qualification": False,
               "scope": "fresh primitive driver compile/link against reused native reference objects; not image daemon 097a9e21",
               "library_scope": "explicit reference deps libraries; system linker/runtime files not exhaustively inventoried"}
    sidecar = work / "c-build-receipt.json"
    sidecar.write_text(json.dumps(receipt, indent=2) + "\n")
    for label, flags in [("version", ["--version"]), ("machine", ["-dumpmachine"]),
                         ("macros", [*abi_flags, "-dM", "-E", "-x", "c", "-"])]:
        run, row = c_build_command(work, "c-compiler-" + label, [command[0], *flags], input_data=b"")
        receipt["compiler_probes"].append(row)
        receipt["status"] = "compiler-failed" if run.returncode else "compiler-probed"
        sidecar.write_text(json.dumps(receipt, indent=2) + "\n")
        run.check_returncode()
    run, row = c_build_command(work, "c-build", command)
    receipt["compile_link"] = row
    after = c_input_identity(paths)
    (work / "c-build-inputs-after.json").write_text(json.dumps(after, indent=2) + "\n")
    receipt["status"] = "build-failed" if run.returncode else "built"
    receipt["inputs_unchanged"] = before == after
    sidecar.write_text(json.dumps(receipt, indent=2) + "\n")
    run.check_returncode()
    if before != after:
        raise ValueError("C primitive inputs changed during compile/link")
    binary = Path(command[command.index("-o") + 1])
    receipt["artifact"] = c_elf_identity(binary)
    machine = receipt["artifact"]["machine"]
    if expected_machine is not None and machine != expected_machine:
        receipt["status"] = "abi-failed"
        sidecar.write_text(json.dumps(receipt, indent=2) + "\n")
        raise ValueError("C primitive ELF machine differs")
    if (any(c_elf_identity(path)["machine"] != machine for path in objects)
            or (native_daemon.is_file() and receipt["native_reference_daemon"]["machine"] != machine)):
        receipt["status"] = "abi-failed"
        sidecar.write_text(json.dumps(receipt, indent=2) + "\n")
        raise ValueError("C primitive object ELF machine differs")
    receipt["status"] = "built-inputs-and-abi-verified"
    sidecar.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def verify_c_build(work: Path, binary: Path) -> dict[str, object]:
    sidecar = work / "c-build-receipt.json"
    receipt = json.loads(sidecar.read_text())
    inputs = receipt["input_identity"]
    variant = receipt["variant"]
    expected_machine = variant["expected_elf_machine"]
    expected_native_sha = variant["expected_native_sha256"]
    if (receipt.get("schema") != 1 or receipt.get("kind") != "native-c-primitive-build"
            or receipt.get("status") != "built-inputs-and-abi-verified"
            or receipt.get("tool_sha256") != sha256(Path(__file__))
            or len(receipt.get("compiler_probes", [])) != 3
            or c_input_identity([Path(name) for name in inputs]) != inputs
            or receipt["artifact"] != c_elf_identity(binary)
            or variant["config_h_sha256"] != REFERENCE_CONFIG_SHA256
            or variant["copts"] != REFERENCE_COPTS
            or (expected_machine is not None and expected_machine != receipt["artifact"]["machine"])
            or (expected_native_sha is not None and expected_native_sha != receipt["native_reference_daemon"]["sha256"])):
        raise ValueError("C primitive source/compiler/object/library/ELF binding changed")
    for name in ["c-build-inputs-before.json", "c-build-inputs-after.json"]:
        if json.loads((work / name).read_text()) != inputs:
            raise ValueError("C primitive compilation-input witness differs")
    for row in [receipt["compile_link"], *receipt["compiler_probes"]]:
        if (row["exit"] != 0 or sha256(work / row["stdout"]) != row["stdout_sha256"]
                or sha256(work / row["stderr"]) != row["stderr_sha256"]
                or json.loads((work / row["command_file"]).read_text()) != row):
            raise ValueError("C primitive compile/compiler observations differ")
    return {"receipt": sidecar.name, "receipt_sha256": sha256(sidecar),
            "binary_sha256": receipt["artifact"]["sha256"], "elf_machine": receipt["artifact"]["machine"],
            "native_reference_objects_reused": True, "full_c_objects_rebuilt": False,
            "image_daemon_qualification": False, "scope": receipt["scope"]}


def build_oracle(reference_build: Path, work: Path, *, expected_machine: int | None = None,
                 expected_native_sha: str | None = None) -> Path:
    build = reference_build / "dnsmasq"
    # build_reference.sh nests objects under dnsmasq/. Existing audited native
    # builds predate that wrapper and place the same objects at their root.
    if not build.is_dir() and (reference_build / "dnsmasq.o").exists():
        build = reference_build
    if not build.is_dir():
        raise SystemExit(f"expected object directory {build}")
    validate_reference_variant(build)
    binary = work / "local-answer-oracle"
    renamed = rename_main(build, work)
    source = work / "local_answer_driver.c"
    shutil.copy2(DRIVER, source)
    objects = sorted(path for path in build.glob("*.o") if path.name != "dnsmasq.o")
    if renamed not in objects:
        objects.append(renamed)
    cc = os.environ.get("CC", shutil.which("cc") or "cc")
    flags = [
        *REFERENCE_COPTS,
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        f"-I{build}",
        f"-I{reference_build / 'deps/include'}",
    ]
    command = [cc, *flags, str(source), *(str(path) for path in objects)]
    deps = reference_build / "deps/lib"
    if deps.exists():
        command.extend([f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox"])
    command.extend(["-o", str(binary)])
    compile_c_oracle(command, work, build, source, objects, deps, flags,
                     expected_machine=expected_machine, expected_native_sha=expected_native_sha)
    return binary


def run_probe(binary: Path, config: Path, queries: list[str]) -> list[str]:
    process = subprocess.run(
        [str(binary), "-C", str(config)],
        input=("\n".join(queries) + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(
            f"oracle exited {process.returncode}: {process.stderr.decode(errors='replace')}"
        )
    lines = process.stdout.decode("ascii", errors="strict").splitlines()
    if len(lines) != len(queries):
        raise RuntimeError(
            f"oracle emitted {len(lines)} rows for {len(queries)} queries: "
            f"{process.stderr.decode(errors='replace')}"
        )
    return lines


def run_command(command: list[str], config: Path, queries: list[str]) -> list[str]:
    process = subprocess.run(
        [*command, str(config)],
        input=("\n".join(queries) + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(
            f"Rust probe exited {process.returncode}: {process.stderr.decode(errors='replace')}"
        )
    lines = process.stdout.decode("ascii", errors="strict").splitlines()
    if len(lines) != len(queries):
        raise RuntimeError(f"Rust probe emitted {len(lines)} rows for {len(queries)} queries")
    return lines


def dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[bytes] = []
    seen: set[int] = set()
    cursor = offset
    resume: int | None = None
    for _ in range(256):
        if cursor >= len(packet) or cursor in seen:
            raise ValueError("DNS name pointer loop/truncation")
        seen.add(cursor)
        length = packet[cursor]
        cursor += 1
        if length == 0:
            return b".".join(labels).decode("ascii", errors="backslashreplace").lower(), resume or cursor
        if length & 0xC0 == 0xC0:
            if cursor >= len(packet):
                raise ValueError("truncated DNS pointer")
            target = ((length & 0x3F) << 8) | packet[cursor]
            cursor += 1
            resume = resume or cursor
            cursor = target
            continue
        if length > 63 or cursor + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[cursor : cursor + length])
        cursor += length
    raise ValueError("DNS name hop limit")


def rdata_semantics(packet: bytes, rrtype: int, start: int, end: int) -> object:
    data = packet[start:end]
    try:
        if rrtype in (2, 3, 4, 5, 7, 8, 9, 12, 39):
            name, consumed = dns_name(packet, start)
            if consumed == end:
                return [name]
        elif rrtype in (15, 18, 21, 36) and len(data) >= 2:
            name, consumed = dns_name(packet, start + 2)
            if consumed == end:
                return [data[:2].hex(), name]
        elif rrtype == 33 and len(data) >= 6:
            name, consumed = dns_name(packet, start + 6)
            if consumed == end:
                return [data[:6].hex(), name]
        elif rrtype == 6:
            first, consumed = dns_name(packet, start)
            second, consumed = dns_name(packet, consumed)
            if consumed + 20 == end:
                return [first, second, packet[consumed:end].hex()]
        elif rrtype == 35 and len(data) >= 4:
            cursor = start + 4
            fields: list[str] = []
            for _ in range(3):
                length = packet[cursor]
                cursor += 1
                fields.append(packet[cursor : cursor + length].hex())
                cursor += length
            replacement, consumed = dns_name(packet, cursor)
            if consumed == end:
                return [data[:4].hex(), *fields, replacement]
    except (IndexError, ValueError):
        pass
    return data.hex()


def dns_semantics(row: str) -> object:
    if row == "NONE":
        return None
    packet = bytes.fromhex(row)
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    ident, flags, qd, an, ns, ar = __import__("struct").unpack_from("!6H", packet)
    pos = 12
    questions = []
    for _ in range(qd):
        name, pos = dns_name(packet, pos)
        if pos + 4 > len(packet):
            raise ValueError("truncated question")
        qtype, qclass = __import__("struct").unpack_from("!HH", packet, pos)
        pos += 4
        questions.append([name, qtype, qclass])
    sections = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        records = []
        for _ in range(count):
            owner, pos = dns_name(packet, pos)
            if pos + 10 > len(packet):
                raise ValueError("truncated RR header")
            rrtype, rrclass, ttl, rdlength = __import__("struct").unpack_from("!HHIH", packet, pos)
            start = pos + 10
            end = start + rdlength
            if end > len(packet):
                raise ValueError("truncated RR data")
            records.append([owner, rrtype, rrclass, ttl, rdata_semantics(packet, rrtype, start, end)])
            pos = end
        sections.append([section, records])
    return {"id": ident, "flags": flags, "questions": questions, "sections": sections}


def semantic_equal(c_row: str, rust_row: str) -> bool:
    return dns_semantics(c_row) == dns_semantics(rust_row)


def read_queries(path: Path) -> list[str]:
    queries = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        prefix = ""
        if line.startswith(("udp ", "tcp ")):
            prefix, line = line[:4], line[4:].strip()
        try:
            raw = bytes.fromhex(line)
        except ValueError as error:
            raise SystemExit(f"{path}:{number}: invalid query hex: {error}") from error
        if not raw:
            raise SystemExit(f"{path}:{number}: empty query")
        queries.append(prefix + raw.hex())
    return queries


def manifest(reference_build: Path) -> dict[str, object]:
    source_files = ["config.h", "rfc1035.c", "domain-match.c", "cache.c", "edns0.c"]
    source = reference_build / "dnsmasq"
    if not source.is_dir() and (reference_build / "dnsmasq.o").exists():
        source = reference_build
    return {
        "driver_sha256": sha256(DRIVER),
        "reference_build": str(reference_build.resolve()),
        "source_root": str(DEFAULT_SOURCES.resolve()),
        "source_sha256": {
            name: sha256(DEFAULT_SOURCES / name) for name in source_files if (DEFAULT_SOURCES / name).exists()
        },
        "objects": {
            path.name: sha256(path)
            for path in sorted(source.glob("*.o"))
            if path.name in {"dnsmasq.o", "rfc1035.o", "domain-match.o", "cache.o", "edns0.o"}
        },
        "copts": REFERENCE_COPTS,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True, help="exact build output directory")
    parser.add_argument("--config", type=Path, required=True, help="dnsmasq configuration used by both probes")
    parser.add_argument("--queries", type=Path, required=True, help="one raw DNS query (hex) per line")
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--rust-command", nargs="+", help="probe command; config path is appended")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    binary = build_oracle(args.reference_build.resolve(), args.work.resolve())
    queries = read_queries(args.queries)
    c_rows = run_probe(binary, args.config.resolve(), queries)
    rust_rows = run_command(args.rust_command, args.config.resolve(), queries) if args.rust_command else None
    c_semantics = [dns_semantics(row) for row in c_rows]
    rust_semantics = [dns_semantics(row) for row in rust_rows] if rust_rows is not None else None
    mismatches = []
    if rust_rows is not None:
        mismatches = [
            {
                "index": i,
                "query": queries[i],
                "c": c_rows[i],
                "rust": rust_rows[i],
                "c_semantics": c_semantics[i],
                "rust_semantics": rust_semantics[i],
            }
            for i in range(len(queries))
            if c_semantics[i] != rust_semantics[i]
        ]
    report = {
        "config": str(args.config.resolve()),
        "query_count": len(queries),
        "c_rows": c_rows,
        "c_semantics": c_semantics,
        "rust_rows": rust_rows,
        "rust_semantics": rust_semantics,
        "mismatches": mismatches,
        "identity": manifest(args.reference_build.resolve()),
    }
    output = args.work / "result.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"query_count": len(queries), "mismatches": len(mismatches), "result": str(output)}))
    return 1 if mismatches else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
