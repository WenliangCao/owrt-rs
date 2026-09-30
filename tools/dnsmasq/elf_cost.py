#!/usr/bin/env python3
"""Read ELF64 little-endian file/segment/section sizes without running the ELF.

PT_LOAD ranges supply file/mapped sizes. Other program headers often overlap
them, so this tool never sums every program header as independent storage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
TYPES = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 6: "PHDR", 7: "TLS",
         0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO"}


def inspect(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"expected ELF64 little-endian: {path}")
    (_, kind, machine, _, _, phoff, shoff, _, _, phsize, phcount,
     shsize, shcount, names_index) = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if phcount and (phsize < 56 or phoff + phsize * phcount > len(data)):
        raise ValueError("program header table exceeds file")
    segments = []
    for index in range(phcount):
        type_id, flags, offset, _, _, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        if filesz > memsz or offset + filesz > len(data):
            raise ValueError("invalid segment bounds")
        segments.append({"type": TYPES.get(type_id, str(type_id)),
                         "flags": "".join(letter if flags & bit else "-" for letter, bit in (("R", 4), ("W", 2), ("X", 1))),
                         "offset": offset, "file_bytes": filesz, "memory_bytes": memsz,
                         "zero_fill": memsz - filesz, "alignment": align})
    sections = []
    if shoff and shcount:
        if shsize < 64 or shoff + shsize * shcount > len(data) or names_index >= shcount:
            raise ValueError("invalid section header table")
        entries = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize) for i in range(shcount)]
        names_offset, names_size = entries[names_index][4:6]
        if names_offset + names_size > len(data):
            raise ValueError("section-name string table exceeds file")
        names = data[names_offset:names_offset + names_size]
        for name, type_id, flags, _, offset, size, _, _, _, _ in entries:
            if name >= len(names) or (type_id != 8 and offset + size > len(data)):
                raise ValueError("invalid section bounds")
            end = names.find(b"\0", name)
            if end == -1:
                raise ValueError("unterminated section name")
            sections.append({"name": names[name:end].decode("utf-8", errors="replace"),
                             "type": type_id, "flags": flags, "size": size,
                             "file_bytes": 0 if type_id == 8 else size})
    loads = [segment for segment in segments if segment["type"] == "LOAD"]
    # Assert non-overlap before adding file ranges. Page-rounded mappings and
    # sharing/RSS/PSS cannot be inferred from these byte totals.
    spans = sorted((segment["offset"], segment["offset"] + segment["file_bytes"]) for segment in loads)
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError("overlapping PT_LOAD file ranges require separate accounting")
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "file_bytes": len(data),
            "elf_type": {1: "REL", 2: "EXEC", 3: "DYN"}.get(kind, kind), "machine": machine,
            "load_file_bytes": sum(segment["file_bytes"] for segment in loads),
            "load_memory_bytes": sum(segment["memory_bytes"] for segment in loads),
            "non_load_file_bytes": len(data) - sum(segment["file_bytes"] for segment in loads),
            "section_headers_present": bool(shoff and shcount), "segments": segments, "sections": sections,
            "scope": "ELF storage accounting only; memory byte counts are not RSS/PSS/USS or runtime peaks"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "private"):
        parser.error("output must be a new file below private/")
    report = [inspect(path.resolve()) for path in args.elf]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{k: row[k] for k in ("file_bytes", "elf_type", "load_file_bytes", "section_headers_present")} for row in report]))


if __name__ == "__main__":
    main()
