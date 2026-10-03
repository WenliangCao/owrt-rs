#!/usr/bin/env python3
"""Account for AArch64 ELF storage and sized function symbols without executing it.

Usage: elf_size_report.py stripped-elf --companion unstripped-elf --output private/.../size.json
The companion must have identical ALLOC section addresses, sizes and content.
Without real symbols this tool reports sections, never inferred crate sizes.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ALLOC, EXEC, NOBITS = 2, 4, 8
AMBIGUOUS = "[shared or overlapping]"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def bounded(data, offset, size, what):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"{what} exceeds file")
    return data[offset:offset + size]


def string_at(data, offset):
    if offset >= len(data) or offset < 0:
        raise ValueError("string offset exceeds string table")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return data[offset:end].decode("utf-8", errors="strict")


class Elf:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        header = bounded(self.data, 0, 64, "ELF header")
        (ident, kind, machine, version, entry, phoff, shoff, flags, ehsize,
         phsize, phcount, shsize, shcount, names_index) = struct.unpack("<16sHHIQQQIHHHHHH", header)
        if ident[:7] != b"\x7fELF\x02\x01\x01" or version != 1 or machine != 183:
            raise ValueError("only ELF64 little-endian AArch64 is supported")
        if kind not in (2, 3) or ehsize != 64:
            raise ValueError("expected an executable or shared ELF image")
        if not shoff or not shcount or shsize != 64 or names_index >= shcount:
            raise ValueError("a standard section table is required; extended indices are unsupported")
        bounded(self.data, shoff, shcount * shsize, "section table")
        entries = [struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + i * shsize)
                   for i in range(shcount)]
        names = entries[names_index]
        if names[1] != 3:
            raise ValueError("section names must use a string table")
        names_data = bounded(self.data, names[4], names[5], "section name table")
        self.sections = []
        for index, (name, typ, sflags, addr, offset, size, link, info, align, entsize) in enumerate(entries):
            content = b"" if typ == NOBITS else bounded(self.data, offset, size, "section")
            self.sections.append({"index": index, "name": string_at(names_data, name),
                                  "type": typ, "flags": sflags, "address": addr,
                                  "offset": offset, "size": size, "link": link,
                                  "alignment": align, "entry_bytes": entsize,
                                  "file_bytes": 0 if typ == NOBITS else size,
                                  "sha256": None if typ == NOBITS else sha256(content)})
        # Stripping can move non-ALLOC data and headers, but must not change
        # program mappings. Ignore offsets of the section table in the ELF header.
        self.loads = []
        if phcount:
            if phsize != 56 or phcount == 0xffff:
                raise ValueError("unsupported program header layout")
            bounded(self.data, phoff, phcount * phsize, "program table")
            for i in range(phcount):
                typ, pflags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
                    "<IIQQQQQQ", self.data, phoff + i * phsize)
                bounded(self.data, offset, filesz, "segment")
                if typ == 1:
                    if filesz > memsz:
                        raise ValueError("LOAD file bytes exceed memory bytes")
                    self.loads.append((pflags, offset, vaddr, paddr, filesz, memsz, align))
        self.identity = (kind, machine, entry, flags, ident[7:9].hex())
        spans = sorted((s["offset"], s["offset"] + s["file_bytes"])
                       for s in self.sections if s["flags"] & ALLOC and s["file_bytes"])
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise ValueError("overlapping ALLOC file sections are unsupported")

    def allocated(self):
        return [s for s in self.sections if s["flags"] & ALLOC]

    def verify_companion(self, companion):
        keys = ("name", "type", "flags", "address", "size", "alignment", "sha256")
        signature = lambda elf: sorted(tuple(s[k] for k in keys) for s in elf.allocated())
        if (self.identity != companion.identity or self.loads != companion.loads
                or signature(self) != signature(companion)):
            raise ValueError("companion differs: ELF identity, LOAD layout or ALLOC section address/size/content")
        return {"status": "identical_alloc_sections_and_load_layout",
                "checked_sections": len(self.allocated()), "checks": list(keys)}

    def functions(self):
        result = set()
        zero_size = 0
        for table in self.sections:
            if table["type"] not in (2, 11):  # SYMTAB or DYNSYM
                continue
            if table["entry_bytes"] != 24 or table["size"] % 24:
                raise ValueError("invalid symbol table entry size")
            if table["link"] >= len(self.sections) or self.sections[table["link"]]["type"] != 3:
                raise ValueError("invalid symbol string table")
            strings = self.sections[table["link"]]
            names = bounded(self.data, strings["offset"], strings["size"], "symbol strings")
            for offset in range(table["offset"], table["offset"] + table["size"], 24):
                name, info, other, index, address, size = struct.unpack_from("<IBBHQQ", self.data, offset)
                if info & 15 not in (2, 10) or index == 0 or index >= 0xff00:
                    continue  # Only defined FUNC/IFUNC; no guessed sizes for assembly labels.
                if index >= len(self.sections):
                    raise ValueError("symbol section index exceeds section table")
                section = self.sections[index]
                if section["flags"] & (ALLOC | EXEC) != ALLOC | EXEC:
                    continue
                if not section["address"] <= address <= address + size <= section["address"] + section["size"]:
                    raise ValueError("function exceeds its executable section")
                if not size:
                    zero_size += 1
                    continue
                result.add((index, address, size, string_at(names, name)))
        return sorted(result), zero_size


def demangle(names, program=None):
    if any("\n" in name or "\r" in name for name in names):
        raise ValueError("line breaks in symbol names are unsupported")
    if not program:
        program = shutil.which("llvm-cxxfilt")
        if not program and shutil.which("xcrun"):
            program = subprocess.run(["xcrun", "--find", "llvm-cxxfilt"], check=True,
                                     capture_output=True, text=True, timeout=10).stdout.strip()
    if not program:
        raise ValueError("llvm-cxxfilt is required for symbol attribution; pass --demangler")
    output = subprocess.run([str(program), "--no-strip-underscore"], input="\n".join(names) + "\n",
                            check=True, capture_output=True, text=True, timeout=60).stdout.splitlines()
    if len(output) != len(names):
        raise ValueError("demangler did not return one line per symbol")
    version = subprocess.run([str(program), "--version"], check=True, capture_output=True,
                             text=True, timeout=10).stdout.strip()
    return dict(zip(names, output)), {"path": str(program), "version": version}


def namespace(name):
    # Attribute the displayed owner, not a generic argument or implemented trait.
    # This deliberately leaves v0/legacy names unknown if LLVM cannot demangle them.
    name = re.sub(r"::h[0-9a-f]{16}(?:\.llvm\..*)?$", "", name)
    match = re.match(r"^<?([A-Za-z_][A-Za-z_0-9]*)::", name)
    if not match:
        group = "[unresolved Rust]" if name.startswith(("_R", "_ZN", "<")) else "[C/assembly/unmangled]"
        return group, group
    crate = match[1]
    module = re.match(r"^<?[A-Za-z_][A-Za-z_0-9]*::([A-Za-z_][A-Za-z_0-9]*)::", name)
    return crate, crate + "::" + module[1] if module else crate + "::[root]"


def attribute(functions, names, sections):
    crates, modules = Counter(), Counter()
    covered = overlapping = 0
    by_section = defaultdict(list)
    for section, address, size, raw in functions:
        by_section[section].append((address, size, names[raw]))
    for rows in by_section.values():
        events = defaultdict(list)
        for index, (address, size, name) in enumerate(rows):
            events[address].append((index, True))
            events[address + size].append((index, False))
        active, previous = set(), None
        owners = [namespace(row[2]) for row in rows]
        for position, changes in sorted(events.items()):
            if active:
                size = position - previous
                covered += size
                overlapping += size if len(active) > 1 else 0
                for level, counts in ((0, crates), (1, modules)):
                    labels = {owners[i][level] for i in active}
                    counts[next(iter(labels)) if len(labels) == 1 else AMBIGUOUS] += size
            for index, starts in changes:
                if starts:
                    active.add(index)
                else:
                    active.remove(index)
            previous = position
    executable = sum(s["size"] for s in sections if s["flags"] & (ALLOC | EXEC) == ALLOC | EXEC)
    aliases = defaultdict(set)
    for section, address, size, name in functions:
        aliases[(section, address, size)].add(names[name])
    largest = sorted(aliases, key=lambda key: (-key[2], key[1], key[0]))[:30]
    rows = lambda counts: [{"namespace": k, "bytes": v} for k, v in counts.most_common()]
    return {"basis": "union of sized FUNC/IFUNC address ranges in executable ALLOC sections",
            "executable_section_bytes": executable, "attributed_function_bytes": covered,
            "unattributed_executable_bytes": executable - covered,
            "alias_or_overlap_bytes": overlapping,
            "crates": rows(crates), "modules": rows(modules),
            "largest_ranges_non_additive": [
                {"section": sections[s]["name"], "address": addr, "declared_bytes": size,
                 "names": sorted(aliases[(s, addr, size)])} for s, addr, size in largest],
            "limitations": [
                "Crate/module means displayed symbol namespace, not source or dependency cost.",
                "LTO inlining, generic monomorphization and merged functions can cross crate boundaries.",
                "Overlapping names with different owners are marked shared; aliases are never added twice.",
                "Unsized symbols, gaps and stripped functions remain unattributed.",
                "Read-only data, unwind tables, TLS, globals and ELF overhead have no crate attribution."]}


def report(path, companion_path=None, demangler=None):
    elf = Elf(path)
    allocated = elf.allocated()
    file_bytes = sum(s["file_bytes"] for s in allocated)
    result = {"elf": {"path": str(elf.path), "sha256": sha256(elf.data), "file_bytes": len(elf.data)},
              "alloc_file_bytes": file_bytes,
              "non_alloc_and_headers_bytes": len(elf.data) - file_bytes,
              "alloc_zero_fill_bytes": sum(s["size"] for s in allocated if s["type"] == NOBITS),
              "alloc_sections": allocated,
              "scope": "Static storage and symbol ranges; no runtime RSS, heap or stack inference."}
    source = elf
    if companion_path:
        source = Elf(companion_path)
        result["companion"] = {"path": str(source.path), "sha256": sha256(source.data),
                               "file_bytes": len(source.data), **elf.verify_companion(source)}
    functions, zero_size = source.functions()
    if not functions:
        if companion_path:
            raise ValueError("companion contains no sized function symbols")
        result["attribution"] = {"status": "unavailable_no_sized_function_symbols"}
    else:
        names, program = demangle(sorted({row[3] for row in functions}), demangler)
        result["attribution"] = {"status": "available", "demangler": program,
                                 "symbol_source": "verified_companion" if companion_path else "input_elf",
                                 "sized_symbols": len(functions), "ignored_zero_size_symbols": zero_size,
                                 **attribute(functions, names, source.sections)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--companion", type=Path)
    parser.add_argument("--demangler", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "private"):
        parser.error("output must be a new file below private/")
    try:
        value = report(args.elf, args.companion, args.demangler)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"ELF size report failed: {error}\n")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"file_bytes": value["elf"]["file_bytes"], "alloc_file_bytes": value["alloc_file_bytes"],
                      "attribution": value["attribution"]["status"], "report": str(output)}))


if __name__ == "__main__":
    main()
