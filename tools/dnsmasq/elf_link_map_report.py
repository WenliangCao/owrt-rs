#!/usr/bin/env python3
"""Attribute executable input-section bytes from a verified GNU linker map.

This measures linked input sections, not guessed function sizes or causal
feature deltas. A map-producing build must be byte-identical to its candidate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
from elf_size_report import ALLOC, EXEC, ROOT, Elf, attribute, demangle


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def input_sections(text, elf):
    _, marker, text = text.partition("Linker script and memory map")
    if not marker:
        raise ValueError("missing GNU map body")
    rows = set()
    pending = None
    for line in text.splitlines():
        start = re.match(r'^ (\.(?:text|init|fini)(?:\.\S+)?)(?=\s|$)\s*(.*)$', line)
        if start:
            pending, tail = start.groups()
        elif pending and line.startswith('                '):
            tail = line.strip()
        else:
            pending = None
            continue
        fields = re.match(r'^(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+)$', tail)
        if not fields:
            continue
        address, size = (int(value, 16) for value in fields.groups()[:2])
        name, pending = pending, None
        if not address or not size:
            continue  # Discarded input sections have address zero.
        sections = [index for index, section in enumerate(elf.sections)
                    if section['flags'] & (ALLOC | EXEC) == ALLOC | EXEC
                    and section['address'] <= address < address + size
                    <= section['address'] + section['size']]
        if len(sections) != 1:
            raise ValueError('linked executable input exceeds its ELF section')
        symbol = re.sub(r'^\.text\.(?:unlikely\.|hot\.)?', '', name)
        if symbol == name:
            symbol = '[unnamed input section]'
        rows.add((sections[0], address, size, symbol))
    if not rows:
        raise ValueError('no linked executable input sections')
    return sorted(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--map', dest='link_map', type=Path, required=True)
    parser.add_argument('--build-json', type=Path, required=True)
    parser.add_argument('--expected-elf-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / 'private'):
        parser.error('output must be fresh and below private/')
    build = json.loads(args.build_json.read_text())
    elf = Elf(args.elf)
    actual = digest(args.elf)
    artifact = next(row for row in build['artifacts'] if row['path'] == args.elf.name)
    if actual != artifact['sha256'] or actual != args.expected_elf_sha256:
        raise ValueError('map build does not match the byte-identical candidate')
    if len(elf.data) != artifact['bytes'] or digest(args.link_map) != build['link_map']['sha256']:
        raise ValueError('artifact/map identity mismatch')
    rows = input_sections(args.link_map.read_text(), elf)
    names, program = demangle(sorted({row[3] for row in rows}))
    attribution = attribute(rows, names, elf.sections)
    attribution['basis'] = 'union of verified linker executable input-section ranges'
    attribution['attributed_input_section_bytes'] = attribution.pop('attributed_function_bytes')
    attribution['limitations'] = 'Input-section owners do not identify the cause of a feature increment; shared generic code stays under its displayed namespace.' 
    report = {'kind': 'executable_linker_input_sections', 'elf_sha256': actual,
              'map_sha256': digest(args.link_map), 'file_bytes': len(elf.data),
              'demangler': program, 'attribution': attribution,
              'top_sections': [{'name': names[raw], 'address': address, 'bytes': size}
                               for _, address, size, raw in sorted(rows, key=lambda row: row[2], reverse=True)[:40]],
              'limits': 'Input sections may contain several functions or shared generic code. This is storage attribution, not a causal family delta.'}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'input_sections': len(rows), 'file_bytes': len(elf.data), 'output': str(output)}))


if __name__ == '__main__':
    main()
