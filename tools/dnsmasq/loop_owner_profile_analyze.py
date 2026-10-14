#!/usr/bin/env python3
"""Bind profile IPs to a sectionless SDK ELF's verified executable LOAD ranges.

The OpenWrt sstrip artifact intentionally has no section table. GNU map input
sections are checked against its executable file-backed PT_LOAD range instead;
addresses and sizes still come from that artifact's exact map, never guesses.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_link_map_report import input_sections
from elf_size_report import ALLOC, EXEC, bounded, demangle
from perf_link_map_profile import analyze, check_report, samples_from_text
from r121_symbolize import parse_proc_maps


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LoadElf:
    def __init__(self, path):
        self.data = path.read_bytes()
        (ident, kind, machine, version, _, phoff, _, _, header_size,
         phsize, phcount, _, _, _) = struct.unpack('<16sHHIQQQIHHHHHH',
                                                  bounded(self.data, 0, 64, 'ELF header'))
        if (ident[:7] != b'\x7fELF\x02\x01\x01' or kind not in (2, 3)
                or machine != 183 or version != 1 or header_size != 64
                or phsize != 56 or not 0 < phcount < 0xffff):
            raise ValueError('expected ordinary ELF64 little-endian AArch64 program headers')
        bounded(self.data, phoff, phcount * phsize, 'program headers')
        self.loads = []
        # An adapter for the existing map validator; these describe executable
        # LOAD bounds, not fabricated on-disk section headers.
        self.sections = []
        for index in range(phcount):
            kind, flags, offset, address, physical, file_size, memory_size, alignment = struct.unpack_from(
                '<IIQQQQQQ', self.data, phoff + index * phsize)
            if kind != 1:
                continue
            bounded(self.data, offset, file_size, 'LOAD segment')
            if file_size > memory_size:
                raise ValueError('LOAD file extent exceeds memory extent')
            self.loads.append((flags, offset, address, physical, file_size, memory_size, alignment))
            if flags & 1:
                self.sections.append({'flags': ALLOC | EXEC, 'address': address,
                                      'size': file_size})
        if not self.sections:
            raise ValueError('no executable file-backed LOAD')
        ranges = sorted((item['address'], item['address'] + item['size']) for item in self.sections)
        if any(first[1] > second[0] for first, second in zip(ranges, ranges[1:])):
            raise ValueError('overlapping executable LOAD ranges')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    root = args.input
    artifact = root / 'dnsmasq-rs'
    elf = LoadElf(artifact)
    build = json.loads((root / 'build.json').read_text())
    identity = json.loads((root / 'process-identity.json').read_text())
    scope = json.loads((root / 'profile-scope.json').read_text())
    rows = [row for row in build['artifacts'] if row['path'] == artifact.name]
    actual = sha(artifact)
    if (len(rows) != 1 or rows[0]['sha256'] != actual or rows[0]['bytes'] != len(elf.data)
            or identity['sha256'] != actual or scope['elf_sha256'] != actual):
        raise ValueError('ELF/build/running-process/profile identity mismatch')
    if sha(root / 'link.map') != build['link_map']['sha256']:
        raise ValueError('link map does not match exact build receipt')
    before = parse_proc_maps(identity['maps'])
    after = parse_proc_maps((root / 'maps-after').read_text())
    target = identity['exe']
    executable = lambda rows: [row for row in rows if 'x' in row.permissions and row.path == target]
    if not executable(before) or executable(before) != executable(after):
        raise ValueError('executable process mapping absent or changed')
    ranges = sorted(input_sections((root / 'link.map').read_text(), elf), key=lambda row: row[1])
    if any(first[1] + first[2] > second[1] for first, second in zip(ranges, ranges[1:])):
        raise ValueError('overlapping linker input sections')
    names, demangler = demangle(sorted({row[3] for row in ranges}))
    samples = samples_from_text((root / 'samples.txt').read_text())
    totals = check_report((root / 'self.txt').read_text(), samples)
    result = analyze(samples, elf, before, identity, ranges, names)
    output = {'scope': __doc__, 'profile_scope': scope, 'elf_sha256': actual,
              'map_sha256': sha(root / 'link.map'), 'demangler': demangler,
              'totals': totals, **result,
              'limitations': ['Self instruction samples, not inclusive caller stacks or elapsed time.',
                              'Kernel/perf sampling overhead is included in the diagnostic.',
                              'Input-section ranges may contain inlined functions; no source-line attribution.',
                              'Unattributed addresses remain explicit; no nearest-symbol assignment.']}
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'totals': totals,
                      'samples_by_mode': result['samples_by_mode']}))


if __name__ == '__main__':
    main()
