#!/usr/bin/env python3
"""Symbolize sampled PCs using verified ELF text and GNU ld input-section ranges.

Input is `perf script -F misc,ip,sym,dso`, one sampled PC per line (no callchain).
Use repeated --elf DSO=FILE, --linker-map DSO=FILE, --symbols-elf DSO=FILE and
--expected-sha256 DSO=HASH for each supported image. DSO is its /proc/PID/maps
pathname. ET_DYN relocation comes from that maps snapshot and ELF PT_LOADs.
For sectionless shared libraries, --dynamic-symbols DSO=FILE accepts output of
`readelf --use-dynamic --symbols -W EXACT_ELF`; --expected-sha256 is required.

Counts describe sampled PCs in emitted code, not calls or inclusive time.
Linker maps do not identify inlined callees. Same-address aliases remain grouped;
padding, unknown-size ELF functions and ambiguous ranges are never extrapolated.
"""

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import struct


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass(frozen=True)
class LoadSegment:
    flags: int
    offset: int
    address: int
    file_size: int
    memory_size: int
    alignment: int


class ELF:
    """The ELF64 little-endian subset used by the exact AArch64 artifacts."""

    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:6] != b'\x7fELF\x02\x01':
            raise ValueError(f'{path}: expected ELF64 little-endian')
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', self.data)
        self.kind, self.machine, self.entry = h[1], h[2], h[4]
        if self.kind not in (2, 3) or self.machine != 183:
            raise ValueError(f'{path}: expected AArch64 ET_EXEC or ET_DYN')
        self.sha256 = sha256(self.data)
        self.loads = []
        for i in range(h[10]):
            p = struct.unpack_from('<IIQQQQQQ', self.data, h[5] + i * h[9])
            if p[0] == 1:
                self.loads.append(LoadSegment(p[1], p[2], p[3], p[5], p[6], p[7]))
        sh = [struct.unpack_from('<IIQQQQIIQQ', self.data, h[6] + i * h[11])
              for i in range(h[12])]
        names = self.data[sh[h[13]][4]:sh[h[13]][4] + sh[h[13]][5]] if sh else b''
        self.sections = [Section(self.string(names, s[0]), s[1], s[2], s[3],
                                 s[4], s[5], s[6], s[9]) for s in sh]

    @staticmethod
    def string(data, offset):
        return data[offset:].split(b'\0', 1)[0].decode('utf-8', errors='replace')

    def section(self, name):
        return next((s for s in self.sections if s.name == name), None)

    def virtual_bytes(self, address, size):
        for p in self.loads:
            if p.address <= address and address + size <= p.address + p.memory_size:
                relative = address - p.address
                stored = max(0, min(size, p.file_size - relative))
                start = p.offset + relative
                return self.data[start:start + stored] + b'\0' * (size - stored)
        raise ValueError(f'{self.path}: range {address:#x}+{size:#x} not in PT_LOAD')


@dataclass(frozen=True)
class FunctionRange:
    start: int
    end: int
    names: tuple
    source: str
    section: str = '.text'


def merge_aliases(ranges):
    groups = defaultdict(set)
    for r in ranges:
        groups[(r.start, r.end, r.source, r.section)].update(r.names)
    return sorted((FunctionRange(a, b, tuple(sorted(names)), source, section)
                   for (a, b, source, section), names in groups.items()),
                  key=lambda r: (r.start, r.end, r.names))


def elf_function_ranges(elf):
    """Only STT_FUNC with explicit nonzero sizes fully inside .text."""
    text = elf.section('.text')
    if not text:
        raise ValueError(f'{elf.path}: symbol ELF has no .text')
    text_index = elf.sections.index(text)
    ranges = []
    for section in elf.sections:
        if section.kind not in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
            continue
        if section.entry_size != 24:
            raise ValueError(f'{elf.path}: unexpected ELF64 symbol entry size')
        strings = elf.sections[section.link]
        names = elf.data[strings.offset:strings.offset + strings.size]
        for offset in range(section.offset, section.offset + section.size, 24):
            name, info, _other, index, address, size = struct.unpack_from(
                '<IBBHQQ', elf.data, offset)
            if info & 15 != 2 or index != text_index or size == 0:
                continue
            if text.address <= address and address + size <= text.address + text.size:
                ranges.append(FunctionRange(address, address + size,
                                            (elf.string(names, name),), 'elf_stt_func'))
    return merge_aliases(ranges)


def dynamic_symbol_ranges(text, elf):
    """Import readelf dynamic FUNC ranges; hidden functions remain unknown.

    The caller supplies readelf output from the exact ELF, records both hashes,
    and checks the expected ELF identity. No symbol sizes are inferred.
    """
    rows = re.compile(r'^\s*\d+:\s+([0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|\d+)\s+'
                      r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?\s*$')
    expected_rows, row_count, ranges = None, 0, []
    for line in text.splitlines():
        count = re.search(r'Symbol table .* contains (\d+) entries:', line)
        if count:
            if expected_rows is not None:
                raise ValueError('expected one readelf dynamic symbol table')
            expected_rows = int(count[1])
        if not re.match(r'^\s*\d+:', line):
            continue
        match = rows.fullmatch(line)
        if not match:
            raise ValueError(f'unrecognized readelf symbol row: {line!r}')
        row_count += 1
        address = int(match[1], 16)
        size = int(match[2], 16 if match[2].startswith('0x') else 10)
        if match[3] != 'FUNC' or size == 0 or not match[6].isdigit():
            continue
        name = re.sub(r'\s+\(\d+\)$', '', match[7] or '').strip()
        if not name:
            continue
        if any(p.flags & 1 and p.address <= address and
               address + size <= p.address + p.file_size for p in elf.loads):
            ranges.append(FunctionRange(address, address + size, (name,),
                                        'readelf_dynamic_stt_func', 'executable PT_LOAD'))
    if expected_rows is None or expected_rows != row_count:
        raise ValueError(f'incomplete readelf table: expected {expected_rows}, read {row_count}')
    return merge_aliases(ranges)


@dataclass
class Contribution:
    section: str
    start: int
    size: int
    labels: list = field(default_factory=list)


def linker_map_ranges(text, text_start, text_size):
    """Read GNU bfd ld Map output; input sections bound every returned range.

    Discarded sections are ignored. No nearest-symbol/next-symbol size guesses.
    Generic .text contributions with several distinct label addresses are left
    unknown because a map does not tell functions from internal assembly labels.
    """
    output = re.compile(r'^\.text\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s*$')
    section_line = re.compile(r'^ (\.(?:text(?:\.[^\s]+)?|gnu\.linkonce\.t\.[^\s]+))'
                              r'(?:\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+.+)?\s*$')
    continuation = re.compile(r'^\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+.+$')
    symbol = re.compile(r'^\s+(0x[0-9a-fA-F]+)\s+([^\s].*)$')
    active, pending, current = False, None, None
    contributions = []
    found = 0
    for line in text.splitlines():
        match = output.match(line)
        if match:
            found += 1
            if (int(match[1], 16), int(match[2], 16)) != (text_start, text_size):
                raise ValueError('linker Map output .text differs from exact ELF')
            active = True
            continue
        if not active:
            continue
        if line and not line[0].isspace():
            active = False
            continue
        match = section_line.match(line)
        if match:
            current = None
            pending = match[1]
            if match[2] is None:
                continue
            current = Contribution(pending, int(match[2], 16), int(match[3], 16))
            contributions.append(current)
            pending = None
            continue
        match = continuation.match(line)
        if pending and match:
            current = Contribution(pending, int(match[1], 16), int(match[2], 16))
            contributions.append(current)
            pending = None
            continue
        match = symbol.match(line)
        if current and match:
            name = match[2].strip()
            if not name.startswith('0x') and not any(x in name for x in (' = ', 'PROVIDE', 'LOAD ')):
                current.labels.append((int(match[1], 16), name))
        elif line.lstrip().startswith('*fill*'):
            current = None
    if found != 1:
        raise ValueError(f'expected one output .text in linker Map, found {found}')
    ranges = []
    for c in contributions:
        if c.size == 0:
            continue
        if not (text_start <= c.start < c.start + c.size <= text_start + text_size):
            raise ValueError(f'input section outside .text: {c.section}')
        name = re.sub(r'^\.(?:text\.|gnu\.linkonce\.t\.)', '', c.section)
        name = re.sub(r'^(?:unlikely|hot|startup|exit)\.', '', name)
        named_section = name not in ('.text', 'unlikely', 'hot', 'startup', 'exit')
        labels = {(a, n) for a, n in c.labels if c.start <= a < c.start + c.size}
        at_start = {n for a, n in labels if a == c.start}
        if named_section:
            # Explicit start aliases are authoritative; section names such as
            # .text.dummy can differ from the exported function name.
            names = at_start or {name}
        elif at_start and {a for a, _ in labels} == {c.start}:
            names = at_start
        else:
            continue
        ranges.append(FunctionRange(c.start, c.start + c.size, tuple(sorted(names)),
                                    'linker_input_section', c.section))
    return merge_aliases(ranges)


@dataclass(frozen=True)
class ProcessMapping:
    start: int
    end: int
    permissions: str
    offset: int
    path: str


def parse_proc_maps(text):
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = re.fullmatch(r'([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxps-]{4})\s+'
                             r'([0-9a-fA-F]+)\s+[0-9a-fA-F]+:[0-9a-fA-F]+\s+\d+'
                             r'(?:\s+(.*))?', line)
        if not match:
            raise ValueError(f'proc maps line {number}: unrecognized format')
        result.append(ProcessMapping(int(match[1], 16), int(match[2], 16), match[3],
                                     int(match[4], 16), match[5] or ''))
    return result


def runtime_to_elf_address(ip, mapping, elf, page_size=4096):
    if not mapping.start <= ip < mapping.end or 'x' not in mapping.permissions:
        raise ValueError('sample does not belong to an executable mapping')
    candidates = set()
    for p in elf.loads:
        first = p.offset // page_size * page_size
        last = (p.offset + p.file_size + page_size - 1) // page_size * page_size
        if p.flags & 1 and first <= mapping.offset < last:
            address = ip - mapping.start + mapping.offset - p.offset + p.address
            if p.address <= address < p.address + p.memory_size:
                candidates.add(address)
    if len(candidates) != 1:
        raise ValueError('mapping offset does not identify one executable PT_LOAD')
    return candidates.pop()


def lookup_function(ranges, address):
    matches = [r for r in ranges if r.start <= address < r.end]
    if not matches:
        return None, 'no_function_range'
    if len(matches) != 1:
        return None, 'overlapping_function_ranges'
    return matches[0], None


@dataclass(frozen=True)
class PerfSample:
    mode: str
    ip: int
    reported_symbol: str
    dso: str


def parse_perf_script(text):
    """Do not trust perf's symbol text; only use raw PCs and reported DSO."""
    samples = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([KUHGg][MESp]*)\s+([0-9a-fA-F]+)\s+(.+?)\s+\((.*)\)\s*', line)
        if not match:
            raise ValueError(f'perf script line {number}: expected -F misc,ip,sym,dso without callchains')
        samples.append(PerfSample(match[1], int(match[2], 16), match[3], match[4]))
    return samples


def clean_dso(path):
    return path.removesuffix(' (deleted)')


def sample_report(samples, mappings, images, top=30):
    counts, unknown = Counter(), Counter()
    unknown_ips = Counter()
    modes, non_user_symbols = Counter(), Counter()
    details = {}
    for sample in samples:
        ip, dso = sample.ip, sample.dso
        modes[sample.mode[0]] += 1
        if sample.mode[0] != 'U':
            non_user_symbols[(sample.mode[0], dso, sample.reported_symbol)] += 1
            continue
        matching = [m for m in mappings if m.start <= ip < m.end and 'x' in m.permissions]
        reason = None
        if len(matching) != 1:
            reason = 'no_unique_executable_mapping'
        else:
            mapping = matching[0]
            path = clean_dso(mapping.path)
            # The maps address range identifies the image; reject conflicting
            # perf DSO names but allow perf's usual basename or [unknown].
            if dso not in ('[unknown]', '[unknown] (deleted)') and clean_dso(dso) not in (path, Path(path).name):
                reason = 'perf_dso_mapping_mismatch'
            elif path not in images:
                reason = 'image_not_configured'
            else:
                image = images[path]
                try:
                    address = runtime_to_elf_address(ip, mapping, image['elf'])
                    r, reason = lookup_function(image['ranges'], address)
                except ValueError:
                    reason = 'mapping_load_segment_mismatch'
                if reason is None:
                    key = (path, r.start, r.end, r.names)
                    counts[key] += 1
                    details[key] = {'dso': path, 'start': hex(r.start), 'end': hex(r.end),
                                    'names': list(r.names), 'alias_group': len(r.names) > 1,
                                    'source': r.source, 'input_section': r.section}
        if reason:
            unknown[reason] += 1
            unknown_ips[(reason, dso, ip)] += 1
    total = len(samples)
    user_count = modes['U']
    return {'schema_version': 1, 'sample_count': total, 'samples_by_mode': dict(modes),
            'user_sample_count': user_count,
            'symbolized_count': sum(counts.values()), 'unknown_count': sum(unknown.values()),
            'unknown_fraction_of_user_samples': sum(unknown.values()) / user_count if user_count else None,
            'unknown_reasons': dict(unknown),
            'top_functions': [{**details[k], 'sample_count': n,
                               'fraction_of_all_samples': n / total,
                               'fraction_of_user_samples': n / user_count}
                              for k, n in counts.most_common(top)],
            'top_unknown_ips': [{'reason': r, 'dso': d, 'ip': hex(ip), 'sample_count': n}
                                for (r, d, ip), n in unknown_ips.most_common(top)],
            'non_user_perf_symbols': [{'mode': mode, 'dso': dso, 'reported_symbol': name,
                                       'sample_count': n}
                                      for (mode, dso, name), n in non_user_symbols.most_common(top)],
            'interpretation': 'Sampled emitted-code PCs only; no inline attribution or call counts. '
                              'Alias names share a single count. Padding is not assigned.'}


def pairs(values):
    result = {}
    for value in values:
        key, separator, item = value.partition('=')
        if not separator or not key or not item or key in result:
            raise ValueError(f'expected unique DSO=VALUE, got {value!r}')
        result[key] = item
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--perf-script', required=True, type=Path)
    parser.add_argument('--proc-maps', required=True, type=Path)
    parser.add_argument('--elf', action='append', default=[], required=True, metavar='DSO=FILE')
    parser.add_argument('--linker-map', action='append', default=[], metavar='DSO=FILE')
    parser.add_argument('--symbols-elf', action='append', default=[], metavar='DSO=FILE')
    parser.add_argument('--dynamic-symbols', action='append', default=[], metavar='DSO=FILE')
    parser.add_argument('--expected-sha256', action='append', default=[], metavar='DSO=HASH')
    parser.add_argument('--top', type=int, default=30)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    paths, maps, symbols, dynamic, hashes = map(pairs, (args.elf, args.linker_map,
                                                      args.symbols_elf, args.dynamic_symbols,
                                                      args.expected_sha256))
    if (set(maps) | set(symbols) | set(dynamic) | set(hashes)) - set(paths):
        raise ValueError('symbol or hash DSO has no --elf entry')
    if set(dynamic) - set(hashes):
        raise ValueError('--dynamic-symbols requires --expected-sha256 for the exact ELF')
    images, evidence = {}, {}
    for dso, path in paths.items():
        elf = ELF(path)
        if dso in hashes and elf.sha256 != hashes[dso]:
            raise ValueError(f'{dso}: exact ELF SHA256 mismatch')
        if sum(dso in source for source in (maps, symbols, dynamic)) > 1:
            raise ValueError(f'{dso}: choose one symbol source')
        if dso in dynamic:
            raw = Path(dynamic[dso]).read_bytes()
            ranges = dynamic_symbol_ranges(raw.decode(), elf)
            images[dso] = {'elf': elf, 'ranges': ranges}
            evidence[dso] = {
                'elf_sha256': elf.sha256, 'expected_sha256_checked': True,
                'dynamic_symbols_sha256': sha256(raw), 'function_range_count': len(ranges),
                'symbol_scope': 'Defined dynamic FUNC exports only; hidden functions unavailable.',
                'executable_segments': [{'start': hex(p.address), 'file_size': p.file_size,
                                         'memory_size': p.memory_size, 'offset': p.offset,
                                         'sha256': sha256(elf.virtual_bytes(p.address, p.file_size))}
                                        for p in elf.loads if p.flags & 1]}
            continue
        symbol_elf = ELF(symbols[dso]) if dso in symbols else elf
        section = symbol_elf.section('.text')
        if not section or not section.flags & 4:
            raise ValueError(f'{dso}: symbol ELF needs executable .text')
        exact_text = elf.virtual_bytes(section.address, section.size)
        symbol_text = symbol_elf.virtual_bytes(section.address, section.size)
        if exact_text != symbol_text or elf.kind != symbol_elf.kind:
            raise ValueError(f'{dso}: symbol ELF .text differs from exact ELF')
        ranges = (linker_map_ranges(Path(maps[dso]).read_text(), section.address, section.size)
                  if dso in maps else elf_function_ranges(symbol_elf))
        images[dso] = {'elf': elf, 'ranges': ranges}
        evidence[dso] = {'elf_sha256': elf.sha256, 'expected_sha256_checked': dso in hashes,
                         'symbol_elf_sha256': symbol_elf.sha256, 'text_sha256': sha256(exact_text),
                         'text_start': hex(section.address), 'text_size': section.size,
                         'function_range_count': len(ranges),
                         'map_sha256': sha256(Path(maps[dso]).read_bytes()) if dso in maps else None}
    result = sample_report(parse_perf_script(args.perf_script.read_text()),
                           parse_proc_maps(args.proc_maps.read_text()), images, args.top)
    result['images'] = evidence
    result['inputs'] = {str(p): sha256(p.read_bytes()) for p in (args.perf_script, args.proc_maps)}
    output = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
