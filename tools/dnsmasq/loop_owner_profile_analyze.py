#!/usr/bin/env python3
"""Bind profile IPs to a sectionless SDK ELF's verified executable LOAD ranges.

The OpenWrt sstrip artifact intentionally has no section table. GNU map input
sections are checked against its executable file-backed PT_LOAD range instead;
addresses and sizes still come from that artifact's exact map, never guesses.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from elf_link_map_report import input_sections
from elf_size_report import ALLOC, EXEC, NOBITS, Elf, bounded, demangle
from perf_link_map_profile import check_report, elf_address, samples_from_text
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


EVENTS = ('instructions:u', 'instructions:k', 'cycles:u', 'cycles:k')


def sample_read_metadata(raw, attributes, samples, period):
    """Bind :S exported read deltas to the configured hardware period."""
    event_lines = [line for line in attributes.splitlines() if line.startswith(samples[0].event + ':')]
    if (len(event_lines) != 1 or f'{{ sample_period, sample_freq }}: {period},' not in event_lines[0]
            or 'sample_type: IP|TID|TIME|READ|' not in event_lines[0]
            or 'read_format: TOTAL_TIME_ENABLED|TOTAL_TIME_RUNNING|ID|LOST' not in event_lines[0]
            or 'exclude_kernel: 1' not in event_lines[0]):
        raise ValueError('sample read attributes do not match the frozen user event')
    periods = [int(value) for value in re.findall(r'PERF_RECORD_SAMPLE\([^\n]+ period: (\d+) addr:', raw)]
    enabled = [int(value, 16) for value in re.findall(r'^\.+ time enabled ([0-9a-f]+)$', raw, re.M)]
    running = [int(value, 16) for value in re.findall(r'^\.+ time running ([0-9a-f]+)$', raw, re.M)]
    reads = re.findall(r'^\.+ id ([0-9a-f]+), value ([0-9a-f]+), lost (\d+)$', raw, re.M)
    if not (len(periods) == len(enabled) == len(running) == len(reads) == len(samples)):
        raise ValueError('sample read metadata count differs from exported samples')
    previous = {}
    for index, (identifier, value, lost) in enumerate(reads):
        value = int(value, 16)
        delta = value - previous.get(identifier, 0)
        if (periods[index] != period or int(lost) or enabled[index] <= 0
                or enabled[index] != running[index] or delta != samples[index].period):
            raise ValueError('sample read delta, period, lost or running time mismatch')
        previous[identifier] = value
    return {'read_samples': len(reads), 'all_observed_enabled_equal_running': True,
            'configured_period': period, 'exported_weight': 'Exact consecutive per-event raw READ count deltas',
            'observed_weight_range': [min(row.period for row in samples), max(row.period for row in samples)],
            'last_observed_time_enabled_ns': enabled[-1], 'last_observed_time_running_ns': running[-1],
            'counter_values_by_event_id': previous,
            'limit': 'Timing metadata is recorded at samples, not a separate final counter read; zero THROTTLE is checked independently.'}


def stat_counts(text, verbose, pid, operations):
    """Retain perf's raw read values separately from its possibly scaled CSV."""
    attrs = verbose.split('perf_event_attr:')[1:]
    opened = re.findall(r'sys_perf_event_open: pid (\d+)\s+cpu -1\s+group_fd (-?\d+)\s+flags \S+ = (\d+)', verbose)
    if (len(attrs) != 4 or len(opened) != 4
            or any(not re.search(r'^\s*inherit\s+1\s*$', block, re.M) for block in attrs)
            or any(int(row[0]) != pid for row in opened)
            or opened[0][1] != '-1'
            or any(row[1] != opened[0][2] for row in opened[1:])):
        raise ValueError('expected four inherited events in one root-PID group')
    for index, block in enumerate(attrs):
        excluded = 'exclude_kernel' if index % 2 == 0 else 'exclude_user'
        if not re.search(r'^\s*' + excluded + r'\s+1\s*$', block, re.M):
            raise ValueError('wrong user/kernel event privilege filter')
    rows = {}
    for fields in csv.reader(text.splitlines()):
        if len(fields) < 5 or fields[2] not in EVENTS:
            continue
        event = fields[2]
        if event in rows or not re.fullmatch(r'\d+(?:\.\d+)?', fields[0]):
            raise ValueError('duplicate, unsupported or uncounted event')
        raw = re.findall(r'^' + re.escape(event) + r': (\d+) (\d+) (\d+)\s*$', text, re.M)
        reads = re.findall(r'^' + re.escape(event) + r': (-?\d+): (\d+) (\d+) (\d+)\s*$', text, re.M)
        if len(raw) != 1 or not reads:
            raise ValueError('missing unscaled value/time-enabled/time-running diagnostic')
        count, enabled, running = map(int, raw[0])
        reported = float(fields[0])
        if not 0 < running <= enabled or abs(float(fields[4]) - 100 * running / enabled) > .011:
            raise ValueError('invalid running fraction')
        if abs(reported - count * enabled / running) > max(1, reported * 1e-8):
            raise ValueError('CSV count disagrees with raw count and scaling')
        rows[event] = {'reported_count': reported, 'raw_count': count,
                       'time_enabled_ns': enabled, 'time_running_ns': running,
                       'csv_runtime_ns': int(fields[3]), 'csv_running_percent': float(fields[4]),
                       'scaled': enabled != running, 'scale_factor': enabled / running,
                       'per_operation': reported / operations,
                       'raw_reads': [list(map(int, item)) for item in reads]}
    if set(rows) != set(EVENTS):
        raise ValueError('missing required stat event')
    return {'events': rows, 'inherit': True, 'one_group': True,
            'all_unscaled': all(not row['scaled'] for row in rows.values())}


def c_companion_ranges(artifact, companion, receipt):
    """Recheck all allocated bytes; sstrip -z may move trailing zeroes to BSS."""
    target, full = LoadElf(artifact), Elf(companion)
    if (sha(artifact) != receipt['stripped_sha256']
            or sha(companion) != receipt['companion_sha256']):
        raise ValueError('C symbol receipt hash mismatch')
    if len(target.loads) != len(full.loads):
        raise ValueError('C companion LOAD count changed')
    for stripped, original in zip(target.loads, full.loads):
        if any(stripped[i] != original[i] for i in (0, 1, 2, 3, 5, 6)) or stripped[4] > original[4]:
            raise ValueError('C companion LOAD layout changed')
    checked = []
    for section in full.allocated():
        start, size = section['address'], section['size']
        matches = [load for load in target.loads if load[2] <= start and start + size <= load[2] + load[5]]
        if len(matches) != 1:
            raise ValueError('C ALLOC section has no unique LOAD')
        load = matches[0]
        if section['flags'] & EXEC and not load[0] & 1:
            raise ValueError('C executable ALLOC section lost executable LOAD')
        offset = load[1] + start - load[2]
        backed = max(0, min(size, load[1] + load[4] - offset))
        actual = target.data[offset:offset + backed] + bytes(size - backed)
        expected = bytes(size) if section['type'] == NOBITS else full.data[section['offset']:section['offset'] + size]
        if actual != expected:
            raise ValueError('C companion ALLOC section content changed: ' + section['name'])
        checked.append(section['name'])
    functions, zero = full.functions()
    return functions, {'checked_alloc_sections': checked, 'defined_sized_functions': len(functions),
                       'zero_size_functions_unattributed': zero}


def dynamic_ranges(path, elf):
    """Read defined sized dynamic symbols from the exact sectionless library."""
    result = subprocess.run(['readelf', '-W', '-D', '-s', str(path)], check=True,
                            capture_output=True, text=True)
    ranges, zero = set(), 0
    for line in result.stdout.splitlines():
        match = re.fullmatch(r'\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(FUNC|IFUNC)\s+\S+\s+\S+\s+(\S+)\s+(\S+)(?:\s+\(\d+\))?\s*', line)
        if not match or match[4] in ('UND', 'ABS'):
            continue
        address, size, name = int(match[1], 16), int(match[2]), match[5]
        if not size:
            zero += 1
            continue
        if not any(flags & 1 and start <= address < address + size <= start + file_size
                   for flags, _, start, _, file_size, _, _ in elf.loads):
            raise ValueError('dynamic function outside executable LOAD')
        ranges.add((0, address, size, name))
    return sorted(ranges), {'defined_sized_functions': len(ranges),
                            'zero_size_functions_unattributed': zero,
                            'readelf_stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest()}


def task_tree(text, root_pid, mappings, samples):
    """Admit descendants only through observed forks, never numeric PID guesses."""
    parents, active, exited, sample_counts = {root_pid: None}, {root_pid}, set(), Counter()
    comms, mmap_count = [], 0
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if 'PERF_RECORD_' not in line:
            match = re.match(r'\s*(\d+)/(\d+)\s+\S+\s+[\d.]+:\s+(\S+):\s+([0-9a-fA-F]+)\b', line)
            if not match:
                raise ValueError('unrecognized timestamped sample: ' + line)
            pid, tid, event, ip = match.groups()
            if int(pid) not in active or int(tid) != int(pid):
                raise ValueError('sample has no active single-thread fork lineage')
            sample_counts[(int(pid), int(tid), event, int(ip, 16))] += 1
            continue
        if 'PERF_RECORD_FORK' in line or 'PERF_RECORD_EXIT' in line:
            match = re.search(r'PERF_RECORD_(FORK|EXIT)\s*\((\d+):(\d+)\):\((\d+):(\d+)\)', line)
            if not match:
                raise ValueError('unrecognized fork/exit event: ' + line)
            kind, pid, tid, parent, ptid = match.groups()
            pid, tid, parent, ptid = map(int, (pid, tid, parent, ptid))
            if pid != tid or parent != ptid:
                raise ValueError('unexpected thread fork in single-thread workload')
            if kind == 'FORK':
                if pid in parents or parent not in active:
                    raise ValueError('duplicate or orphan fork event')
                parents[pid] = parent
                active.add(pid)
            else:
                if pid not in active or pid == root_pid or parents[pid] != parent:
                    raise ValueError('unexpected exit event')
                active.remove(pid)
                exited.add(pid)
        elif 'PERF_RECORD_COMM' in line:
            match = re.search(r'PERF_RECORD_COMM:\s+(.*):(\d+)/(\d+)\s*$', line)
            if not match or 'exec' in line.split('PERF_RECORD_COMM', 1)[1].split(':', 1)[0]:
                raise ValueError('unexpected exec or malformed COMM record')
            name, pid, tid = match.groups()
            if int(pid) not in active or pid != tid:
                raise ValueError('COMM has no active process lineage')
            comms.append({'pid': int(pid), 'name': name})
        elif 'PERF_RECORD_MMAP' in line:
            match = re.search(r'PERF_RECORD_MMAP2?\s+(-?\d+)/(-?\d+):\s+\[(0x[0-9a-f]+)\((0x[0-9a-f]+)\)\s+@\s+(0x[0-9a-f]+|0)\b.*?\]:\s+([rwxps-]+)\s+(.*)$', line)
            if not match:
                raise ValueError('unrecognized mmap event: ' + line)
            pid, tid, start, size, offset, permissions, path = match.groups()
            pid, tid = int(pid), int(tid)
            if pid in (-1, 0xffffffff):
                continue  # perf synthesized kernel maps, never user attribution.
            if pid not in active or pid != tid:
                raise ValueError('MMAP has no active process lineage')
            start, size, offset = int(start, 16), int(size, 16), int(offset, 16)
            if 'x' in permissions and not any(
                    row.start == start and row.end == start + size and row.offset == offset
                    and row.permissions == permissions and row.path == path for row in mappings):
                raise ValueError('new executable map differs from inherited identity: ' + line)
            mmap_count += 1
        else:
            raise ValueError('unexpected task/lost record: ' + line)
    expected = Counter((row.pid, row.tid, row.event, row.ip) for row in samples)
    if sample_counts != expected:
        raise ValueError('timestamped task export and sample export differ')
    if active != {root_pid} or exited != set(parents) - {root_pid}:
        raise ValueError('descendant exit records incomplete at fixed grace')
    return {'root_pid': root_pid, 'parents': parents, 'exited_children': sorted(exited),
            'sample_pids': sorted({row.pid for row in samples}), 'comm_records': comms,
            'mmap_records': mmap_count, 'all_samples_bound_to_fork_tree': True}


def attribute_samples(samples, mappings, images):
    groups = defaultdict(lambda: {'samples': 0, 'period': 0})
    modes, dsos = Counter(), Counter()
    for row in samples:
        modes[row.mode] += row.period
        if row.mode != 'U':
            key = ('non_user_pc_unattributed', row.dso, row.mode + ':' + row.symbol, ())
            group = groups[key]
            group['samples'] += 1
            group['period'] += row.period
            dsos[row.dso] += row.period
            continue
        matches = [mapping for mapping in mappings
                   if 'x' in mapping.permissions and mapping.start <= row.ip < mapping.end]
        if len(matches) != 1:
            key = ('user_unattributed', row.dso, 'no_unique_executable_mapping', ())
        else:
            mapping = matches[0]
            path = mapping.path
            if row.dso not in ('[unknown]', path, Path(path).name):
                raise ValueError('sample DSO conflicts with inherited mapping')
            if path not in images:
                key = ('user_unattributed', path, 'unattributed_image', ())
            else:
                elf, ranges, names = images[path]
                address = elf_address(elf, mapping, row.ip)
                owners = {(start, size, names.get(raw, raw)) for _, start, size, raw in ranges
                          if start <= address < start + size}
                if len(owners) == 1:
                    start, size, name = owners.pop()
                    key = ('user_attributed', path, name, (hex(start), hex(start + size)))
                elif owners:
                    key = ('user_shared_or_overlapping', path,
                           ' | '.join(sorted({owner[2] for owner in owners})), ())
                else:
                    key = ('user_unattributed', path, 'no_sized_symbol_or_input_section', ())
        group = groups[key]
        group['samples'] += 1
        group['period'] += row.period
        dsos[key[1]] += row.period
    total = sum(row.period for row in samples)
    rows = [{'category': key[0], 'dso': key[1], 'label': key[2], 'elf_range': key[3] or None,
             **value, 'percent_all_period': 100 * value['period'] / total}
            for key, value in sorted(groups.items(), key=lambda item: (-item[1]['period'], item[0]))]
    return {'period_by_mode': dict(modes), 'period_by_dso': dict(dsos), 'ranges': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--demangler')
    parser.add_argument('--expected-elf-sha256', help='explicit exact Rust artifact; original C/E defaults remain')
    parser.add_argument('--minimum-samples', type=int, default=0)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be fresh')
    root = args.input
    build = json.loads((root / 'build.json').read_text())
    identity = json.loads((root / 'process-identity.json').read_text())
    scope = json.loads((root / 'profile-scope.json').read_text())
    complete = json.loads((root / 'complete.json').read_text())
    tail = json.loads((root / 'tree-tail.json').read_text())
    counts = (500, 2000) if scope['mode'] == 'dhcp' else (1000, 4000)
    operations = sum(counts)
    if scope['mode'] == 'dhcp' and (scope['rate'] != 100 or not scope.get('fixed_device_counts')):
        raise ValueError('DHCP requires the fixed device fixture and count validation')
    if (complete.get('completed_operations') != operations or not complete.get('tree_tail_complete')
            or not tail['complete'] or tail['remaining_children']
            or tail['root_pid'] != identity['pid']):
        raise ValueError('incomplete fixed-operation whole-tree capture')
    artifact = root / scope['artifact_file']
    actual = sha(artifact)
    pinned = {'dnsmasq-c': '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
              'dnsmasq-rs': '8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27'}
    if args.expected_elf_sha256:
        if not re.fullmatch('[0-9a-f]{64}', args.expected_elf_sha256):
            raise ValueError('invalid exact artifact SHA256')
        pinned['dnsmasq-rs'] = args.expected_elf_sha256
    rows = [row for row in build['artifacts'] if row['path'] == artifact.name]
    if (actual != pinned.get(artifact.name) or len(rows) != 1 or rows[0]['sha256'] != actual
            or rows[0]['bytes'] != artifact.stat().st_size or scope['elf_sha256'] != actual):
        raise ValueError('ELF/build/profile identity mismatch')
    expected = scope['mapped_images']
    if (expected != identity['mapped_images'] or expected.get(str(artifact)) != actual
            or expected.get(identity['exe']) != identity['sha256']):
        raise ValueError('artifact/loader/mapping identity mismatch')
    from loop_owner_profile import verify_mapped_files
    before = parse_proc_maps(identity['maps'])
    after_text = (root / 'maps-after').read_text()
    after = parse_proc_maps(after_text)
    executable = lambda rows: [row for row in rows if 'x' in row.permissions]
    if not executable(before) or executable(before) != executable(after):
        raise ValueError('executable process mapping absent or changed')
    mapped = verify_mapped_files(identity['maps'], expected)
    if (mapped != identity['mapped_file_identity']
            or verify_mapped_files(after_text, expected) != mapped
            or json.loads((root / 'mapped-files-after.json').read_text()) != mapped):
        raise ValueError('mapped executable or data identity changed')
    client = json.loads((root / 'client.json').read_text())
    if client['interrupted'] or client['output_failed']:
        raise ValueError('interrupted or incomplete client output')
    for phase, count in zip(('warmup', 'measurement'), counts):
        part = client[phase]
        if (any(part[key] != count for key in ('scheduled', 'sent', 'correct'))
                or any(part[key] for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))):
            raise ValueError('client completion/error counts violate frozen workload')
    if scope.get('fixed_device_counts'):
        validation = json.loads((root / 'fixed-count-validation.json').read_text())
        if validation['errors']:
            raise ValueError('fixed fixture validation failed')
    output = {'scope': 'Excluded exact-artifact owner diagnostic; stat and user self samples remain separate',
              'profile_scope': scope, 'elf_sha256': actual, 'completed_operations': operations,
              'source_files': {name: sha(root / name) for name in (
                  'process-identity.json', 'profile-scope.json', 'build.json', 'complete.json',
                  'tree-tail.json', 'client.json', 'maps-after', 'mapped-files-after.json')}}
    if scope['observer'] == 'stat':
        result = stat_counts((root / 'perf-stat.csv').read_text(),
                             (root / 'perf-stat.stderr').read_text(), identity['pid'], operations)
        if not result['all_unscaled']:
            raise ValueError('multiplexed/scaled stat window; raw result retained')
        output.update(result)
        output['source_files'].update({name: sha(root / name) for name in ('perf-stat.csv', 'perf-stat.stderr')})
    elif scope['observer'] == 'sample':
        images, symbols, demangler = {}, {}, None
        for path, digest in expected.items():
            image_path = Path(path)
            if sha(image_path) != digest:
                raise ValueError('mapped image changed before analysis')
            elf = LoadElf(image_path)
            if image_path == artifact and artifact.name == 'dnsmasq-c':
                receipt = json.loads((root / 'c-symbol-receipt.json').read_text())
                if sha(root / 'c-symbol-receipt.json') != build['symbol_receipt_sha256']:
                    raise ValueError('C receipt changed after capture')
                ranges, proof = c_companion_ranges(artifact, root / 'dnsmasq-c-symbols', receipt)
                names = {}
            elif image_path == artifact:
                if sha(root / 'link.map') != build['link_map']['sha256']:
                    raise ValueError('link map differs from exact build')
                ranges = sorted(input_sections((root / 'link.map').read_text(), elf), key=lambda row: row[1])
                if any(a[1] + a[2] > b[1] for a, b in zip(ranges, ranges[1:])):
                    raise ValueError('overlapping linker input sections')
                names, demangler = demangle(sorted({row[3] for row in ranges}), args.demangler)
                proof = {'kind': 'same-build linker input sections', 'map_sha256': sha(root / 'link.map')}
            else:
                ranges, proof = dynamic_ranges(image_path, elf)
                names = {}
            images[path] = (elf, ranges, names)
            symbols[path] = proof
        samples = samples_from_text((root / 'samples.txt').read_text())
        if (scope['sample_event'] not in ('instructions:u', 'cycles:u', 'instructions:uS', 'cycles:uS')
                or any(row.event != scope['sample_event'] for row in samples)):
            raise ValueError('unexpected sampling event or period')
        if scope.get('sample_running_time'):
            output['sample_read_metadata'] = sample_read_metadata(
                (root / 'raw-records.txt').read_text(), (root / 'event-attributes.txt').read_text(),
                samples, scope['sample_period'])
        elif any(row.period != scope['sample_period'] for row in samples):
            raise ValueError('unexpected fixed sampling period')
        totals = check_report((root / 'self.txt').read_text(), samples)
        lineage = task_tree((root / 'task-events.txt').read_text(), identity['pid'], before, samples)
        result = attribute_samples(samples, before, images)
        output.update(totals=totals, process_tree=lineage, symbols=symbols, demangler=demangler, **result)
        output['source_files'].update({name: sha(root / name) for name in ('samples.txt', 'self.txt', 'task-events.txt')})
        raw_path = root / 'raw-records.txt'
        if raw_path.exists():
            footer = raw_path.read_text().rsplit('Aggregated stats:', 1)[1]
            records = {name: int(count) for name, count in re.findall(r'^\s*(\S+) events:\s+(\d+)', footer, re.M)}
            valid = (not any(records.get(name, 0) for name in ('THROTTLE', 'UNTHROTTLE', 'LOST', 'LOST_SAMPLES'))
                     and totals['samples'] >= args.minimum_samples)
            output['sampling_coverage'] = {'records': records, 'minimum_samples': args.minimum_samples,
                                           'eligible_for_coarse_hotspots': valid}
            output['source_files']['raw-records.txt'] = sha(raw_path)
            output['source_files']['event-attributes.txt'] = sha(root / 'event-attributes.txt')
            if not valid:
                args.output.write_text(json.dumps(output, indent=2) + '\n')
                raise ValueError('sampling throttled, lost records or insufficient samples; full ranking retained')
        elif args.minimum_samples:
            raise ValueError('sampling coverage metadata missing')
        output['limitations'] = [
            'Self user event samples, not inclusive caller stacks, elapsed time or kernel cost.',
            'Non-user PCs from a user event remain unattributed in the full denominator; they do not measure kernel cost.',
            'Function estimates require separate stat medians; multiplying sample share is a cross-run estimate.',
            'Input sections can contain inlined callees; symbol overlaps and aliases remain explicit.',
            'Zero-size functions, gaps and unknown images remain unattributed; no nearest-symbol guesses.']
    else:
        raise ValueError('expected separate stat or sample observer')
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'observer': scope['observer'],
                      'totals': output.get('totals'), 'all_unscaled': output.get('all_unscaled')}))


if __name__ == '__main__':
    main()
