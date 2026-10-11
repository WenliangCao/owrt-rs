#!/usr/bin/env python3
"""Observe C/R image mappings; optionally require complete runtime RELRO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

PT_LOAD = 1
PT_GNU_RELRO = 0x6474E552
QUERY = struct.pack('!6H', 0x5234, 0x100, 1, 0, 0, 0) + b'\x05relro\x04test\0\0\1\0\1'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def align_down(value, page_size):
    return value - value % page_size


def align_up(value, page_size):
    return (value + page_size - 1) // page_size * page_size


def elf_headers(binary):
    data = binary.read_bytes()
    assert data[:7] == b'\x7fELF\x02\x01\x01', '64-bit little-endian ELF required'
    kind, machine = struct.unpack_from('<HH', data, 16)
    assert kind in (2, 3) and machine == 183, 'AArch64 executable required'
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    assert size >= 56 and offset + size * count <= len(data)
    keys = ('type', 'flags', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align')
    headers = [dict(zip(keys, struct.unpack_from('<IIQQQQQQ', data, offset + i * size)))
               for i in range(count)]
    return kind, headers


def parse_maps(text):
    entries = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        start, end = (int(value, 16) for value in fields[0].split('-'))
        major, minor = (int(value, 16) for value in fields[3].split(':'))
        entries.append(dict(start=start, end=end, permissions=fields[1],
                            offset=int(fields[2], 16), device=[major, minor],
                            inode=int(fields[4]), path=fields[5] if len(fields) > 5 else ''))
    return entries


def object_identity(path):
    info = path.stat()
    return dict(device=[os.major(info.st_dev), os.minor(info.st_dev)], inode=info.st_ino)


def same_object(mapping, identity):
    return all(mapping[key] == identity[key] for key in ('device', 'inode'))


def load_bias(headers, entries, identity, kind, page_size):
    loads = [row for row in headers if row['type'] == PT_LOAD]
    first = [row for row in loads if row['offset'] == 0 and row['filesz'] > 0]
    assert len(first) == 1, 'one ELF-header PT_LOAD required'
    candidates = {row['start'] - align_down(first[0]['vaddr'], page_size)
                  for row in entries if same_object(row, identity) and row['offset'] == 0}
    valid = []
    for bias in candidates:
        if kind == 2 and bias != 0:
            continue
        for segment in loads:
            if not segment['filesz']:
                continue
            assert segment['vaddr'] % page_size == segment['offset'] % page_size
            start = bias + align_down(segment['vaddr'], page_size)
            offset = align_down(segment['offset'], page_size)
            if not any(same_object(row, identity) and row['start'] <= start < row['end']
                       and row['offset'] + start - row['start'] == offset for row in entries):
                break
        else:
            valid.append(bias)
    assert len(valid) == 1, 'ELF PT_LOADs do not identify one consistent load bias'
    return valid[0]


def relro_mapping(headers, entries, bias, page_size):
    relros = [row for row in headers if row['type'] == PT_GNU_RELRO]
    assert len(relros) == 1 and relros[0]['memsz'] > 0, 'one nonempty PT_GNU_RELRO required'
    relro = relros[0]
    # The protected bytes must belong to this object's loaded memory, not an
    # unrelated read-only VMA reached through an incorrect bias calculation.
    assert any(row['type'] == PT_LOAD and row['vaddr'] <= relro['vaddr']
               and row['vaddr'] + row['memsz'] >= relro['vaddr'] + relro['memsz']
               for row in headers), 'RELRO lies outside PT_LOAD memory'
    start, end = bias + relro['vaddr'], bias + relro['vaddr'] + relro['memsz']
    # Inspect every byte's page. This is not a recommendation to mprotect a
    # partial final page, which may also contain writable non-RELRO data.
    begin, stop = align_down(start, page_size), align_up(end, page_size)
    pages = []
    for page in range(begin, stop, page_size):
        covering = [row for row in entries if row['start'] <= page and row['end'] >= page + page_size]
        permissions = covering[0]['permissions'] if len(covering) == 1 else None
        pages.append(dict(address=hex(page), permissions=permissions,
                          readable_not_writable=permissions is not None
                          and 'r' in permissions and 'w' not in permissions))
    return dict(relro_start=hex(start), relro_end=hex(end),
                page_start=hex(begin), page_end=hex(stop),
                relro_start_page_aligned=start % page_size == 0,
                relro_end_page_aligned=end % page_size == 0,
                relro_pages=pages,
                relro_readonly=bool(pages) and all(row['readable_not_writable'] for row in pages))


def exchange(tcp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(.25)
        sock.connect(('127.0.0.1', 15353))
        if not tcp:
            sock.send(QUERY)
            reply = sock.recv(65535)
        else:
            def exact(count):
                value = b''
                while len(value) < count:
                    chunk = sock.recv(count - len(value))
                    if not chunk:
                        raise EOFError('short DNS TCP response')
                    value += chunk
                return value
            sock.sendall(struct.pack('!H', len(QUERY)) + QUERY)
            reply = exact(struct.unpack('!H', exact(2))[0])
    assert len(reply) >= len(QUERY) + 16 and reply[:2] == QUERY[:2]
    header = struct.unpack_from('!6H', reply)
    assert header[1] & 0x800F == 0x8000 and header[2:4] == (1, 1)
    assert reply[12:len(QUERY)] == QUERY[12:] and reply[-4:] == bytes([192, 0, 2, 99])
    return reply.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--image-root', type=Path, default=Path(
        '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files'))
    parser.add_argument('--require-relro', action='store_true',
                        help='fail unless every page touched by PT_GNU_RELRO is readable and not writable')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
    sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
    from m2_rootfs import prepare, command
    args.out.mkdir()
    root = prepare(args.image_root, None, args.out / 'image', args.candidate)
    page_size = os.sysconf('SC_PAGE_SIZE')
    result = dict(tool_sha256=sha256(Path(__file__)), require_relro=args.require_relro,
                  page_size=page_size, scope='C/R actual mappings and UDP/TCP local answers in isolated image; no router',
                  variants={}, failures=[])
    for variant, relative in [('c', 'usr/sbin/dnsmasq'), ('rust', 'usr/sbin/dnsmasq-rs')]:
        binary = root / relative
        kind, headers = elf_headers(binary)
        readelf = subprocess.check_output(['readelf', '-W', '-h', '-l', '-d', str(binary)], text=True)
        (args.out / f'{variant}.readelf').write_text(readelf)
        item = dict(sha256=sha256(binary), size=binary.stat().st_size, elf_type=kind,
                    headers=headers, runs=[])
        relros = [row for row in headers if row['type'] == PT_GNU_RELRO]
        if len(relros) == 1:
            item.update(relro_vaddr=relros[0]['vaddr'], relro_memsz=relros[0]['memsz'])
        result['variants'][variant] = item
        for index in range(3):
            pidfile = root / 'm2/protection.pid'
            pidfile.unlink(missing_ok=True)
            argv = command(root, variant, '-C', '/dev/null', '-k', '--user=root', '--group=root',
                           '--port=15353', '--listen-address=127.0.0.1', '--bind-interfaces',
                           '--address=/relro.test/192.0.2.99', '--no-hosts', '--no-resolv',
                           '--pid-file=/m2/protection.pid', '--log-facility=-')
            run = dict(argv=argv, failures=[])
            item['runs'].append(run)
            with (args.out / f'{variant}-{index}.log').open('wb') as log:
                process = subprocess.Popen(argv, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        assert process.poll() is None and time.monotonic() < deadline, 'startup failed'
                        if pidfile.exists():
                            try:
                                run['udp_before'] = exchange()
                                break
                            except (OSError, EOFError):
                                pass
                        time.sleep(.01)
                    executable = Path(f'/proc/{process.pid}/exe')
                    run['actual_elf_sha256'] = sha256(executable)
                    run['actual_elf_identity'] = object_identity(executable)
                    assert run['actual_elf_sha256'] == item['sha256']
                    assert run['actual_elf_identity'] == object_identity(binary)
                    maps = Path(f'/proc/{process.pid}/maps').read_text()
                    (args.out / f'{variant}-{index}.maps').write_text(maps)
                    entries = parse_maps(maps)
                    bias = load_bias(headers, entries, run['actual_elf_identity'], kind, page_size)
                    run['load_bias'] = hex(bias)
                    header_load = next(row for row in headers if row['type'] == PT_LOAD and row['offset'] == 0)
                    run['base'] = hex(bias + align_down(header_load['vaddr'], page_size))
                    run.update(relro_mapping(headers, entries, bias, page_size))
                    run['stack_permissions'] = next(row['permissions'] for row in entries if row['path'] == '[stack]')
                    run['wx_mappings'] = [row for row in entries if 'w' in row['permissions'] and 'x' in row['permissions']]
                    run['mapped_files'] = sorted({row['path'] for row in entries if row['path'].startswith('/')})
                    (args.out / f'{variant}-{index}.smaps').write_text(Path(f'/proc/{process.pid}/smaps_rollup').read_text())
                    run['tcp_after'] = exchange(tcp=True)
                    assert run['udp_before'] == run['tcp_after'], 'UDP/TCP local answer differs'
                    assert process.poll() is None, 'daemon exited after DNS query'
                    if args.require_relro and not run['relro_readonly']:
                        run['failures'].append('PT_GNU_RELRO is not fully readable and non-writable')
                except Exception as error:
                    run['failures'].append(repr(error))
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        run['failures'].append('forced shutdown')
                    run['exit'] = process.returncode
                    if process.returncode != 0:
                        run['failures'].append('nonzero daemon exit')
            result['failures'].extend(f'{variant}/{index}: {error}' for error in run['failures'])
        item['distinct_bases'] = len({run['load_bias'] for run in item['runs'] if 'load_bias' in run})
    answers = [run.get('udp_before') for item in result['variants'].values() for run in item['runs']]
    result['dns_answers_match'] = len(answers) == 6 and None not in answers and len(set(answers)) == 1
    if not result['dns_answers_match']:
        result['failures'].append('C/R startup DNS answers differ or are missing')
    result['passed'] = not result['failures']
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return int(not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
