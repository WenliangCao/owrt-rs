"""DNS semantic comparison: preserve every header/section/rdata field, normalize compression.

Ordinary RR TTLs are omitted because fresh daemons may cross one wall-clock second;
OPT's extended RCODE/version/flags word is retained. Raw wire is always retained by
callers. This is deliberately independent from product parsing code.
"""
import struct


def _canonical(response):
    if response['status'] != 'reply':
        return dict(response)
    packet = bytes.fromhex(response['hex'])

    def name(offset):
        labels, seen, end = [], set(), None
        while True:
            if offset in seen:
                raise ValueError('compression pointer loop')
            seen.add(offset)
            size = packet[offset]
            offset += 1
            if size == 0:
                return labels, end or offset
            if size & 192 == 192:
                end = end or offset + 1
                offset = ((size & 63) << 8) | packet[offset]
            else:
                if size > 63 or offset + size > len(packet):
                    raise ValueError('invalid label')
                labels.append(packet[offset:offset + size].hex())
                offset += size

    header = struct.unpack_from('!6H', packet)
    result = {'id': header[0], 'flags': header[1], 'counts': list(header[2:]),
              'questions': [], 'records': []}
    offset = 12
    for _ in range(header[2]):
        owner, offset = name(offset)
        kind, cls = struct.unpack_from('!HH', packet, offset)
        offset += 4
        result['questions'].append([owner, kind, cls])
    for count in header[3:]:
        section = []
        for _ in range(count):
            owner, offset = name(offset)
            kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
            offset += 10
            if offset + length > len(packet):
                raise ValueError('truncated rdata')
            data = packet[offset:offset + length].hex()
            if kind in (2, 5, 12):
                data = name(offset)[0]
            elif kind == 15:
                data = [struct.unpack_from('!H', packet, offset)[0], name(offset + 2)[0]]
            elif kind == 33:
                data = [*struct.unpack_from('!HHH', packet, offset), name(offset + 6)[0]]
            elif kind == 6:
                primary, position = name(offset)
                contact, position = name(position)
                data = [primary, contact, *struct.unpack_from('!IIIII', packet, position)]
            section.append([owner, kind, cls, ttl if kind == 41 else None, data])
            offset += length
        result['records'].append(section)
    result['trailing'] = packet[offset:].hex()
    return result


def canonical(response):
    try:
        return _canonical(response)
    except (ValueError, IndexError, struct.error) as error:
        # C can return a REFUSED packet retaining a malformed question. For this
        # case only raw equality is meaningful; never discard the bad bytes.
        return {'parse_error': str(error), 'raw_response': response}


def response_checks(c, rust):
    return {'both_reply': c['status'] == rust['status'] == 'reply',
            'canonical_equal': canonical(c) == canonical(rust)}


def common_udp_case(profile, query):
    return ((profile == "target-local-positive" and query in
             {f"{kind}-rd" for kind in (6, 12, 15, 16, 28, 33, 255, 257)})
            or (profile == "target-literal-positive" and query == "255-rd"))


def parity_checks(c_udp, c_tcp, rust_udp, rust_tcp, common_udp=False):
    values = [canonical(row) for row in (c_udp, c_tcp, rust_udp, rust_tcp)]
    cu, ct, ru, rt = values
    truncated = all(row.get('flags', 0) & 0x200 for row in (cu, ru))
    return {'C_UDP_equal': cu == ru, 'C_TCP_equal_or_declared_common_UDP': (cu if common_udp else ct) == rt,
            'transport_equal_or_C_truncation': ru == rt or (truncated and cu == ru and ct == rt),
            'transport_size_difference': truncated and ru != rt}
