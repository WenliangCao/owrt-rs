#!/usr/bin/env python3
"""Verify that the independent audit comparator rejects injected differences."""
import copy
import json
from pathlib import Path
import struct
import negative_final as check

q = bytes.fromhex('123401000001000000000000016104746573740000010001')
soa = b'\x02ns\x04test\0\x04host\x04test\0' + struct.pack('!5I', 1, 60, 60, 600, 3600)
r = q[:2] + struct.pack('!5H', 0x8180, 1, 0, 1, 0) + q[12:]
r += b'\x04test\0' + struct.pack('!HHIH', 6, 1, 3600, len(soa)) + soa
base = dict(status='passed', dhcp_checks=[], dhcp_replies=[], events=[dict(
    label='test', packet=r.hex(), request=q.hex(), started=10.0, ended=10.1, alive=True, upstream=[])])
checks = dict(identical_response=check.strict_pair(base, copy.deepcopy(base)) ==
    dict(responses=1, exact=1, bounded_soa=0, dhcp_replies=0))
offset = len(q) + len(b'\x04test\0') + 4
for label, mutate, expected in [
    ('adjacent_soa_tick', lambda w: struct.pack_into('!I', w, offset, 3599), True),
    ('excess_soa_age', lambda w: struct.pack_into('!I', w, offset, 3598), False),
    ('flags_mismatch', lambda w: w.__setitem__(3, w[3] ^ 1), False),
    ('trailing_bytes', lambda w: w.extend(b'\0'), False),
]:
    other = copy.deepcopy(base)
    wire = bytearray(r)
    mutate(wire)
    other['events'][0]['packet'] = wire.hex()
    try:
        check.strict_pair(base, other)
        passed = True
    except (AssertionError, struct.error):
        passed = False
    checks[label] = passed == expected
assert all(checks.values())
root = Path(__file__).resolve().parent
report = dict(script_sha256=check.sha(root / 'negative_final.py'), calibration_sha256=check.sha(__file__),
    synthetic_checker_calibration=checks, scope='Audit comparator correctness only; no daemon experiment.')
(root / 'negative-checker-calibration.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
