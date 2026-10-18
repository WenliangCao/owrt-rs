#!/usr/bin/env python3
"""Read archived trial evidence; print only redacted consistency checks."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import tarfile
import sys

base = Path(sys.argv[1])
log = (base / 'health.jsonl').read_bytes()
records = [json.loads(line) for line in log.splitlines()]
health = json.loads((base / 'client-health.json').read_text())
activation = dt.datetime.fromisoformat((base / 'activated-at.txt').read_text().strip().replace('Z', '+00:00')).timestamp()
samples = [row for row in records if row['event'] == 'pass']
identities = {(row['sample']['candidate']['pid'], row['sample']['candidate']['start_ticks'], row['sample']['candidate']['sha256']) for row in samples}
archive = {}
with tarfile.open(base / 'device-evidence.tar.gz') as tar:
    for member in tar:
        if member.isfile():
            archive[Path(member.name).name] = tar.extractfile(member).read()
state = archive['state'].decode().strip()
accepted = archive['accepted'].decode().split()
remote_health = json.loads(archive['client-health.json'])
candidate_sha = '79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55'
stock_sha = '53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82'
checks = {
    'health_log_sha_matches_receipt': hashlib.sha256(log).hexdigest() == health['external_health_token'],
    'events_are_start_passes_complete': [row['event'] for row in records] == ['start'] + ['pass'] * len(samples) + ['complete'],
    'one_candidate_process_entire_window': len(identities) == 1 and next(iter(identities))[2] == candidate_sha,
    'all_samples_same_expected_boot': all(row['sample']['health']['boot_id'] == health['boot_id'] for row in samples),
    'summary_matches_archived_receipt': remote_health == health,
    'accepted_binds_exact_receipt_and_raw_log': accepted == [hashlib.sha256(archive['client-health.json']).hexdigest(), hashlib.sha256(log).hexdigest()],
    'archive_candidate_and_stock_hashes_match': hashlib.sha256(archive['candidate.elf']).hexdigest() == candidate_sha and hashlib.sha256(archive['stock.elf']).hexdigest() == stock_sha,
    'restored_confirmed': state == 'restored-confirmed',
}
fresh = sorted({row['sample']['ra']['received_epoch'] for row in samples if row['sample']['ra']['received_epoch'] > activation})
output = {'checks': checks, 'samples': len(samples), 'fresh_ra_timestamps': len(fresh),
          'continuous_s': records[-1]['continuous_client_health_s'],
          'raw_log_sha256': hashlib.sha256(log).hexdigest(),
          'archive_sha256': hashlib.sha256((base / 'device-evidence.tar.gz').read_bytes()).hexdigest(),
          'read_only_archived_evidence': True}
(base / 'audit-result.json').write_text(json.dumps(output, indent=2) + '\n')
print(json.dumps(output, indent=2))
assert all(checks.values()) and len(samples) == 13 and len(fresh) == 5 and output['continuous_s'] >= 120
