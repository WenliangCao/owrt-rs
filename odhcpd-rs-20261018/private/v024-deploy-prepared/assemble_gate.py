"""Offline gate assembly only. Does not contact or mutate the router."""
import hashlib
import json
import os
from pathlib import Path
import tarfile

base = Path('/home/ubuntu/odhcpd-rs-20261018/private/v024-deploy-prepared')
task = Path('/home/ubuntu/odhcpd-image-fable-v024-20261018')
artifact = task / 'inputs/artifact'
root = task / 'rootfs'
local = Path('/Users/USER/Developer/owrt-control-plane-rs')
local_artifact = local / 'private/odhcpd-20261018/image-fable-v024-e1cf7890/artifact'
owner = base.stat()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(name, data):
    path = base / name
    path.write_text(json.dumps(data, indent=2) + '\n')
    path.chmod(0o600)
    os.chown(path, owner.st_uid, owner.st_gid)

manifest = json.loads((artifact / 'manifest.json').read_text())
assert sha(artifact / 'manifest.json') == 'c738b05adc5f143e98b9ead6601289d71e4f704699548f7734faea61e9eab6b3'
assert manifest['deployment_layout'] == 'native-eleven' and len(manifest['components']) == 11
image = manifest['image']
assert Path(image['file']).name == image['file']
assert sha(artifact / image['file']) == image['sha256'] == 'e669c44cd5eadbf29605304fbe295c73673502d32a8e0364ad9e0692f12315a8'
assert (artifact / image['file']).stat().st_size == 14131488
assert sha(base / 'config-before.tar.gz') == 'b8702654472e3aec26c233e30f1ad2192e351d4d572965768c880c945562b650'
trial = json.loads((base / 'trial-config.tar.json').read_text())
assert sha(base / 'trial-config.tar.gz') == trial['archive_sha256']
assert trial['image']['sha256'] == image['sha256']
assert trial['rollback_image_sha256'] == '02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606'
health = json.loads((base / 'client-health.json').read_text())
assert health['passed'] and health['continuous_client_health_s'] >= 120
assert health['candidate_sha256'] == manifest['components']['odhcpd']['rust_sha256']
post = json.loads((base / 'full-health-after.json').read_text())
assert 'error' not in post and post['boot_id'] == health['boot_id']
assert all(post[key] for key in ('client_dns_ipv4', 'client_dns_ipv6', 'client_https_ipv4', 'client_https_ipv6', 'local_http_https'))

def sums(name):
    return dict(line.split(None, 1)[::-1] for line in (base / name).read_text().splitlines())

config, protected, rom = (sums(name) for name in ('config-before.sha256', 'protected-before.sha256', 'omitted-rom.sha256'))
with tarfile.open(base / 'config-before.tar.gz') as archive:
    contents = {'/' + m.name.lstrip('/'): archive.extractfile(m).read() for m in archive if m.isfile()}
assert len(config) == 19
assert all(name in contents and hashlib.sha256(contents[name]).hexdigest() == value for name, value in config.items())
omitted = {}
for name, value in protected.items():
    if name in contents:
        assert hashlib.sha256(contents[name]).hexdigest() == value
    else:
        assert name in ('/etc/sysupgrade.conf', '/etc/ethers')
        assert rom['/rom' + name] == value == sha(root / name.lstrip('/'))
        omitted[name] = value
write('backup-omitted-paths.json', {'all_current_ROM_and_candidate_equal': True, 'paths': omitted})
old = json.loads((base / 'release-before.json').read_text())
assert old['version'] == '0.2.3-r1' and old['source_commit'] == '0a925bcc2ec065eebaae51811c1a6252007b9d56'
offline = (base / 'offline-recovery-verification.txt').read_text().splitlines()
assert len(offline) == 14 and all(line.endswith(': OK') for line in offline)
backup_names = ['config-before.tar.gz', 'config-before.sha256', 'protected-before.sha256',
                'sysupgrade-list.txt', 'release-before.json', 'backup-omitted-paths.json',
                'offline-recovery-verification.txt', 'verification.json', 'client-health.json', 'full-health-after.json']
gate = {'ready_for_staging': True, 'not_staged': True, 'not_flashed': True,
        'image_path': str(local_artifact / image['file']), 'image_sha256': image['sha256'],
        'manifest_path': str(local_artifact / 'manifest.json'), 'manifest_sha256': sha(artifact / 'manifest.json'),
        'rollback_image_path': str(local / 'private/backup/release-v0.2.3/installed-v023' / image['file']),
        'rollback_sha256': trial['rollback_image_sha256'], 'rollback_version': 'v0.2.3',
        'rollback_source_commit': old['source_commit'],
        'ujail_sha256': sha(root / 'sbin/ujail'), 'bounded_sha256': '21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49',
        'previous_boot_id': health['boot_id'], 'guard_evidence_sha256': sha(base / 'guard-evidence.tar.gz'),
        'backup_sha256': {name: sha(base / name) for name in backup_names},
        'configuration_members_preserved': 46, 'configuration_files_verified': len(config),
        'protected_files_verified': len(protected), 'offline_recovery_materials_verified': len(offline),
        'full_image_recovery_entries': 13, 'fable_packet_checks': 129,
        'fresh_candidate_client_health_seconds': health['continuous_client_health_s'],
        'source_commit': manifest['source_commit'], 'qualification_ci': '39115006321',
        'note': 'All preparation and conditional qualification gates passed. No sysupgrade staging, activation, publication or mainline merge has been performed.'}
write('recovery-gate.json', gate)
print(json.dumps({key: gate[key] for key in ('ready_for_staging', 'not_staged', 'not_flashed', 'configuration_files_verified', 'protected_files_verified', 'offline_recovery_materials_verified')}))
