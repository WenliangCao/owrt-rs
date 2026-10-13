#!/usr/bin/env python3
"""Close local audit identities; no build, daemon or product mutation."""
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


root = Path(git('rev-parse', '--show-toplevel'))
evidence = root / 'docs/dnsmasq/audits/20261014/fix4'
identity = json.loads((evidence / 'build/local-input-identity.json').read_text())
report = root / 'docs/dnsmasq/AUDIT_FIX4_20261014.md'
assert git('branch', '--show-current') == 'fix/audit-20261011'
assert git('rev-parse', 'main') == identity['main']
for name, expected in identity['source_inputs'].items():
    assert sha(root / name) == expected, name
    assert hashlib.sha256(subprocess.check_output(['git', 'show', f'HEAD:{name}'])).hexdigest() == expected, name
changed = git('diff', '--name-only', identity['head'], 'HEAD').splitlines()
assert all(name.startswith('docs/dnsmasq/audits/20261014/fix4/')
           or name == str(report.relative_to(root)) for name in changed), changed
missing = []
for target in re.findall(r'\]\(([^)]+)\)', report.read_text()):
    if '://' not in target and not (report.parent / target.split('#')[0]).exists():
        missing.append(target)
assert not missing, missing
assert '待' + '填写' not in report.read_text()
assert '待最终' not in report.read_text()
result = dict(
    passed=True, scope='Local Git/worktree/product-input/report-link closure; remote execution receipts remain separately identified.',
    audited_head=identity['head'], main=identity['main'], closing_head=git('rev-parse', 'HEAD'),
    product_files_checked=len(identity['source_inputs']), only_audit_files_committed=True,
    report_sha256=sha(report), missing_report_links=missing,
    files={str(p.relative_to(root)): sha(p) for p in sorted(evidence.rglob('*'))
           if p.is_file() and '__pycache__' not in p.parts and p.name != 'local-closure.json'},
)
(evidence / 'root/local-closure.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: value for key, value in result.items() if key != 'files'}))
