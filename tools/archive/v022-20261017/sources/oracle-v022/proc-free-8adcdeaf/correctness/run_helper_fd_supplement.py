import json,subprocess,time,hashlib
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/proc-free-8adcdeaf';SOURCE=ROOT/'source-8adcdeaf';TOOLS=SOURCE/'tools/dnsmasq';OUT=BASE/'correctness/helper-fd-supplement';assert not OUT.exists();OUT.mkdir()
scenarios=','.join('helper-startup-'+service+'-'+mode for mode in ['default','foreground','debug'] for service in ['tftp','dhcp'])
image='/srv/owrt-archive/image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c'
report={'scope':'explicit six-case helper FD supplement; does not replace original broad legacyFD family','cases_per_role':6,'roles':[]}
for role,binary,digest,commit,contract in [('k',ROOT/'private/baseline-k/dnsmasq-rs','f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08','4ce24c627615ae5ff42d3dcdbccb66d57b218b5a','fork'),('candidate',BASE/'pgo/train-stage/use/dnsmasq-rs','756aef353b04324ac66922adff01fe82b105d72e286a1e9b3dac93ee95d3ab4f','8adcdeafddb7cfd8bc5d059e396d898c0447cb70','selfexec')]:
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==digest
 cmd=['sudo','-n','sh',str(TOOLS/'run_isolated.sh'),'python3',str(TOOLS/'m5_logging.py'),'--image-root',image,'--rust',str(binary),'--rust-sha256',digest,'--source-commit',commit,'--output',str(OUT/role),'--scopes','daemon','--scenarios',scenarios,'--helper-fd-contract',contract]
 row={'role':role,'argv':cmd,'start':time.time()};report['roles'].append(row)
 with (OUT/(role+'.stdout')).open('xb') as stdout,(OUT/(role+'.stderr')).open('xb') as stderr:row['returncode']=subprocess.run(cmd,stdout=stdout,stderr=stderr,timeout=180).returncode
 row['end']=time.time();result=json.loads((OUT/role/'result.json').read_text());row['cases']=len(result['scenarios']);row['failures']=result['failures'];assert row['cases']==6
 (OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(row),flush=True)
report['passed']=all(row['returncode']==0 and not row['failures'] for row in report['roles']);(OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
