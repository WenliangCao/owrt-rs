from pathlib import Path
import json,hashlib
b=Path('/dev/shm/full-f10-dhcp-20261014/private')
versions=['v2','v3','v4','v5','cross-alias-c-matched','candidate-b99e','candidate-b99e-no-lease']
reports=[]
for version in versions:
 p=b/version/'result.json';j=json.loads(p.read_text())
 reports.append({'directory':str(p.parent),'result_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'runs':[{k:r.get(k) for k in ['retained','repeat','case','c_sha256','rust_sha256','source_commit','alive','exit','error']}|{k:r[k]['answer_order'] for k in ['initial_a','after_a','after_y','after_ptr','after_tcp_ptr']} for r in j['runs']]})
(b/'derived.json').write_text(json.dumps({'scope':'Exact C retained-DHCP controls and same-query candidate-b99e replays; ordered PTR is process hash dependent, owner membership and A phase are separate checks.','runs':reports},indent=2)+'\n')
