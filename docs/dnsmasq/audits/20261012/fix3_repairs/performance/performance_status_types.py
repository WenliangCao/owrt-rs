#!/usr/bin/env python3
"""Read completion and acceptance only; no interim CPU comparison."""
import json
from pathlib import Path
p=Path('/home/ubuntu/dnsmasq-fix3-repair-20261013/private/performance-types-01')
run=json.loads((p/'run.json').read_text());done=[w for w in run['windows'] if 'returncode' in w]
bad=[]
for w in done:
    q=p/w['id']/'result.json';j=json.loads(q.read_text()) if q.exists() else {}
    if w['returncode'] or j.get('accepted') is not True:
        bad.append({'window':w,'accepted':j.get('accepted'),'errors':j.get('errors')})
print(json.dumps({'status':run['status'],'completed':len(done),'current':run['windows'][-1]['id'],'bad':bad}))
