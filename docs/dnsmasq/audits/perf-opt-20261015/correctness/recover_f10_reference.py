#!/usr/bin/env python3
"""Recover exact missing synthetic F10 evidence; refuse any SHA mismatch.

This is data recovery, not a comparator or a new reference. A fresh exact-C run
supplies deterministic bytes. Original recorded paths, original manifest tracks,
and the original lease-file hash supply the missing historical fields. The
recovered output is accepted only if all 13 case-file and the full JSON hashes
match the pre-existing Git index byte for byte.
"""
import argparse
import copy,datetime,hashlib,json,struct
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fresh-c',type=Path,required=True)
parser.add_argument('--contract-directory',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
assert 'private' in args.output.resolve().parts and not args.output.exists()
doc=args.contract_directory
r=json.loads(args.fresh_c.read_text())
assert r['implementation']=='c' and r['binary_sha256']=='097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
assert not r['errors'] and r['case_count']==13
for case in r['cases']:
 assert case['completed'] and case['exit']==0
 assert case['argv'][0]=='chroot'
 case['argv'][1]='/dev/shm/full-f10-contract-20261014/private/repeat-c/stage/rootfs' 
m=json.loads((doc/'qualifier/approved/manifest.json').read_text())
idx=json.loads((doc/'baseline/raw-index.json').read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(x):return (json.dumps(x,indent=2)+'\n').encode()
def endname(p,i):
 while p[i]:
  if p[i]&192==192:return i+2
  i+=p[i]+1
 return i+1
def replace(row,s):
 p=bytearray.fromhex(row['response_wire']);i=endname(p,12)+4
 assert len(row['semantics']['records'])==len(s['records'])
 for prev,new in zip(row['semantics']['records'],s['records']):
  i=endname(p,i);kind,cls,ttl,n=struct.unpack_from('!HHIH',p,i);i+=10
  if prev!=new:
   assert kind==12 and {k:v for k,v in prev.items() if k!='data'}=={k:v for k,v in new.items() if k!='data'}
   data=b''.join(bytes([len(x)])+x.encode() for x in new['data'].split('.'))+b'\0'
   assert len(data)==n
   p[i:i+n]=data
  i+=n
 row['response_wire']=p.hex();row['semantics']=copy.deepcopy(s)
 row['answer_order']=[v['data'] for v in s['records'] if v['section']=='answer']
for e in m['entries']:
 c=next(c for c in r['cases'] if c['case']==e['key']['case'])
 rows={o['label']:o for o in c['observations']}
 for item in e['observed_sequences'][0]:replace(rows[item['label']],item['semantics'])
for e in m['source_bound_entries']:
 c=next(c for c in r['cases'] if c['case']==e['fixture_input']['case'])
 for o in c['observations']:
  if o['label'] in e['target_labels']:
   s=copy.deepcopy(o['semantics']);s['records']=e['reference_records'];replace(o,s)
lease=next(c for c in r['cases'] if c['case']=='leases-dhcp')
_,sep,rest=lease['leases'].partition(' ')
target=idx['repeat-c/stage/rootfs-overlay/upper/m2/leases-dhcp/leases']['sha256']
start=int(datetime.datetime(2026,10,13,tzinfo=datetime.timezone.utc).timestamp())
for epoch in range(start,start+3*86400):
 value=str(epoch)+sep+rest
 if sha(value.encode())==target:
  lease['leases']=value;print('recovered original lease epoch from SHA',epoch);break
else:raise ValueError('lease bytes not recovered')
for c in r['cases']:
 info=idx['repeat-c/'+c['case']+'/result.json'];b=dump(c)
 assert len(b)==info['bytes'] and sha(b)==info['sha256'], c['case']
 print(c['case'],'exact original SHA verified')
r['driver_sha256']='e42e2f3fd3e82e322ce9d3048ff2fd24a63897eb722b23b2f63948bf7baa477a'
b=dump(r);expected=idx['repeat-c/result.json'];print('full',len(b),expected['bytes'],sha(b),expected['sha256'])
assert len(b)==expected['bytes'] and sha(b)==expected['sha256']=='4021e120f447aa54e7fad49146837c01fd8752f7e9184b67e42f31ba79bcae94'
assert sha(json.dumps(r,sort_keys=True).encode())=='c927b1cef7fcf3ee13583080260d038354f5bbdc793d41b64507a3e7624c50b9'
args.output.write_bytes(b)
print('RECOVERED exact original file; full raw and canonical hashes verified')
