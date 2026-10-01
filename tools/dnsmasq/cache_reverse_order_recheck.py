#!/usr/bin/env python3
"""Offline completeness audit of the frozen 42 C traces; starts no oracle.

The original ordered relation checker remains unchanged. This adds a separate
hash-chain/LRU membership invariant and rejects deleting a final HASH row.
Membership checks never replace ordered answer or hash-chain comparisons.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from cache_reverse_order_oracle import audit, parse, save, sha

RESULT_SHA = '3e5a67972c4424af3cead4aab8acd8bafb8be2790c8274b699409caab508c83b'
IDENTITY_SHA = '3df5c55ac116646fb122f276d19a8a652c4f031913a5c51a9bfa1be9d4b2073a'
PLAN_SHA = 'fa4064f97f6dc221695b6d746e554df297c3b7d91c4892b484fe7a3240ee2d74'


def membership(trace):
    # Snapshots contain committed dynamic entries only. Compare membership as
    # an additional invariant, while all returned/hash/LRU orders stay exact.
    return [{'phase':phase,'passed':Counter(token for _,chain in state['hash'] for token in chain)==Counter(state['lru'])}
            for phase,state in trace['states'].items()]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();base=args.baseline.resolve();out=args.out.resolve()
    assert 'private' in out.parts;out.mkdir(parents=True,exist_ok=False)
    assert sha(base/'result.json')==RESULT_SHA and sha(base/'identity.json')==IDENTITY_SHA and sha(base/'plan.json')==PLAN_SHA
    original=json.loads((base/'result.json').read_text())
    assert original['completed_invocations']==42 and original['passed_relations']==3666 and not original['failures']
    report=dict(scope=__doc__,tool_sha256=sha(Path(__file__)),original_tool_sha256=sha(Path(__file__).with_name('cache_reverse_order_oracle.py')),
                baseline_result_sha256=RESULT_SHA,baseline_identity_sha256=IDENTITY_SHA,baseline_plan_sha256=PLAN_SHA,
                new_oracle_invocations=0,runs=[],failures=[])
    for row in original['runs']:
        stem=f"{row['runtime']}-{row['repeat']}";folder=base/row['profile']
        assert sha(folder/(stem+'.stdout'))==row['stdout_sha256']
        assert sha(folder/(stem+'.stderr'))==row['stderr_sha256']
        assert sha(folder/(stem+'.relations.json'))==row['relations_sha256']
        text=(folder/(stem+'.stdout')).read_text();trace=parse(text)
        relations=audit(row['profile'],trace);checks=membership(trace)
        assert len(relations)==row['checks'] and all(c['passed'] for c in relations)
        assert len(checks)==11 and all(c['passed'] for c in checks)
        removed=False;lines=[]
        for line in text.splitlines():
            if line.startswith('HASH parent-final ') and not removed:removed=True
            else:lines.append(line)
        assert removed and any(not c['passed'] for c in membership(parse('\n'.join(lines)+'\n')))
        report['runs'].append(dict(profile=row['profile'],runtime=row['runtime'],repeat=row['repeat'],
            original_relations=len(relations),complete_snapshots=len(checks),missing_hash_row_rejected=True))
    report.update(status='passed-offline-completeness-audit',original_relations_rechecked=sum(r['original_relations'] for r in report['runs']),
                  complete_snapshots=sum(r['complete_snapshots'] for r in report['runs']),missing_hash_negatives=len(report['runs']))
    save(out/'result.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ['scope','runs']}))


if __name__=='__main__':main()
