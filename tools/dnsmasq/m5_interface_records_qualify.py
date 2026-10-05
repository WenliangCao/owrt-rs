#!/usr/bin/env python3
"""Reject partial/identity-drift family runs before final-registry qualification."""
import argparse
import hashlib
import json
from pathlib import Path

import m5_interface_records as family
from m2_rootfs import STOCK_SHA256


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualify(runs,scope,source,elf):
    manifest,options,required=family.ordinary_contract(scope)
    expected={(mode,case['id']):case for mode in ['syntax','service'] for case in family.ordinary_cases(mode,scope)}
    actual={};references=[];identities=[]
    for run in runs:
        report=json.loads((run/'result.json').read_text());schedule=json.loads((run/'schedule.json').read_text())
        if not report['comparison_executed'] or report['failures']:raise AssertionError('C-only or failed run')
        if report['source_commit'] not in [source,source[:8]] or report['rust_sha256']!=elf or report['c_sha256']!=STOCK_SHA256:
            raise AssertionError('candidate/source identity drift')
        if report['tool_sha256']!=digest(run/'driver/m5_interface_records.py') or report['requirements_sha256']!=digest(run/'driver/m5_interface_records.json'):
            raise AssertionError('executed tool/manifest changed')
        if not report.get('driver_sha256') or any(digest(run/'driver'/name)!=value for name,value in report['driver_sha256'].items()):
            raise AssertionError('complete executed helper identities missing or changed; final runs must be fresh')
        if [case['id'] for case in report['cases']]!=[case['id'] for case in schedule]:raise AssertionError('schedule rows missing or reordered')
        if not set(family.controls())<=set(report['negative_controls']):raise AssertionError('negative controls missing')
        for case,row in zip(schedule,report['cases']):
            key=(report['mode'],case['id'])
            if key not in expected:continue
            execution=dict(case);execution.pop('allocator_map',None)
            if execution!=json.loads(json.dumps(expected[key])):raise AssertionError('executed profile differs from final ordinary catalog: '+str(key))
            observed={side:json.loads((run/case['id']/side/'observed.json').read_text()) for side in ['c','rust']}
            if report['mode']=='syntax':
                if family.endpoints.normal(observed['c'])!=family.endpoints.normal(observed['rust']):raise AssertionError('syntax differs')
            else:
                failures,differences=family.compare_service(observed['c'],observed['rust'],case)
                if failures:raise AssertionError({'case':case['id'],'failures':failures})
                references.extend(dict(case=case['id'],**difference) for difference in differences)
                for side,value in observed.items():
                    if value['startup']['ready'] and value['identity']['sha256']!=(STOCK_SHA256 if side=='c' else elf):raise AssertionError('live daemon identity missing')
            actual[key]={'run':str(run),'result_sha256':digest(run/'result.json'),
                'observed_sha256':{side:digest(run/case['id']/side/'observed.json') for side in observed}}
        identities.append({'run':str(run),'tool_sha256':report['tool_sha256'],'requirements_sha256':report['requirements_sha256']})
    missing=sorted(set(expected)-set(actual))
    if missing:raise AssertionError({'ordinary_profiles_missing':missing})
    rows=[]
    for row in required:
        keys=[key for key in expected if key[1] in row['case_ids']]
        if not keys or any(key not in actual for key in keys):raise AssertionError('required source row has no complete paired observations')
        rows.append({'id':row['id'],'profiles':[{'mode':mode,'id':ident,**actual[(mode,ident)]} for mode,ident in keys]})
    return {'schema':'m5-interface-family-full-ordinary-qualification-v1','qualified':True,'closed_options':options,
        'scope':scope,'source_commit':source,'elf_sha256':elf,'image_elf_sha256':STOCK_SHA256,
        'required_count':len(rows),'qualified_required':len(rows),'syntax_configurations':sum(mode=='syntax' for mode,_ in actual),
        'service_configurations':sum(mode=='service' for mode,_ in actual),'missing_required':0,'missing_profiles':0,
        'reference_differences':references,'run_identities':identities,'required':rows,
        'known_deferred_components':manifest.get('known_deferred_components',[])}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope',choices=['all',*family.SCOPES],default='all');parser.add_argument('--source-commit',required=True)
    parser.add_argument('--rust-sha256',required=True);parser.add_argument('--run',type=Path,action='append',required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    result=qualify(args.run,args.scope,args.source_commit,args.rust_sha256)
    args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['qualified','scope','closed_options','required_count','syntax_configurations','service_configurations']}))


if __name__=='__main__':main()
