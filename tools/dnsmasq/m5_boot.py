#!/usr/bin/env python3
"""Boot family against the exact image daemon in a disposable namespace.

Uses the shared DHCP family runner. Requests contain synthetic boot metadata;
no boot image is executed. Expected wire bytes come exclusively from image C.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess

from dhcp_boot_service_diff import fixtures as ordinary_fixtures
from m5_dhcp_tags_options import config, run, compare, save
from m2_rootfs import prepare, command, sha256, STOCK_SHA256


def fixtures():
    yield from ordinary_fixtures()
    events = [dict(label="legacy", kind=1), dict(label="options", kind=1, prl=[66,67]),
              dict(label="ack", kind=3, prl=[66,67]), dict(label="bootp", kind=0)]
    for label, text in [
        ("tagged-before-fallback", "dhcp-boot=tag:known,tagged.img,tagged,127.0.0.9\ndhcp-boot=fallback.img,fallback,127.0.0.8\n"),
        ("tagged-after-fallback", "dhcp-boot=fallback.img,fallback,127.0.0.8\ndhcp-boot=tag:known,tagged.img,tagged,127.0.0.9\n"),
        ("no-tag-match", "dhcp-boot=fallback.img\ndhcp-boot=tag:absent,wrong.img\n"),
        ("negation-only", "dhcp-boot=fallback.img\ndhcp-boot=tag:!,negated.img\n"),
        ("negated-tag", "dhcp-boot=fallback.img\ndhcp-boot=tag:!absent,tagged.img\n"),
        ("last-tagged-wins", "dhcp-boot=tag:known,old.img,old,127.0.0.8\ndhcp-boot=tag:known,new.img,,127.0.0.9\n"),
        ("empty-tagged-fields", "dhcp-boot=fallback.img,fallback,127.0.0.8\ndhcp-boot=tag:known,,,0.0.0.0\n"),
        ("range-tag", "dhcp-boot=tag:range,range.img\n"),
        ("range-tag-if", "tag-if=tag:range,set:boot-ready\ndhcp-boot=tag:boot-ready,ready.img\n"),
        ("hostname-server", "host-record=boot.example,127.0.0.9\ndhcp-boot=net:known,boot.img,,boot.example\n"),
        ("missing-hostname", "dhcp-boot=tag:known,boot.img,,absent.example\n"),
        ("ordinary-option-is-not-boot", "dhcp-option=tag:known,66,option-name\ndhcp-boot=boot.img,boot-name,127.0.0.9\n"),
    ]:
        yield label, text, events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', required=True, type=Path)
    parser.add_argument('--rust', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out/'image', args.rust)
    (root/'m2').chmod(0o777)
    cases = list(fixtures())
    save(args.out/'plan.json', {'cases':cases,'checklist': {'option.c:dhcp_tags':'quoted fields, tag/net/empty selectors, syntax-only invalid runtime', 'rfc2131.c:find_boot':'tagged before fallback; reverse order within tag class', 'rfc2131.c:do_options':'PRL/no override, context and tag-if, next-server hosts lookup, empty fields and NAK', 'rfc2131.c:option_put_string/free_space':'fixed field limits, 254/255 data, default/large capacity, overwide syntax rejection defect'},'reference_defects_runtime_excluded':['empty tag null dereference','overwide TLV length narrowing']})
    report = dict(c_sha256=sha256(root/'usr/sbin/dnsmasq'), rust_sha256=sha256(args.rust),
                  cases=[], failures=[], parser=[], reference_differences=[], negative_controls=[], compared=0)
    assert report['c_sha256'] == STOCK_SHA256
    for label, extra, events in cases:
        folder=args.out/label; folder.mkdir()
        text=config(extra).replace('domain=pool.test\n','')
        c=run(root, 'c', folder/'c', text, events)
        rust=run(root, 'rust', folder/'rust', text, events)
        errors=compare(c, rust)
        assert len(c['rows']) <= len(events) and len(rust['rows']) <= len(events)
        report['cases'].append(dict(name=label, errors=errors, planned=len(events),
                                    c_rows=len(c['rows']), rust_rows=len(rust['rows'])))
        report['compared'] += min(len(c['rows']), len(rust['rows']))
        if errors: report['failures'].append(label)
        if c['status']=='ok' and c['rows']:
            changed=copy.deepcopy(c); changed['rows'][0]['reply']='mutated'
            omitted=copy.deepcopy(c); omitted['rows'].pop()
            assert compare(c, changed) and compare(c, omitted)
            report['negative_controls'].append(label)
        save(args.out/'result.json', report)
    for label, text in [('empty-tag','dhcp-boot=tag:,file'), ('empty-negated','dhcp-boot=tag:!,file'),
                        ('no-fields','dhcp-boot=tag:known'), ('hostname','dhcp-boot=tag:known,file,,boot.test'),
                        ('overwide-filename','dhcp-boot='+('f'*256)),
                        ('overwide-servername','dhcp-boot=file,'+('s'*256))]:
        row=dict(name=label)
        (root/'m2/parser.conf').write_text(text+'\n')
        for side in ['c','rust']:
            result=subprocess.run(command(root,side,'--test','-C','/m2/parser.conf'),capture_output=True,timeout=5)
            row[side]=result.returncode
            (args.out/f'parser-{label}-{side}.stderr').write_bytes(result.stderr)
        report['parser'].append(row)
        if row['c']!=row['rust']:
            if label in ('empty-tag','overwide-filename','overwide-servername') and (row['c'],row['rust'])==(0,1):
                report['reference_differences'].append(dict(name=label, scope='syntax only',
                    reason=('empty selector becomes a null netid in C' if label=='empty-tag' else 'C option_put_string narrows a length greater than one-byte DHCP capacity'), candidate='explicit configuration error', source=('option.c dhcp_netid_create/match_netid' if label=='empty-tag' else 'rfc2131.c option_put_string/free_space'), disposition='retain bounded Rust rejection; only --test runs for this reference defect'))
            else:report['failures'].append('parser-'+label)
    report['passed'] = not report['failures'] and len(report['negative_controls'])==len(cases)
    save(args.out/'result.json',report)
    print(json.dumps({k:report[k] for k in ['passed','compared','failures']}))
    return int(not report['passed'])

if __name__=='__main__':raise SystemExit(main())
