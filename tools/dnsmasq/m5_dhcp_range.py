#!/usr/bin/env python3
"""IPv4 dhcp-range family against exact-image C in disposable namespaces.

The first phase freezes parser and ordinary range observations. Packet transport
and namespaces reuse the existing DHCP matrix helpers; expected packets always
come from image C. Raw output and failed runs remain in private evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import m5_option_matrix_dhcp as dhcp
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from m5_dhcp_tags_options import options, primary_options
from test_single_poll_service import stop

SERVER = '10.77.0.1'

# Keep the executable scenarios tied to the source-derived family checklist.
# The plan is written beside each run so a partial Oracle run cannot be read as
# coverage of a boundary that was never scheduled.  Probe-fault rows are
# intentionally marked planned-only until the child-only fault injector is
# supplied; they must not be counted as a differential pass.
BOUNDARY_IDS = [
    'CFG-01', 'CFG-02', 'CFG-03', 'CFG-04', 'CFG-05', 'CFG-06', 'CFG-07', 'CFG-08', 'CFG-09',
    'CTX-01', 'CTX-02', 'CTX-03', 'CTX-04', 'CTX-05', 'CTX-06',
    'SELECT-01', 'SELECT-02', 'SELECT-03', 'SELECT-04', 'SELECT-05', 'SELECT-06',
    'SELECT-07', 'SELECT-08', 'SELECT-09', 'SELECT-10',
    'LEASE-01', 'LEASE-02', 'LEASE-03',
    'PROBE-01', 'PROBE-02', 'PROBE-03', 'PROBE-04', 'PROBE-05', 'PROBE-06',
    'PROBE-07', 'PROBE-08', 'LIFE-01', 'LIFE-02', 'LIFE-03',
]


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def syntax_cases():
    values = [
        ('range-basic', 'normal', '10.77.0.10,10.77.0.14'),
        ('range-reverse', 'reverse', '10.77.0.14,10.77.0.10'),
        ('range-one-address', 'single', '10.77.0.10,10.77.0.10'),
        ('range-repeat', 'first', '10.77.0.10,10.77.0.14'),
        ('range-repeat', 'second', '10.77.0.20,10.77.0.24'),
    ]
    for prefix in ['lan', 'red', 'dead', '1234', '1.2.3', '2001:db8::1', '',
                   'set:dead', 'set:pool', 'tag:match', 'net:match', 'tag:!blocked',
                   'set:,red', 'tag:,net:,set:', 'set:a,set:b', 'red,blue']:
        values.append(('range-prefix-grammar', 'prefix-'+str(len(values)), prefix+',10.77.0.10,10.77.0.14'))
    for name, value in [
        ('range-tags', 'tag:known,net:lan,10.77.0.10,10.77.0.14'),
        ('range-filter-conjunction', 'tag:known,tag:!blocked,net:lan,10.77.0.10,10.77.0.14'),
        ('range-empty-selectors', 'tag:,net:,set:,10.77.0.10,10.77.0.14'),
    ]:
        values.append((name, name, value))
    for value in ['', '0', '119S', '121s', '1m', '2M', '1H', '1D', '1W', 'h',
                  'infinite', 'deprecated', 'DEPRECATED', 'word', '-1', '1 h',
                  '2147483647', '2147483648', '4294967295', '4294967296',
                  '4294967297', '2147483647w', '18446744073709551616']:
        group = ('range-wide-lease' if any(c.isdigit() for c in value) and len(value)>8
                 else 'range-infinite-deprecated' if value in ('infinite','deprecated','DEPRECATED')
                 else 'range-lease-grammar')
        values.append((group, 'lease-'+str(len(values)), '10.77.0.10,10.77.0.14,'+value))
    for value in [
        '10.77.0.10,10.77.0.14,255.255.255.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.200',
        '10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0,600',
        '10.77.0.10,10.77.0.14,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.0.255.0',
        '10.77.0.10,10.78.0.14,255.255.255.0',
        '10.77.0.10,10.77.0.14,10.77.0.255',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600,extra',
        '10.77.0.10,static', '10.77.0.10,proxy',
    ]:
        values.append(('range-mask-grammar', 'mask-'+str(len(values)), value))
    for value in [
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255',
        '10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600',
    ]:
        values.append(('range-broadcast-grammar', 'broadcast-'+str(len(values)), value))
    for value in ['10.77.0.10', 'bad', '10.77.0.10,broken', '10.77.0.10,10.77.0.14,1.2.3',
                  '::,constructor:br-lan,ra-stateless', '2001:db8::10,2001:db8::20',
                  '0.0.0.0,255.255.255.255', '0.0.0.0,255.255.255.255,0.0.0.0']:
        values.append(('range-invalid','invalid-'+str(len(values)),value))
    for value in [
        '2001:db8::10,2001:db8::20',
        '::,constructor:br-lan,ra-stateless',
        '::,ra-only',
    ]:
        values.append(('range-ipv6', 'ipv6-'+str(len(values)), value))
    for value in [
        '0.0.0.0,255.255.255.255',
        '0.0.0.0,255.255.255.255,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600,extra',
    ]:
        values.append(('range-full-address-space', 'full-'+str(len(values)), value))
    cases = []
    for group, name, value in values:
        case = {'name': group+'--'+name, 'group': group, 'ranges': [value], 'events': []}
        cases.append(case)
    # A repeated declaration must remain one configuration so C's prepend
    # order is observable by the parser driver.
    repeat = next(case for case in cases if case['name'] == 'range-repeat--first')
    repeat['ranges'] = ['10.77.0.10,10.77.0.14', '10.77.0.20,10.77.0.24']
    cases.remove(next(case for case in cases if case['name'] == 'range-repeat--second'))
    groups = {
        'range-basic': ['CFG-01', 'SELECT-03', 'LIFE-01'],
        'range-reverse': ['CFG-01'],
        'range-one-address': ['CFG-01', 'SELECT-03', 'SELECT-09'],
        'range-repeat': ['CFG-01'],
        'range-prefix-grammar': ['CFG-02', 'CFG-03', 'CFG-04', 'CFG-09'],
        'range-tags': ['CFG-03'],
        'range-filter-conjunction': ['CFG-03', 'SELECT-01'],
        'range-empty-selectors': ['CFG-04'],
        'range-lease-grammar': ['CFG-06'],
        'range-lease-wire': ['CFG-06', 'LEASE-01'],
        'range-infinite-deprecated': ['CFG-06', 'CFG-07'],
        'range-wide-lease': ['CFG-08'],
        'range-mask-grammar': ['CFG-05', 'CFG-09'],
        'range-broadcast-grammar': ['CFG-05', 'LEASE-02'],
        'range-invalid': ['CFG-09'],
        'range-ipv6': ['CFG-09'],
        'range-full-address-space': ['CFG-08', 'CFG-09'],
    }
    for case in cases:
        case['boundaries'] = groups.get(case['group'], [])
    return cases


def service_cases():
    def event(name, action='discover', **fields):
        return dict(id=name, action=action, flags=0x8000, **fields)
    def row(name, ranges, events, extra='', boundaries=(), **fields):
        value = dict(name=name, group=name.split('--')[0], ranges=ranges, events=events,
                     extra=extra, boundaries=list(boundaries))
        value.update(fields)
        return value

    yield row('range-basic--dora', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer'), event('ack', 'select', address='assigned'),
               event('release', 'release', address='assigned')],
              boundaries=['CTX-01', 'CTX-02', 'SELECT-03', 'SELECT-09', 'LIFE-01', 'LIFE-02', 'LIFE-03'])
    yield row('range-reverse--offer', ['10.77.0.14,10.77.0.10,255.255.255.0,600'],
              [event('offer')], boundaries=['CFG-01'])
    yield row('range-one-address--exhaust', ['10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('first'), event('ack', 'select', address='assigned'), event('exhausted', client=2)],
              boundaries=['CFG-01', 'SELECT-03', 'SELECT-08', 'SELECT-09'])
    for name, tail in [('absent',''),('empty',','),('deprecated',',deprecated'),('infinite',',infinite'),
                       ('minimum',',0'),('wide',',4294967297')]:
        yield row('range-lease-wire--'+name, ['10.77.0.10,10.77.0.14'+tail], [event('offer')],
                  boundaries=['CFG-06', 'CFG-07', 'CFG-08', 'LEASE-01'])
    yield row('range-static--known-unknown', ['10.77.0.0,static,255.255.255.0,600'],
              [event('known'), event('ack', 'select', address='10.77.0.40'), event('unknown', client=2)],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n',
              boundaries=['SELECT-04', 'SELECT-05', 'SELECT-08'])
    yield row('range-proxy--ordinary-pxe', ['10.77.0.0,proxy,255.255.255.0,600'],
              [event('ordinary'), event('pxe', packet={'extra': [[60, b'PXEClient'.hex()], [93, '0000']]}, prl=[43, 60])],
              'pxe-service=0,Range fixture,boot.bin\n', boundaries=['SELECT-06', 'SELECT-07'])
    yield row('range-tag-priority--matched', ['10.77.0.10,10.77.0.10,255.255.255.0,600',
                                           'tag:selected,set:chosen,10.77.0.20,10.77.0.20,255.255.255.0,600'],
              [event('without-tag'), event('with-tag', packet={'extra': [[60, b'Matrix'.hex()]]})],
              'dhcp-vendorclass=set:selected,Matrix\ndhcp-option=tag:chosen,224,2\n',
              boundaries=['SELECT-01', 'SELECT-02', 'LEASE-02'])
    yield row('range-filter-conjunction--negative',
              ['tag:known,net:lan,10.77.0.10,10.77.0.11,255.255.255.0,600',
               '10.77.0.20,10.77.0.21,255.255.255.0,600'],
              [event('untagged'), event('known', packet={'extra': [[60, b'Matrix'.hex()]]})],
              'dhcp-vendorclass=set:known,Matrix\n', boundaries=['CFG-03', 'SELECT-01'])
    yield row('range-set-tag-stage--options',
              ['tag:selected,set:chosen,10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('matched', packet={'extra': [[60, b'Matrix'.hex()]]})],
              'dhcp-vendorclass=set:selected,Matrix\ndhcp-option=tag:chosen,224,2\n',
              boundaries=['SELECT-02', 'LEASE-02'])
    yield row('range-derived-mask--offer', ['10.77.0.10,10.77.0.14'], [event('offer')],
              boundaries=['CTX-01', 'CTX-02'])
    yield row('range-inconsistent-derived--none', ['10.77.0.10,10.78.0.14'], [event('offer')],
              boundaries=['CTX-01', 'CTX-06'])
    yield row('range-mask-broadcast--explicit-zero', ['10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0,600'],
              [event('offer', prl=[1, 3, 28, 51, 58, 59])], boundaries=['CTX-02', 'LEASE-02'])
    yield row('range-interface-aliases--first-local', ['10.77.0.10,10.77.0.14'], [event('offer')],
              server_aliases=['10.77.0.2'], boundaries=['CTX-03', 'CTX-04'])
    yield row('range-context-order--two-pools',
              ['10.77.0.20,10.77.0.21,255.255.255.0,600', '10.77.0.10,10.77.0.11,255.255.255.0,600'],
              [event('first'), event('second', client=2)], boundaries=['CTX-03', 'SELECT-10'])
    yield row('range-multi-interface--guest', ['10.77.0.10,10.77.0.14'],
              [event('lan'), event('guest', client=2, guest=True)], two_interfaces=True,
              boundaries=['CTX-04', 'CTX-06'])
    yield row('range-remote-selectors--link-selection', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('relay', packet={'giaddr': '10.77.0.2',
                                       'extra': [[118, socket.inet_aton('10.77.0.0').hex()],
                                                 [82, '0b040a4d0001']]})],
              boundaries=['CTX-05', 'SELECT-10'])
    yield row('range-remote-classful--fallback', ['10.77.0.10,10.77.0.14'],
              [event('relay', packet={'giaddr': '10.77.0.2'})], boundaries=['CTX-05'])
    yield row('range-requested-address--eligible', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('discover'), event('requested', 'select', address='10.77.0.12')], boundaries=['SELECT-04'])
    yield row('range-reserved-and-leases--skip', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('first'), event('second', client=2), event('decline', 'decline', address='assigned'),
               event('release', 'release', address='assigned')],
              'dhcp-host='+dhcp.mac(3)+',10.77.0.11\n', boundaries=['SELECT-04', 'SELECT-08', 'SELECT-09'])
    yield row('range-narrow-priority--static',
              ['10.77.0.10,10.77.0.14,255.255.255.0,600', '10.77.0.0,static,255.255.255.0,600'],
              [event('known', client=1, address='10.77.0.40')],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n', boundaries=['SELECT-05', 'LEASE-03'])
    yield row('range-bootp-static--known', ['10.77.0.0,static,255.255.255.0,600'],
              [event('bootp', 'bootp')], 'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n',
              boundaries=['SELECT-06'])
    yield row('range-bootp-dynamic--permission', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('bootp', 'bootp')], 'bootp-dynamic\n', boundaries=['SELECT-06'])
    yield row('range-mixed-proxy--head', ['10.77.0.0,proxy,255.255.255.0,600',
                                          '10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('ordinary'), event('pxe', packet={'extra': [[60, b'PXEClient'.hex()], [93, '0000']]})],
              'pxe-service=0,Range fixture,boot.bin\n', boundaries=['SELECT-07', 'SELECT-10'])
    yield row('range-class-c-ends--reserved', ['10.77.0.0,10.77.0.255,255.255.255.0,600'],
              [event('offer'), event('second', client=2)], boundaries=['SELECT-08'])
    yield row('range-selecting-context-chain--server-id',
              ['10.77.0.10,10.77.0.11,255.255.255.0,600', '10.77.0.20,10.77.0.21,255.255.255.0,600'],
              [event('selected', 'select', address='10.77.0.20', server_id='10.77.0.1')],
              boundaries=['SELECT-10'])
    yield row('range-host-and-client-lease--floor', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('host', packet={'extra': [[50, socket.inet_aton('10.77.0.10').hex()]]})],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.10,60\n', boundaries=['LEASE-01'])
    yield row('range-restart-renew--existing', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer'), event('renew', 'renew', address='assigned')], boundaries=['LEASE-03'])
    yield row('range-probe-free--icmp', ['10.79.0.10,10.79.0.14,255.255.255.0,600'],
              [event('offer')], server_aliases=['10.79.0.1'], no_ping=False, boundaries=['PROBE-01'])
    yield row('range-probe-conflict--occupied', ['10.79.0.10,10.79.0.14,255.255.255.0,600'],
              [event('offer'), event('second', client=2)], server_aliases=['10.79.0.1'], no_ping=False,
              boundaries=['PROBE-01', 'PROBE-08'])
    yield row('range-probe-bypass--no-ping', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer')], boundaries=['PROBE-01'])
    yield row('range-probe-cache--same-client', ['10.79.0.10,10.79.0.14,255.255.255.0,600'],
              [event('discover'), event('repeat')], server_aliases=['10.79.0.1'], no_ping=False,
              boundaries=['PROBE-02', 'PROBE-08'])
    for fault in ['socket', 'send', 'receive', 'cancel']:
        yield row('range-probe-'+fault+'-failure--planned', ['10.79.0.10,10.79.0.14,255.255.255.0,600'], [],
                  server_aliases=['10.79.0.1'], no_ping=False, planned_only=True,
                  fault_injection='icmp-'+fault,
                  boundaries=['PROBE-03' if fault == 'socket' else 'PROBE-04' if fault == 'send'
                              else 'PROBE-05' if fault == 'receive' else 'PROBE-07'])
    yield row('range-probe-progress--dns', ['10.79.0.10,10.79.0.14,255.255.255.0,600'],
              [event('offer'), event('dns', action='discover')], server_aliases=['10.79.0.1'], no_ping=False,
              coexistence=True, boundaries=['PROBE-06'])


def configuration(case):
    lines=['no-hosts','no-resolv','user=root','group=root','port=15353',
           'interface=br-lan','host-record=matrix.ready,8.8.8.8',
           'dhcp-authoritative','dhcp-leasefile=/m2/range.leases','pid-file=/m2/range.pid']
    if case.get('no_ping', True):
        lines.insert(5, 'no-ping')
    lines.extend('dhcp-range='+value for value in case['ranges'])
    if case.get('two_interfaces'):
        lines.extend(['interface=br-guest',
                      'dhcp-range=10.78.0.10,10.78.0.14,255.255.255.0,600'])
    return '\n'.join(lines)+'\n'+case.get('extra','')


def lease_snapshot(root, observed_at, durations):
    file=root/'m2/range.leases'; text=file.read_text() if file.exists() else ''
    rows=[]
    for line in text.splitlines():
        fields=line.split()
        if not fields: continue
        if fields[0].isdigit():
            expires=int(fields[0]); address=fields[2]
            if expires:
                duration=durations[address]
                assert observed_at-3+duration <= expires <= observed_at+1+duration, (fields,duration)
                fields[0]='finite-'+str(duration)
            else: fields[0]='infinite'
        rows.append(fields)
    return text,sorted(rows)


def decode(raw):
    if raw['reply'] is None: return None
    wire=bytes.fromhex(raw['reply']);opts=options(wire);values={code:bytes.fromhex(value) for code,value in opts}
    return {'wire':raw['reply'],'options':opts,'status':values.get(53,b'\0')[0],
            'address':socket.inet_ntoa(wire[16:20]),'server':socket.inet_ntoa(values[54]) if 54 in values else None,
            'lease_time':int.from_bytes(values[51],'big') if 51 in values else None,'destination':raw['destination']}


def run(root, side, case, folder, syntax_only):
    folder.mkdir();text=configuration(case);(root/'m2/range.conf').write_text(text);(folder/'config').write_text(text)
    for name in ['range.leases','range.pid']:(root/'m2'/name).unlink(missing_ok=True)
    syntax=subprocess.run(command(root,side,'--test','-C','/m2/range.conf'),capture_output=True,timeout=5)
    result={'status':'failed','syntax':{'exit':syntax.returncode,'stdout':syntax.stdout.decode(errors='replace'),
            'stderr':syntax.stderr.decode(errors='replace')},'rows':[],'planned':len(case['events']), 'startup':None}
    (folder/'syntax.stdout').write_bytes(syntax.stdout);(folder/'syntax.stderr').write_bytes(syntax.stderr)
    if syntax_only or case.get('planned_only'):
        result['status']='ok' if syntax.returncode in (0,1) else 'failed'
        if case.get('planned_only'):
            result['execution'] = 'planned-only'
            result['fault_injection'] = case.get('fault_injection')
        save(folder/'observed.json',result);return result
    network=process=None
    try:
        network=dhcp.setup_network(case)
        with (folder/'stdout').open('wb') as stdout,(folder/'stderr').open('wb') as stderr:
            process=subprocess.Popen(command(root,side,'-k','-C','/m2/range.conf'),stdout=stdout,stderr=stderr,start_new_session=True)
            deadline=time.monotonic()+3
            while process.poll() is None and time.monotonic()<deadline:
                try:
                    if dhcp.dns_health()['records'][0]['data']=='8.8.8.8':break
                except (socket.timeout,OSError):time.sleep(.01)
            ready=process.poll() is None and time.monotonic()<deadline
            result['startup']={'ready':ready,'exit':process.poll()}
            if not ready:
                if syntax.returncode==0:raise AssertionError('valid config did not start')
            else:
                result['identity']=process_identity(root,process.pid)
                assigned={};durations={}
                for index,source_event in enumerate(case['events']):
                    pre_health = dhcp.dns_health() if case.get('coexistence') else None
                    wire_source = copy.deepcopy(source_event)
                    if wire_source.get('action') == 'bootp':
                        wire_source['action'] = 'discover'
                    event=dhcp.wire_event(wire_source,assigned)
                    if source_event.get('action') == 'bootp':
                        # The shared packet helper has no BOOTP action because
                        # other families use the DHCP matrix.  Keep this
                        # driver-local conversion explicit and preserve all
                        # other event fields for the paired request.
                        event['packet']['kind'] = 0
                    output=network.exec(sys.executable,str(Path(dhcp.__file__).resolve()),'--client',json.dumps({'event':event,'xid':0xb500+index}))
                    raw=json.loads(output.stdout);observed=decode(raw);save(folder/f'{index:03}.raw.json',raw)
                    if observed and observed['status'] in (2,5):
                        assigned[str(event.get('client',1))]=observed['address']
                        if observed['lease_time'] is not None:durations[observed['address']]=observed['lease_time']
                    text,leases=lease_snapshot(root,time.time(),durations);(folder/f'{index:03}.leases').write_text(text)
                    row = {'id':event['id'], 'response':observed, 'leases':leases,
                           'health':dhcp.dns_health()}
                    if pre_health is not None:
                        row['pre_health'] = pre_health
                    result['rows'].append(row)
            result['status']='ok'
    except Exception as error:result['error']=repr(error)
    finally:
        if process is not None:
            ended=stop(process);result['exit']=process.returncode;result['forced']=ended['forced'];result['reaped']=not Path(f'/proc/{process.pid}').exists()
        if network is not None:
            result['network_cleanup']=network.close()
            if result['network_cleanup']['forced'] or result['network_cleanup']['returncode']!=-signal.SIGTERM:
                result['status']='failed'
        result['interfaces_clean']=[name for _,name in socket.if_nameindex()]==['lo'];result['pid_removed']=not(root/'m2/range.pid').exists()
        if not result['interfaces_clean'] or not result['pid_removed'] or result.get('forced'):result['status']='failed'
        if result.get('exit') != (0 if syntax.returncode==0 else 1):result['status']='failed'
        save(folder/'observed.json',result)
    return result


def comparable(observed):
    value=copy.deepcopy(observed)
    for stream in ['stdout','stderr']:
        value['syntax'][stream]=value['syntax'][stream].replace('dnsmasq-rs:','dnsmasq:')
    return {key:value.get(key) for key in ['status','syntax','startup','rows','exit','forced','reaped','interfaces_clean','pid_removed']}


def boundary_plan(cases):
    """Describe scheduled, planned-only and missing family boundaries."""
    rows = {}
    for boundary in BOUNDARY_IDS:
        selected = [case for case in cases if boundary in case.get('boundaries', [])]
        rows[boundary] = {
            'cases': [case['name'] for case in selected],
            'planned_only': [case['name'] for case in selected if case.get('planned_only')],
            'scheduled': bool(selected),
        }
    return {
        'schema': 'm5-dhcp-range-boundary-plan-v1',
        'boundaries': rows,
        'missing': [boundary for boundary, row in rows.items() if not row['scheduled']],
        'planned_only': sorted({name for row in rows.values() for name in row['planned_only']}),
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--side',choices=['c','rust','both'],default='both')
    parser.add_argument('--syntax',action='store_true');parser.add_argument('--case',action='append');parser.add_argument('--source-commit')
    args=parser.parse_args();assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert [name for _,name in socket.if_nameindex()]==['lo'];assert 'private' in args.out.resolve().parts and not args.out.exists()
    root=prepare(args.image_root,None,args.out/'image',args.rust);(root/'m2').chmod(0o777)
    cases=syntax_cases() if args.syntax else list(service_cases())
    if args.case:cases=[case for case in cases if case['name'] in args.case or case['group'] in args.case]
    assert cases;save(args.out/'plan.json',cases)
    selected_plan = boundary_plan(cases)
    # Keep the complete CFG+runtime catalogue alongside a filtered run.  A
    # syntax-only invocation therefore records which service rows were not
    # selected without pretending that parser checks covered them.
    catalog = boundary_plan(syntax_cases() + list(service_cases()))
    selected_plan['catalog'] = catalog
    save(args.out/'boundary-plan.json', selected_plan)
    result={'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'source_commit':args.source_commit,
            'tool_sha256':sha256(__file__),'comparison_executed':args.side=='both','cases':[],'failures':[]}
    for case in cases:
        folder=args.out/case['name'];folder.mkdir();observations={}
        for side in ['c','rust'] if args.side=='both' else [args.side]:observations[side]=run(root,side,case,folder/side,args.syntax)
        errors=[]
        if any(row['status']!='ok' for row in observations.values()):errors.append('failed-side')
        if args.side=='both' and comparable(observations['c'])!=comparable(observations['rust']):errors.append('difference')
        result['cases'].append({'name':case['name'],'group':case['group'],'errors':errors})
        if errors:result['failures'].append(case['name'])
        save(args.out/'result.json',result)
    result['passed']=not result['failures'];save(args.out/'result.json',result)
    print(json.dumps({'passed':result['passed'],'cases':len(cases),'failures':result['failures']}));return int(not result['passed'])


if __name__=='__main__':raise SystemExit(main())
