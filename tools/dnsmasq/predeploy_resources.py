#!/usr/bin/env python3
"""Run paired /tmp-only resource windows on an explicitly authorized router.

Input binaries are built separately. Production observations remain in the
private output; publish only derived, redacted results. No service mutation.
"""
import argparse
import hashlib
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', 'openwrt']
BASE = Path(__file__).resolve().parent


def remote(command, **kwargs):
    return subprocess.run(SSH + [command], check=True, capture_output=True, text=True, timeout=20, **kwargs).stdout


def health(out, label, baseline=None):
    command = """cat /proc/3328/stat
cat /proc/meminfo
ubus call network.interface.wan status
ubus call dnsmasq metrics
nslookup openwrt.org 127.0.0.1
ping -c 1 -W 2 1.1.1.1
sha256sum /usr/sbin/dnsmasq /var/etc/dnsmasq.conf.cfg01411c /etc/config/dhcp /etc/config/network
"""
    started = time.time()
    raw = remote(command)
    (out / f'{label}.raw').write_text(raw)
    stat = raw.splitlines()[0].rsplit(')', 1)[1].split()
    available = int(re.search(r'^MemAvailable:\s+(\d+)', raw, re.M)[1])
    hashes = re.findall(r'^([0-9a-f]{64})\s+(/\S+)$', raw, re.M)
    decoder = json.JSONDecoder()
    pos = raw.index('{')
    wan, n = decoder.raw_decode(raw[pos:])
    pos = raw.index('{', pos + n)
    metrics, _ = decoder.raw_decode(raw[pos:])
    row = {'time_unix': started, 'elapsed_seconds': time.time()-started,
           'production_start_ticks': int(stat[19]), 'production_cpu_ticks': int(stat[11])+int(stat[12]),
           'mem_available_kib': available, 'wan_up': wan.get('up') is True,
           'wan_uptime': wan.get('uptime'), 'wan_probe_ok': '1 packets received' in raw, 'dns_ok': bool(re.search(r'^Name:\s+openwrt.org', raw, re.M)),
           'hashes': dict((p,h) for h,p in hashes), 'metrics': metrics}
    if not row['wan_up'] or not row['wan_probe_ok'] or not row['dns_ok'] or available < 65536 or len(hashes) != 4:
        raise RuntimeError(f'production health gate failed: {label}')
    if baseline and (row['production_start_ticks'] != baseline['production_start_ticks'] or row['hashes'] != baseline['hashes']):
        raise RuntimeError(f'production identity/config changed: {label}')
    (out / f'{label}.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def configuration(root, leases):
    # Preserve all effective policy lines; remap resources which could interact
    # with production. Original ethers/config-dir have no effective extra rows.
    common = f'''dhcp-authoritative
domain-needed
localise-queries
expand-hosts
bind-interfaces
listen-address=127.0.0.1
local-service
cache-size=1000
edns-packet-max=1232
domain=lan
local=/lan/
no-hosts
addn-hosts={root}/hosts
no-resolv
server=127.0.0.1#15354@127.0.0.1
stop-dns-rebind
rebind-localhost-ok
dhcp-broadcast=tag:needs-broadcast
user=dnsmasq
group=dnsmasq
dhcp-ignore-names=tag:dhcp_bogus_hostname
dhcp-name-match=set:dhcp_bogus_hostname,localhost
dhcp-name-match=set:dhcp_bogus_hostname,wpad
bogus-priv
server=/bind/
server=/invalid/
server=/local/
server=/localhost/
server=/onion/
server=/test/
dhcp-range=set:lan,127.0.0.100,127.0.0.249,255.0.0.0,12h
no-dhcp-interface=wan
dhcp-alternate-port=15467,15468
port=15353
dhcp-leasefile=@OUT@/leases
pid-file=@OUT@/product.pid
log-facility=@OUT@/service.log
'''
    expiration = int(time.time())+43200
    rows = ''.join(f'{expiration} 02:00:01:00:00:{i:02x} 127.0.0.{120+i} seed{i} *\n' for i in range(leases))
    return common, rows


def socket_proof(root, name, out):
    pid = int(remote(f'cat {root}/{name}/READY').strip())
    raw = remote(f'''cat /proc/{pid}/status
for f in /proc/{pid}/fd/*; do readlink "$f"; done
cat /proc/net/udp /proc/net/udp6 /proc/net/tcp /proc/net/tcp6
''')
    (out / f'{name}-sockets.raw').write_text(raw)
    tracer = int(re.search(r'^TracerPid:\s+(\d+)', raw, re.M)[1])
    inodes = set(re.findall(r'socket:\[(\d+)\]', raw))
    sockets = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields)<10 or not fields[0].endswith(':') or fields[9] not in inodes:
            continue
        addr, port = fields[1].split(':')
        # /proc network tables expose host-endian 32-bit chunks.
        is_loopback = (len(addr)==8 and addr.endswith('7F')) or addr == '00000000000000000000000001000000'
        if not is_loopback or int(port,16) in (53,67):
            raise RuntimeError(f'non-isolated test socket: {fields[1]}')
        sockets.append({'local':fields[1], 'remote':fields[2], 'state':fields[3], 'inode':fields[9]})
    ports = [int(s['local'].split(':')[1],16) for s in sockets]
    if tracer or ports.count(15353)<2 or ports.count(15467)!=1:
        raise RuntimeError(f'listener/tracer proof failed: {ports}, tracer={tracer}')
    proof = {'pid':pid, 'tracer_pid':tracer, 'sockets':sockets}
    (out / f'{name}-sockets.json').write_text(json.dumps(proof,indent=2)+'\n')
    return proof


def cleanup(root, out):
    # Kill only cmdlines containing our unique owned /tmp root, excluding this
    # cleanup shell and its parent. A second scan verifies no test processes.
    command = f'''for f in /proc/[0-9]*/cmdline; do
 p=${{f#/proc/}}; p=${{p%/cmdline}}
 [ "$p" = "$$" ] && continue
 [ "$p" = "$PPID" ] && continue
 case "$(tr '\\000' ' ' < "$f" 2>/dev/null)" in *'{root}/'*) kill "$p" 2>/dev/null || :;; esac
done
sleep 1
rm -rf '{root}'
[ ! -e '{root}' ]
'''
    remote(command)
    raw = remote(f"ps w; test ! -e {root}")
    (out / 'cleanup.raw').write_text(raw)
    remaining = [line for line in raw.splitlines() if root+'/' in line]
    if remaining:
        raise RuntimeError('test processes remain after cleanup')
    sockets=remote('cat /proc/net/udp /proc/net/udp6 /proc/net/tcp /proc/net/tcp6')
    (out / 'cleanup-sockets.raw').write_text(sockets)
    listening=[]
    for line in sockets.splitlines():
        fields=line.split()
        if len(fields)>9 and fields[0].endswith(':'):
            port=int(fields[1].split(':')[1],16)
            if port in (15353,15354,15467,15468) and fields[3] != '06':listening.append(fields[1])
    if listening:raise RuntimeError('test ports remain bound after cleanup')
    (out / 'cleanup.json').write_text(json.dumps({'root_removed':True,'test_processes_remaining':0,'test_ports_bound':0})+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--helpers',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--smoke',action='store_true')
    parser.add_argument('--retain-answer-errors',action='store_true',help='retain failed test answers and continue paired measurements; production health gates still abort')
    parser.add_argument('--windows',default='daily:C,daily:R,daily:R,daily:C,daily:C,daily:R,busy:R,busy:C,busy:C,busy:R')
    args=parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root='/tmp/dnsmasq-audit-c-'+str(int(time.time()))+'-'+uuid.uuid4().hex[:8]
    state={'root':root,'smoke':args.smoke,'windows':[],'artifact_sha256':hashlib.sha256(args.artifact.read_bytes()).hexdigest(),'retain_answer_errors':args.retain_answer_errors}
    save=lambda:(args.output/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    baseline=health(args.output,'initial')
    state['baseline']=baseline;save()
    upload=args.output/'upload';upload.mkdir()
    for profile, count in [('daily',4),('busy',128),('dhcp',128)]:
        config,leases=configuration(root,count)
        (upload/f'{profile}.conf').write_text(config)
        (upload/f'{profile}.leases').write_text(leases)
    (upload/'hosts').write_text('127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n127.0.0.1 router\n::1 router\n')
    created=False
    try:
        remote(f'mkdir {root}')
        created=True
        remote(f'chmod 755 {root}')
        for src,dest in [(args.artifact,'dnsmasq-rs'),(BASE/'predeploy_resource_window.sh','window.sh'),*[(args.helpers/n,n) for n in ('bind','probe','upstream','loadgen')],*[(p,p.name) for p in upload.iterdir()]]:
            subprocess.run(['scp','-O','-q',str(src),'openwrt:'+root+'/'+dest],check=True,timeout=30)
        remote(f'chmod 755 {root}/dnsmasq-rs {root}/bind {root}/probe {root}/upstream {root}/loadgen')
        state['remote_identities']=remote(f'sha256sum {root}/dnsmasq-rs {root}/bind {root}/probe {root}/upstream {root}/loadgen /usr/sbin/dnsmasq')
        observed={Path(line.split()[1]).name:line.split()[0] for line in state['remote_identities'].splitlines()}
        expected={'dnsmasq-rs':state['artifact_sha256'], 'dnsmasq':'097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'}
        expected.update({n:hashlib.sha256((args.helpers/n).read_bytes()).hexdigest() for n in ('bind','probe','upstream','loadgen')})
        if observed!=expected:raise RuntimeError('remote artifact identity mismatch')
        save()
        for index,spec in enumerate(args.windows.split(',')):
            profile,implementation=spec.split(':')
            if profile not in ('daily','busy','dhcp') or implementation not in ('C','R'):raise ValueError(spec)
            name=f'{index+1:02d}-{profile}-{implementation}'
            health(args.output,name+'-before',baseline)
            idle,warm,measure,post=(1,1,4,1) if args.smoke else (20,20,120,20)
            log=(args.output/(name+'.ssh.log')).open('w')
            command=f'sh {root}/window.sh {root} {name} {implementation} {profile} {idle} {warm} {measure} {post}'
            process=subprocess.Popen(SSH+[command],stdout=log,stderr=subprocess.STDOUT)
            start=time.time();row={'name':name,'profile':profile,'implementation':implementation,'start':start,'health':[]};state['windows'].append(row);save()
            ready=False;last_check=0
            try:
                while process.poll() is None:
                    if not ready:
                        if remote(f'[ -f {root}/{name}/READY ] && echo ready || :').strip():
                            row['socket_proof']=socket_proof(root,name,args.output)
                            remote(f'touch {root}/{name}/GO');ready=True;save()
                    if time.time()-last_check>25:
                        label=f'{name}-during-{len(row["health"])}'
                        row['health'].append(health(args.output,label,baseline));last_check=time.time();save()
                        print(json.dumps({'window':name,'elapsed':round(time.time()-start),'health':'ok'}),flush=True)
                    if time.time()-start>235:raise TimeoutError(name)
                    time.sleep(1)
                if process.returncode:raise RuntimeError(f'{name} failed: exit {process.returncode}')
                if not ready:raise RuntimeError('never proved socket isolation')
            finally:
                log.close()
            row['end']=time.time();row['health'].append(health(args.output,name+'-after',baseline));save()
            window=args.output/name;window.mkdir()
            # Retrieve raw files privately, then immediately release tmpfs space.
            with (args.output/(name+'.tar')).open('wb') as target:
                subprocess.run(SSH+[f'tar -C {root}/{name} -cf - .'],stdout=target,check=True,timeout=30)
            subprocess.run(['tar','-xf',str(args.output/(name+'.tar')),'-C',str(window)],check=True)
            if not (window/'COMPLETE').exists():raise RuntimeError('window incomplete')
            if profile=='dhcp':
                proofs=[json.loads(line) for line in (window/'dhcp.named-dns-proof.jsonl').read_text().splitlines()]
                epoch=json.loads((window/'dhcp.json').read_text())['measurement_start_ns']
                if len(proofs)!=20 or {r['client'] for r in proofs}!=set(range(20)) or not all(r['correct'] and r['phase']==0 and r['monotonic_ns']<epoch for r in proofs):
                    raise RuntimeError('named DHCP warmup DNS publication not proved')
                row['named_dhcp_dns_proofs']={'clients':20,'all_correct':True,'all_before_measurement':True};save()

            actual=set(tuple(line.split()) for line in (window/'leases-final').read_text().splitlines())
            expected=set(tuple(line.split()) for line in (upload/(profile+'.leases')).read_text().splitlines())
            if actual!=expected:raise RuntimeError('DHCP lease release/persistence did not converge')
            for mode in ('udp','tcp','dhcp'):
                result=json.loads((window/(mode+'.json')).read_text())
                for phase in ('warmup','measurement'):
                    counters=result[phase]
                    if any(counters[k] for k in ('timeout','wrong','transport_error')) or counters['correct'] != counters['sent']:
                        row.setdefault('answer_errors',[]).append({'mode':mode,'phase':phase,'counters':counters});save()
                        if not args.retain_answer_errors:raise RuntimeError(f'{name}/{mode}/{phase}: incorrect/incomplete workload')
                if result['interrupted'] or result['output_failed']:
                    raise RuntimeError('interrupted workload or failed evidence output')
            remote(f'rm -rf {root}/{name}')
            print(json.dumps({'window':name,'complete':True}),flush=True)
        state['complete']=True;save()
    finally:
        if created:cleanup(root,args.output)
        state['final_health']=health(args.output,'final',baseline);save()


if __name__=='__main__':main()
