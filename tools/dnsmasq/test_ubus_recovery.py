#!/usr/bin/env python3
"""Real Rust9/image ubus outage, exact ACL, retry and shutdown acceptance.

Run through run_isolated.sh. Inputs are explicit and output must be fresh/private.
The only policy override is the supplied package ACL in the disposable overlay.
No production service, host account, router or global bus is touched.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import threading
import subprocess
import sys
import time
import traceback

from m2_lifecycle import Scenario
from m2_rootfs import bind_unix_socket, image_path, process_identity, sha256
from dns_service_probe import query, semantics, exact_read
from test_deploy_oracle import CLIENT, host, wait

BINARIES = {'ubusd':'sbin/ubusd','procd':'sbin/procd','netifd':'sbin/netifd',
            'rpcd':'sbin/rpcd','logd':'sbin/logd','uci':'sbin/uci',
            'reload-config':'sbin/reload_config','fw4':'sbin/fw4','httpd':'usr/sbin/uhttpd'}

class StalledBus:
    """Only a failed bus peer is synthetic; DNS/DHCP remain real services."""
    def __init__(self,path,stage):
        path.unlink(missing_ok=True)
        self.stage=stage;self.rows=[];self.peers=[];self.threads=[];self.stop=threading.Event()
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        bind_unix_socket(self.socket,path);os.chmod(path,0o777)
        self.socket.listen(32);self.socket.settimeout(.05)
        self.thread=threading.Thread(target=self.accept);self.thread.start()
    def accept(self):
        while not self.stop.is_set():
            try:peer,_=self.socket.accept()
            except socket.timeout:continue
            except OSError:return
            self.peers.append(peer)
            thread=threading.Thread(target=self.serve,args=(peer,));thread.start();self.threads.append(thread)
    def serve(self,peer):
        pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        row={'pid':pid,'uid':uid,'gid':gid,'started':time.monotonic(),'requests':[]};self.rows.append(row)
        try:
            peer.settimeout(3)
            if self.stage!='hello':
                time.sleep(.03)
                peer.sendall(struct.pack('!BBHII',0,0,0,42,4))
                wire=exact_read(peer,12)
                wire+=exact_read(peer,(struct.unpack('!I',wire[8:12])[0]&0xffffff)-4)
                row['requests'].append(wire.hex())
                if self.stage=='second':
                    time.sleep(.03)
                    seq=struct.unpack('!H',wire[2:4])[0]
                    obj=struct.pack('!II',(3<<24)|8,77)
                    status=struct.pack('!II',(1<<24)|8,0)
                    for kind,fields in [(2,obj),(1,status)]:
                        peer.sendall(struct.pack('!BBHI',0,kind,seq,0)+struct.pack('!I',4+len(fields))+fields)
                    wire=exact_read(peer,12)
                    wire+=exact_read(peer,(struct.unpack('!I',wire[8:12])[0]&0xffffff)-4)
                    row['requests'].append(wire.hex())
            while peer.recv(4096):pass
        except (OSError,EOFError) as error:row['error']=type(error).__name__
        finally:
            row['elapsed']=time.monotonic()-row['started'];row['closed']=True;peer.close()
    def close(self):
        self.stop.set();self.socket.close();self.thread.join(1)
        for peer in self.peers:
            try:peer.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        for thread in self.threads:thread.join(4)

class Recovery(Scenario):
    def __init__(self, args):
        super().__init__(args)
        self.result = {'source_commit':args.source_commit,'side':args.implementation,
                       'scenario':args.scenario,'expected':args.expect,'passed':False,
                       'candidate_sha256':sha256(args.rust_binary),'tool_sha256':sha256(Path(__file__)),'steps':{},'support':{}}
        shutil.copy2(__file__,self.out/'driver.py')
        self.row = self.result['steps']
        self.acl = self.root/'usr/share/acl.d/dnsmasq_acl.json'
        self.result['stock_acl'] = json.loads(self.acl.read_text())
        self.result['stock_acl_sha256'] = sha256(self.acl)
        assert self.result['stock_acl']['publish'] == ['dnsmasq']
        self.fixed_acl = args.acl.read_bytes()
        self.result['stock_init_sha256']=sha256(self.root/'etc/init.d/dnsmasq')
        self.result['supplied_init_sha256']=sha256(args.init)
        if not args.stock_jail: shutil.copy2(args.init,self.root/'etc/init.d/dnsmasq')
        policy=json.loads(self.fixed_acl)
        assert policy['user']=='dnsmasq' and policy['publish']==['dnsmasq','dnsmasq.dns']
        assert policy['access']==self.result['stock_acl']['access']
        if args.scenario != 'acl-recovery': self.acl.write_bytes(self.fixed_acl)
        self.result['supplied_acl_sha256']=sha256(args.acl)
        for name, relative in BINARIES.items():
            target=image_path(self.root,relative,follow_leaf=False)
            if target.is_symlink(): target.unlink()
            shutil.copy2(args.support_bins/(name+'-rs'),target)
        self.result['installed_support']={k:sha256(self.root/v) for k,v in BINARIES.items()}
        shutil.copy2(args.publish_probe,self.root/'m2/publish-probe')
        (self.root/'m2/publish-probe').chmod(0o755)
        self.result['publish_probe_sha256']=sha256(args.publish_probe)
        self.run('/sbin/uci','set','dhcp.m2.logfacility=/tmp/f5-dns.log')
        self.run('/sbin/uci','commit','dhcp')

    def dnsmasq(self):
        expected=sha256(self.root/'usr/sbin/dnsmasq')
        found=[]
        for p in Path('/proc').glob('[0-9]*/exe'):
            try:
                if os.readlink(p).endswith('/usr/sbin/dnsmasq') and sha256(p)==expected:
                    found.append(int(p.parent.name))
            except OSError: pass
        if not found: return None
        assert len(found)==1,found
        pid=found[0]
        return {'pid':pid,'sha256':sha256(Path(f'/proc/{pid}/exe')),
                'status':Path(f'/proc/{pid}/status').read_text()}

    def objects(self):
        return self.run('/bin/ubus','list','dnsmasq*',check=False).stdout.splitlines()

    def client(self):
        result=subprocess.run(['nsenter','-t',os.environ['DNSMASQ_CLIENT_PID'],'-n',
                               sys.executable,'-c',CLIENT],capture_output=True,text=True,
                              env=dict(os.environ,PYTHONPATH=str(Path(__file__).parent)+os.pathsep+os.environ.get('PYTHONPATH','')),timeout=20)
        assert result.returncode==0,result.stderr
        return json.loads(result.stdout)

    def start_bus(self):
        self.bus_process=self.start('/sbin/ubusd')
        wait(lambda:self.run('/bin/ubus','list',check=False).returncode==0,'ubus listening')
        self.result['support']['ubusd']=process_identity(self.root,self.bus_process.pid)

    def boot(self):
        self.start_bus()
        for binary,obj in [('/sbin/logd','log'),('/sbin/procd','service'),('/sbin/netifd','network'),('/sbin/rpcd','uci')]:
            p=self.start(binary)
            wait(lambda:self.run('/bin/ubus','list',obj,check=False).returncode==0,obj)
            self.result['support'][binary]=process_identity(self.root,p.pid)
        wait(lambda:self.bus('network.interface.lan','status').get('up'),'LAN')
        self.run('/etc/init.d/dnsmasq','start')
        self.expect_dns('lifecycle.lan','192.0.2.51')
        self.row['initial']=self.dnsmasq()
        status=dict(line.split(':',1) for line in self.row['initial']['status'].splitlines() if ':' in line)
        self.row['jail_credentials']={k:status[k].split() for k in ['Uid','Gid','CapEff','CapPrm','NoNewPrivs','Seccomp']}
        assert self.row['jail_credentials']['Uid']==['453']*4
        assert self.row['jail_credentials']['Gid']==['453']*4
        assert self.row['jail_credentials']['CapEff']==['0000000000003400']
        assert self.row['jail_credentials']['CapPrm']==['0000000000003400']
        self.row['initial_client']=wait(self.client,'initial client')
        self.row['initial_metrics']=self.bus('dnsmasq','metrics')
        self.row['initial_socket']=self.socket_identity()
        pid=self.row['initial']['pid']
        try:
            fd=os.open(f'/proc/{pid}/root/var/run/ubus/.f5-write-test',os.O_CREAT|os.O_WRONLY,0o600)
        except OSError as error:
            self.row['jail_bus_directory_write_errno']=error.errno
            if not self.args.stock_jail: assert error.errno==30,error
        else:
            os.close(fd);os.unlink(f'/proc/{pid}/root/var/run/ubus/.f5-write-test')
            assert self.args.stock_jail,'jail bus directory was writable'
        assert self.objects()==['dnsmasq','dnsmasq.dns']

    def socket_identity(self):
        pid=self.row['initial']['pid'];paths={}
        for label,root in [('fixture',self.root),('jail',Path(f'/proc/{pid}/root'))]:
            directory=root/'var/run/ubus'
            paths[label]={'directory_inode':directory.stat().st_ino,'socket_inode':(directory/'ubus.sock').stat().st_ino}
        return paths

    def stop_bus(self):
        self.bus_process.terminate();self.bus_process.wait(3)

    def log(self):
        return (self.root/'tmp/f5-dns.log').read_text(errors='replace')

    def ticks(self):
        fields=Path(f"/proc/{self.row['initial']['pid']}/stat").read_text().split(') ',1)[1].split()
        return int(fields[11])+int(fields[12])

    def publish(self,name,uid=453,hold=False):
        argv=['chroot',f'--userspec={uid}:{uid}',str(self.root),'/m2/publish-probe',name]
        if hold:
            log=(self.out/'holder.log').open('w')
            p=subprocess.Popen(argv+['--hold'],stdout=log,stderr=subprocess.STDOUT)
            self.children.append(p)
            wait(lambda:(self.out/'holder.log').read_text().strip(),'publisher ready')
            assert json.loads((self.out/'holder.log').read_text())['status']==0
            return p
        p=subprocess.run(argv,capture_output=True,text=True,timeout=3)
        return {'exit':p.returncode,'status':json.loads(p.stdout)['status']}

    def startup_boundaries(self):
        self.run('/etc/init.d/dnsmasq','stop')
        wait(lambda:self.dnsmasq() is None,'stop before ACL controls')
        probes={}
        for name in ['dnsmasq','dnsmasq.dns','dnsmasq.extra','dnsmasq.dns.extra','dnsmasqevil','service']:
            result=self.publish(name)
            assert result==({'exit':0,'status':0} if name in ['dnsmasq','dnsmasq.dns'] else {'exit':1,'status':2}),(name,result)
            probes[name]=result
        probes['nobody/dnsmasq']=self.publish('dnsmasq',65534)
        assert probes['nobody/dnsmasq']=={'exit':1,'status':2}
        self.row['publish_acl_controls']=probes
        base=['/usr/sbin/dnsmasq','--keep-in-foreground','--conf-file=/dev/null','--no-hosts','--no-resolv','--port=0','--pid-file=','--enable-ubus=dnsmasq']
        holder=self.publish('dnsmasq.dns',0,True)
        try:
            p=self.run(*base,check=False)
            assert p.returncode==5 and 'UBus error:' in p.stderr,(p.returncode,p.stderr)
            assert self.objects()==['dnsmasq.dns'],self.objects()
            self.row['startup_second_registration_failure']={'exit':p.returncode,'stderr':p.stderr,'objects':self.objects()}
        finally:
            holder.terminate();holder.wait(3)
        p=subprocess.run(['chroot','--userspec=65534:65534',str(self.root),*base],capture_output=True,text=True,timeout=3)
        assert p.returncode==5 and 'UBus error:' in p.stderr,(p.returncode,p.stderr)
        self.row['startup_unauthorized']={'exit':p.returncode,'stderr':p.stderr}

    def execute(self):
        self.boot()
        scenario=self.args.scenario
        if scenario=='startup':
            self.startup_boundaries()
        else:
            ticks=self.ticks();self.stop_bus()
            # No DNS/DHCP traffic during this interval: reconnection has to use
            # its own deadline, not incidental client or periodic activity.
            time.sleep(3.3)
            self.row['absent_cpu_ticks']=self.ticks()-ticks
            self.row['absent_log']=self.log()
            assert self.row['absent_cpu_ticks']<=10,self.row['absent_cpu_ticks']
            assert self.log().count('Cannot set UBus listeners: no connection') in ([0,1] if self.args.expect=='disabled' else [1])
            if scenario=='stop-absent' or scenario.startswith('stall-'):
                stalled=None
                try:
                    if scenario.startswith('stall-'):
                        stalled=StalledBus(self.root/'var/run/ubus/ubus.sock',scenario[6:])
                        latencies=[];end=time.monotonic()+3.4
                        while time.monotonic()<end:
                            for tcp in (False,True):
                                packet=query('lifecycle.lan',1)
                                with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
                                    client.settimeout(.35);started=time.monotonic()
                                    if tcp:
                                        client.connect(('192.168.1.1',53));client.sendall(struct.pack('!H',len(packet))+packet)
                                        reply=exact_read(client,struct.unpack('!H',exact_read(client,2))[0])
                                    else:
                                        client.sendto(packet,('192.168.1.1',53));reply=client.recv(4096)
                                    latencies.append({'tcp':tcp,'seconds':time.monotonic()-started})
                                assert [r['data'] for r in semantics(reply)['records'] if r['section']=='answer']==['192.0.2.51']
                            time.sleep(.01)
                        self.row['stalled_dns_latencies']=latencies
                        self.row['stalled_client']=wait(self.client,'DHCP during stalled bus')
                        pid=self.row['initial']['pid']
                        required={'hello':0,'registration':1,'second':2}[scenario[6:]]
                        wait(lambda:any(row['pid']==pid and not row.get('closed') and len(row['requests'])>=required for row in stalled.rows),'target retry stage in progress',seconds=3)
                        self.row['term_stage_required_requests']=required
                        self.row['term_stage_observed_requests']=[len(row['requests']) for row in stalled.rows if row['pid']==pid and not row.get('closed')]
                        assert any(n>=required for n in self.row['term_stage_observed_requests'])
                    pid=self.row['initial']['pid'];started=time.monotonic();os.kill(pid,signal.SIGTERM)
                    while Path(f'/proc/{pid}').exists() and time.monotonic()-started<3:time.sleep(.002)
                    assert not Path(f'/proc/{pid}').exists(),'TERM during reconnect timed out'
                    self.row['shutdown_seconds']=time.monotonic()-started
                    assert self.row['shutdown_seconds']<.5,self.row['shutdown_seconds']
                finally:
                    if stalled:
                        stalled.close()
                        self.row['stalled_connections']=[row for row in stalled.rows if row['pid']==self.row['initial']['pid']]
                        assert len(self.row['stalled_connections'])>=3
                        assert max(row['elapsed'] for row in self.row['stalled_connections'])<.25
            else:
                self.start_bus()
                self.row['replacement_socket']=self.socket_identity()
                before=self.row['initial_socket'];after=self.row['replacement_socket']
                assert before['fixture']['directory_inode']==after['fixture']['directory_inode']
                assert before['fixture']['socket_inode']!=after['fixture']['socket_inode']
                if not self.args.stock_jail: assert after['jail']==after['fixture'],after
                if scenario=='acl-recovery':
                    time.sleep(3.3)
                    assert not self.objects(),self.objects()
                    self.row['client_while_denied']=wait(self.client,'client during denied registration')
                    wait(lambda:self.log().count('UBus error: Invalid argument')==1,'registration refusal logged')
                    self.row['registration_failure_log']=self.log()
                    self.row['no_partial_main_object']=not self.objects()
                    assert self.row['no_partial_main_object']
                    self.acl.write_bytes(self.fixed_acl)
                    self.bus_process.send_signal(signal.SIGHUP)
                started=time.monotonic()
                if self.args.expect=='disabled':
                    time.sleep(3.3)
                    self.row['after_restart_objects']=self.objects()
                    self.row['client_after_restart']=wait(self.client,'baseline client')
                    self.row['after_client_objects']=self.objects()
                    if 'dnsmasq' in self.row['after_client_objects']:self.row['after_client_metrics']=self.bus('dnsmasq','metrics')
                    assert self.row['after_restart_objects']!=['dnsmasq','dnsmasq.dns']
                else:
                    wait(lambda:self.objects()==['dnsmasq','dnsmasq.dns'],'automatic two-object recovery',seconds=5)
                    self.row['recovery_seconds']=time.monotonic()-started
                    assert self.dnsmasq()['pid']==self.row['initial']['pid']
                    self.row['recovered']=self.dnsmasq()
                    self.row['recovered_metrics']=self.bus('dnsmasq','metrics')
                    subscriber=self.start('/bin/ubus','subscribe','dnsmasq')
                    time.sleep(.2)
                    self.row['recovered_client1']=wait(self.client,'recovered client1')
                    self.row['recovered_client2']=wait(self.client,'recovered client2')
                    wait(lambda:(self.out/'ubus.log').read_text().count('"dhcp.ack"')==2,'two ACK events')
                    time.sleep(1.1)
                    self.row['ack_events']=(self.out/'ubus.log').read_text()
                    assert self.row['ack_events'].count('"dhcp.ack"')==2
                    assert self.objects()==['dnsmasq','dnsmasq.dns']
                    self.row['settled_metrics']=self.bus('dnsmasq','metrics')
                    assert self.row['settled_metrics']['dhcp_ack']-self.row['recovered_metrics']['dhcp_ack']==2
                    subscriber.terminate();subscriber.wait(3)
        self.row['final_log']=self.log()
        self.result['passed']=True
        return self.result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['image-root','rust-binary','support-bins','acl','init','publish-probe','output']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--rust-sha256',required=True);p.add_argument('--source-commit',required=True)
    p.add_argument('--implementation',choices=['c','rust'],default='rust')
    p.add_argument('--scenario',choices=['restart','acl-recovery','stop-absent','stall-hello','stall-registration','stall-second','startup'],required=True)
    p.add_argument('--stock-jail',action='store_true')
    p.add_argument('--expect',choices=['recover','disabled'],default='recover')
    args=p.parse_args();args.jail_procfs=False;args.skip_odhcpd=True
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1' and os.geteuid()==0
    assert sha256(args.rust_binary)==args.rust_sha256
    assert 'private' in args.output.parts and not args.output.exists()
    client=subprocess.Popen(['unshare','--net','sleep','infinity']);scenario=None
    try:
        wait(lambda:os.readlink(f'/proc/{client.pid}/ns/net')!=os.readlink('/proc/self/ns/net'),'client netns',seconds=3)
        for argv in [('ip','link','add','br-lan','type','bridge'),('ip','addr','add','192.168.1.1/24','dev','br-lan'),('ip','link','set','br-lan','up'),('ip','link','add','lan-port','type','veth','peer','name','client0'),('ip','link','set','lan-port','master','br-lan'),('ip','link','set','lan-port','up'),('ip','link','set','client0','netns',str(client.pid)),('nsenter','-t',str(client.pid),'-n','ip','link','set','lo','up'),('nsenter','-t',str(client.pid),'-n','ip','link','set','client0','up')]:host(*argv)
        os.environ['DNSMASQ_CLIENT_PID']=str(client.pid)
        scenario=Recovery(args);result=scenario.execute()
    except Exception:
        result=getattr(scenario,'result',{'passed':False});result.update(passed=False,error=traceback.format_exc())
        if scenario:
            result['failure_log']=scenario.log()
            result['failure_objects']=scenario.objects()
            result['failure_daemon']=scenario.dnsmasq()
            if result['failure_daemon']:
                pid=result['failure_daemon']['pid']
                result['failure_socket_paths']={}
                for label,path in [('fixture',scenario.root/'var/run/ubus/ubus.sock'),('jail',Path(f'/proc/{pid}/root/var/run/ubus/ubus.sock'))]:
                    try:result['failure_socket_paths'][label]={'inode':path.stat().st_ino,'mode':path.stat().st_mode,'uid':path.stat().st_uid}
                    except OSError as error:result['failure_socket_paths'][label]=repr(error)
    finally:
        if scenario:
            (scenario.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');scenario.close()
        client.terminate();client.wait(3)
    print(json.dumps({'scenario':args.scenario,'side':args.implementation,'passed':result['passed'],'error':result.get('error')}))
    return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
