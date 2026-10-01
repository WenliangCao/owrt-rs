#!/usr/bin/env python3
"""C/Rust DHCP leasefile lifecycle in an isolated build-host namespace.

Common explicit private configuration; DNS publication is not compared here.
ENOSPC uses a private tmpfs and verifies the real 60-second idle retry.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from dhcp_daemon_smoke import decode


def packet(kind, xid, client=1, address=None, selecting=False):
    value=bytearray(240);value[:3]=bytes([1,1,6]);value[4:8]=struct.pack("!I",xid)
    value[10:12]=b"\x80\0" if kind==1 or selecting else b"\0\0"
    value[28:34]=bytes([2,0,0,0,0,client]);value[236:240]=bytes([99,130,83,99])
    options=bytearray([53,1,kind,55,6,1,3,6,51,58,59])
    if address:
        encoded=socket.inet_aton(address)
        if kind==1 or selecting:options+=bytes([50,4])+encoded
        else:value[12:16]=encoded
    if selecting or kind==7:options+=bytes([54,4])+socket.inet_aton("127.0.0.1")
    if kind in (1,3):
        name=f"client{client}".encode();options+=bytes([12,len(name)])+name
    return bytes(value+options+b"\xff")


def rows(path):
    result=[]
    for line in path.read_bytes().splitlines():
        words=line.split()
        if not words:continue
        if len(words)!=5:raise AssertionError("incomplete lease row")
        result.append({"expiry":int(words[0]),"mac":words[1].decode(),"address":words[2].decode(),
                       "name":words[3].decode(),"clid":words[4].decode()})
    return result


class Daemon:
    def __init__(self,binary,config,leasefile,folder,checks,label):
        self.binary=binary;self.config=config;self.leasefile=leasefile;self.folder=folder;self.checks=checks;self.label=label
        self.process=None;self.socket=None;self.xid=0;self.responses=[];self.files=[];self.starts=0
    def check(self,name,actual,expected):
        self.checks.append({"case":self.label+"-"+name,"actual":actual,"expected":expected,"pass":actual==expected})
    def start(self):
        self.starts+=1;self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0",68));self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.socket.setsockopt(socket.SOL_SOCKET,25,b"lo\0");self.socket.settimeout(3)
        self.log=(self.folder/f"daemon-{self.starts}.log").open("wb")
        self.process=subprocess.Popen([str(self.binary),"--no-daemon","--conf-file="+str(self.config)],stdout=self.log,stderr=self.log)
        deadline=time.monotonic()+5
        while True:
            if self.process.poll() is not None:raise RuntimeError("daemon exited during startup")
            try:
                with socket.create_connection(("127.0.0.1",15353),.1):break
            except OSError:
                if time.monotonic()>deadline:raise RuntimeError("startup timeout")
                time.sleep(.02)
    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:self.process.wait(5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait();self.check("forced-kill",True,False)
            self.check("exit",self.process.returncode,0)
            self.check("resources-released",Path(f"/proc/{self.process.pid}").exists(),False)
        if self.socket:self.socket.close();self.socket=None
        if getattr(self,"log",None):self.log.close()
    def exchange(self,kind,client=1,address=None,selecting=False,rebind=False):
        self.xid+=1;request=packet(kind,self.xid,client,address,selecting)
        destination="255.255.255.255" if kind==1 or selecting or rebind else "127.0.0.1"
        sent=time.time();self.socket.sendto(request,(destination,67))
        (self.folder/f"{self.xid}.request").write_bytes(request)
        if kind==7:
            self.socket.settimeout(.2)
            try:self.socket.recv(16384);self.check("release-has-no-reply",True,False)
            except socket.timeout:self.check("release-has-no-reply",False,False)
            finally:self.socket.settimeout(3)
            return None
        answer,peer=self.socket.recvfrom(16384);received=time.time();options=decode(answer,self.xid)
        (self.folder/f"{self.xid}.response").write_bytes(answer)
        self.check("server-port",peer[1],67)
        self.check("message",options[53][0],2 if kind==1 else 5)
        self.check("offered-address",socket.inet_ntoa(answer[16:20]),address)
        self.check("lease-duration",struct.unpack("!I",options[51])[0],600)
        timer1=struct.unpack("!I",options[58])[0];timer2=struct.unpack("!I",options[59])[0]
        renewal=kind==3 and not selecting
        self.check("timer-difference",timer2-timer1,225)
        self.check("timer-fuzz-range",0<=300-timer1<=37 if renewal else timer1==300,True)
        semantic={"message":options[53].hex(),"fixed_prefix":answer[:4].hex(),"address":answer[16:20].hex(),"flags":answer[10:12].hex(),
                  "ciaddr":answer[12:16].hex(),"siaddr":answer[20:24].hex(),"giaddr":answer[24:28].hex(),"chaddr":answer[28:44].hex(),
                  "options":{str(code):value.hex() for code,value in options.items() if code not in (58,59)},
                  "timers":[timer1,timer2],"renewal":renewal,"rebind":rebind,"sent":sent,"received":received}
        self.responses.append(semantic)
        return semantic
    def file_snapshot(self,name):
        value=rows(self.leasefile);now=int(time.time())
        if self.responses and name!="readonly-unchanged":
            expected=int(self.responses[-1]["sent"])+600
            for row in value:self.check(name+"-expiry",abs(row["expiry"]-expected)<=1,True)
        if name=="restored-before-query":
            self.check("restart-preserves-exact-rows",value,self.files[-1]["rows"])
        self.files.append({"name":name,"rows":value,"observed_at":now})
        (self.folder/f"{name}.leases").write_bytes(self.leasefile.read_bytes())
        return value
    def wait_rows(self,predicate,timeout):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if self.process.poll() is not None:raise RuntimeError("daemon exited while waiting for maintenance")
            if predicate(rows(self.leasefile)):return
            time.sleep(.05)
        raise AssertionError("leasefile maintenance timeout")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-reference",type=Path,required=True);parser.add_argument("--c-sha256",required=True)
    parser.add_argument("--rust",type=Path,required=True);parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--skip-enospc",action="store_true");parser.add_argument("--inject-error",action="store_true")
    parser.add_argument("--scenario",action="append",choices=["dora-restart-release","idle-expiry","readonly","enospc-idle-retry"])
    args=parser.parse_args();assert os.uname().sysname=="Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert not Path("/etc/openwrt_release").exists(),"build host only"
    assert hashlib.sha256(args.c_reference.read_bytes()).hexdigest()==args.c_sha256,"reference identity mismatch"
    out=args.out.resolve();assert "private" in out.parts;out.mkdir(parents=True,exist_ok=False)
    checks=[];runs=[];calibration=[True,False];assert sum(calibration)==1 and calibration.count(False)==1
    scenarios=args.scenario or (["dora-restart-release","idle-expiry","readonly"]+([] if args.skip_enospc else ["enospc-idle-retry"]))
    try:
        for scenario in scenarios:
            folder=out/scenario;folder.mkdir();database=folder/"db";database.mkdir()
            mounted=scenario=="enospc-idle-retry"
            if mounted:subprocess.run(["mount","-t","tmpfs","-o","size=4096,mode=0700","tmpfs",str(database)],check=True)
            leasefile=database/"leases";config=folder/"dnsmasq.conf"
            config.write_text("no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\nno-ping\ndhcp-authoritative\ndhcp-lease-max=150\n"
                "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                f"dhcp-leasefile={leasefile}\n"+("leasefile-ro\n" if scenario=="readonly" else ""))
            try:
                for implementation,binary in [("c",args.c_reference), ("rust",args.rust)]:
                    child_folder=folder/implementation;child_folder.mkdir();leasefile.write_bytes(b"")
                    initial=b""
                    if scenario=="idle-expiry":initial=f"{int(time.time())+5} 02:00:00:00:00:09 127.0.0.19 short *\n".encode()
                    if scenario=="readonly":initial=b"0 02:00:00:00:00:09 127.0.0.10 saved *\n"
                    leasefile.write_bytes(initial);(child_folder/"initial.leases").write_bytes(initial)
                    daemon=Daemon(binary.resolve(),config,leasefile,child_folder,checks,implementation+"-"+scenario)
                    try:
                        daemon.start()
                        if scenario=="idle-expiry":
                            daemon.check("restored-before-alarm",len(rows(leasefile)),1)
                            daemon.wait_rows(lambda value:not value,7);daemon.file_snapshot("expired-without-traffic")
                            daemon.check("no-dhcp-packets",daemon.xid,0)
                        else:
                            if mounted:(database/"full").write_bytes(bytes(4096))
                            daemon.exchange(1,address="127.0.0.10")
                            daemon.exchange(3,address="127.0.0.10",selecting=True)
                            if scenario=="dora-restart-release":
                                value=daemon.file_snapshot("ack-committed")
                                daemon.check("name-persisted",value[0]["name"],"client1")
                                daemon.check("expiry",abs(value[0]["expiry"]-int(daemon.responses[-1]["sent"])-600)<=1,True)
                                time.sleep(1.05);daemon.exchange(3,address="127.0.0.10")
                                daemon.file_snapshot("renewed");daemon.stop();daemon.start()
                                daemon.file_snapshot("restored-before-query")
                                daemon.exchange(3,address="127.0.0.10",rebind=True)
                                daemon.exchange(7,address="127.0.0.10");daemon.wait_rows(lambda value:not value,2)
                                daemon.file_snapshot("released")
                            elif scenario=="readonly":
                                daemon.check("configured-file-untouched",leasefile.read_bytes()==initial,True)
                                daemon.file_snapshot("readonly-unchanged")
                            else:
                                daemon.check("failed-write-not-ack-rollback",leasefile.stat().st_size,0)
                                (database/"full").unlink();started=time.monotonic()
                                print(f"{implementation}: waiting for source-defined 60-second lease write retry",flush=True)
                                daemon.wait_rows(lambda value:len(value)==1,65)
                                elapsed=time.monotonic()-started
                                daemon.check("idle-retry-window",59<=elapsed<=62,True)
                                daemon.check("retry-no-new-packets",daemon.xid,2)
                                daemon.file_snapshot("retry-durable")
                    finally:
                        daemon.stop()
                        runs.append({"implementation":implementation,"scenario":scenario,"responses":daemon.responses,
                                     "files":daemon.files,"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
                                     "config_sha256":hashlib.sha256(config.read_bytes()).hexdigest()})
            finally:
                if mounted:subprocess.run(["umount",str(database)],check=True)
        for scenario in scenarios:
            c,rust=[run for run in runs if run["scenario"]==scenario]
            left=[{key:value for key,value in row.items() if key not in ("timers","sent","received")} for row in c["responses"]]
            right=[{key:value for key,value in row.items() if key not in ("timers","sent","received")} for row in rust["responses"]]
            for row in right:row["options"]=dict(row["options"])
            if args.inject_error and scenario==scenarios[0] and right:right[0]["options"]["51"]="bad"
            checks.append({"case":scenario+"-c-rust-wire","pass":left==right,"c":left,"rust":right})
            left=[{"name":snapshot["name"],"rows":[{key:value for key,value in row.items() if key!="expiry"} for row in snapshot["rows"]]} for snapshot in c["files"]]
            right=[{"name":snapshot["name"],"rows":[{key:value for key,value in row.items() if key!="expiry"} for row in snapshot["rows"]]} for snapshot in rust["files"]]
            checks.append({"case":scenario+"-c-rust-leases","pass":left==right,"c":left,"rust":right})
    except Exception as error:
        checks.append({"case":"runner-exception","pass":False,"error":repr(error)})
    enospc_checked=all(any(run["implementation"]==implementation and run["scenario"]=="enospc-idle-retry"
        and any(snapshot["name"]=="retry-durable" for snapshot in run["files"]) for run in runs) for implementation in ["c","rust"])
    result={"success_count":sum(row["pass"] for row in checks),"error_count":sum(not row["pass"] for row in checks),
            "checks":checks,"runs":runs,"requested_scenarios":scenarios,"dns_publication_checked":False,"enospc_checked":enospc_checked,
            "normalization":"renewal T1/T2 checked for C base/delta/fuzz bounds; absolute expiry tied to each event wall clock; raw values retained",
            "scope":"shared private config DHCP/file/expiry/restart subset; not full DHCP/DNS/CLI/script equivalence"}
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("checks","runs")}));return int(result["error_count"]!=0)


if __name__=="__main__":raise SystemExit(main())
