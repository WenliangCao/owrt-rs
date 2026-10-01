#!/usr/bin/env python3
"""Real -k TCP cache inheritance/writeback/clock baseline and differential.

Uses the exact C daemon and private ubusd inside run_isolated.sh. C always
runs first. Debug mode is deliberately excluded because it does not fork.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import query, read_name, rr, name, semantics, exact_read
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT=Path(__file__).resolve().parents[2]
LISTEN=("127.0.0.1",15353)


class Upstream:
    def __init__(self):
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind(("127.0.0.1",15354));self.udp.settimeout(.05)
        self.tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.tcp.bind(("127.0.0.1",15354));self.tcp.listen();self.tcp.settimeout(.05)
        self.stop=threading.Event();self.lock=threading.Lock();self.events=[];self.errors=[];self.generation=1;self.workers=[]
        self.threads=[threading.Thread(target=self.udp_loop),threading.Thread(target=self.tcp_loop)]
        for thread in self.threads:thread.start()

    def answer(self,packet,transport):
        host,end=read_name(packet,12)
        kind=struct.unpack_from("!H",packet,end)[0]
        with self.lock:
            generation=self.generation
            self.events.append({"transport":transport,"query":(b"\0\0"+packet[2:]).hex(),"generation":generation})
        ttl=1 if host=="clocked.test" else 120
        flags=0x8180;answers=[];authority=[]
        data=bytes([192,0,2,generation])
        if host=="negative.test":flags|=3
        elif host=="nodata.test":
            soa=name("ns.test")+name("hostmaster.test")+struct.pack("!5I",1,2,3,4,30)
            authority=[rr(6,soa,30,name("test"))]
        elif host=="alias.test":answers=[rr(5,name("target.test"),ttl),rr(1,data,ttl,name("target.test"))]
        elif host=="rrset.test":answers=[rr(1,bytes([192,0,2,last]),ttl) for last in (11,12)]
        elif kind==28:answers=[rr(28,bytes.fromhex("20010db8000000000000000000000000")+bytes([generation]),ttl)]
        else:answers=[rr(1,data,ttl)]
        return packet[:2]+struct.pack("!5H",flags,1,len(answers),len(authority),0)+packet[12:end+4]+b"".join(answers+authority)

    def udp_loop(self):
        while not self.stop.is_set():
            try:packet,peer=self.udp.recvfrom(65535)
            except socket.timeout:continue
            try:self.udp.sendto(self.answer(packet,"udp"),peer)
            except Exception as error:self.errors.append(repr(error))

    def connection(self,client):
        try:
            with client:
                client.settimeout(.1)
                while not self.stop.is_set():
                    try:prefix=exact_read(client,2)
                    except socket.timeout:continue
                    except ConnectionError:break
                    packet=exact_read(client,struct.unpack("!H",prefix)[0]);reply=self.answer(packet,"tcp")
                    client.sendall(struct.pack("!H",len(reply))+reply)
        except Exception as error:self.errors.append(repr(error))

    def tcp_loop(self):
        while not self.stop.is_set():
            try:client,_=self.tcp.accept()
            except socket.timeout:continue
            worker=threading.Thread(target=self.connection,args=(client,));self.workers.append(worker);worker.start()

    def close(self):
        self.stop.set()
        for thread in self.threads:thread.join(2)
        for thread in self.workers:thread.join(2)
        self.udp.close();self.tcp.close()
        assert all(not thread.is_alive() for thread in self.threads+self.workers),"upstream thread leak"


class Product(Fixture):
    def __init__(self,args,out):
        super().__init__(args,out);self.upstream.close();self.upstream=Upstream()

    def start_product(self,binary):
        self.hosts=self.out/"hosts";self.hosts.write_text("192.0.2.41 snapshot.test\n")
        config=self.out/"dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "server=127.0.0.1#15354\ncache-size=32\nneg-ttl=30\nlocal-ttl=37\n"
                          f"addn-hosts={self.hosts}\nenable-ubus={OBJECT}\n")
        command=[str(binary.resolve()),"-k","-C",str(config)]
        if binary.resolve()==(self.args.reference_build/"dnsmasq/dnsmasq").resolve():
            command += ["--user=root","--group=root","--log-facility=-","--pid-file="+str(self.out/"pid")]
        self.daemon,_=self.spawn(command,"daemon");self.wait_registered()

    def wait_metric(self,key,value):
        deadline=time.monotonic()+3
        while True:
            result=self.metrics()
            if result[key]==value:return result
            assert self.daemon.poll() is None and time.monotonic()<deadline,(key,value,result)
            time.sleep(.005)


def run(args,binary,out):
    out.mkdir();fixture=Product(args,out);connections={};rows=[]
    try:
        fixture.start_bus();fixture.start_product(binary)
        initial=fixture.metrics();assert initial["tcp_connections"]==0
        def connect(label):
            connection=socket.create_connection(LISTEN,2);connection.settimeout(2);connections[label]=connection
            fixture.wait_metric("tcp_connections",len(connections))
            return connection
        def ask(label,host,connection=None,kind=1,cache_ttl=False,committed=0):
            before=fixture.metrics();first=len(fixture.upstream.events);request=query(host,kind,0x5000+len(rows));started=time.monotonic()
            if connection is None:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(2);client.sendto(request,LISTEN);response=client.recv(65535)
            else:
                connection.sendall(struct.pack("!H",len(request))+request)
                response=exact_read(connection,struct.unpack("!H",exact_read(connection,2))[0])
            after=fixture.wait_metric("dns_cache_inserted",before["dns_cache_inserted"]+committed) if committed else fixture.metrics()
            assert response[:2]==request[:2]
            rows.append({"label":label,"response":semantics(response),"upstream":copy.deepcopy(fixture.upstream.events[first:]),
                         "metrics":after,"cache_ttl":cache_ttl,"elapsed":time.monotonic()-started,
                         "request":request.hex(),"wire":response.hex()})
            return rows[-1]
        ask("parent-seed","seed.test",committed=1)
        old=connect("old")
        ask("old-inherited","seed.test",old,cache_ttl=True)
        ask("parent-late","late.test",committed=1)
        ask("old-did-not-inherit-late","late.test",old,committed=1)
        ask("child-fill","child.test",old,committed=1)
        ask("child-hit","child.test",old,cache_ttl=True)
        ask("parent-writeback","child.test",cache_ttl=True)
        new=connect("new")
        ask("new-inherited-child","child.test",new,cache_ttl=True)
        for host,insertions in (("alias.test",2),("negative.test",1),("nodata.test",2),("rrset.test",2)):
            ask(host+"-child-fill",host,old,committed=insertions)
            ask(host+"-child-hit",host,old,cache_ttl=True)
            ask(host+"-parent-hit",host,cache_ttl=True)
        ask("clock-child-fill","clocked.test",old,committed=1)
        time.sleep(2.2)
        fixture.upstream.generation=2
        ask("clock-child-after-wall-expiry","clocked.test",old)
        ask("clock-parent-after-wall-expiry","clocked.test",committed=1)
        ask("old-inherited-ttl-still-fixed","seed.test",old,cache_ttl=True)
        ask("late-clock-child-fill","late-clock.test",old,committed=1)
        ask("late-clock-parent-writeback","late-clock.test",cache_ttl=True)
        fixture.hosts.write_text("192.0.2.42 snapshot.test\n");fixture.daemon.send_signal(signal.SIGHUP)
        fixture.wait_metric("dns_cache_inserted",0)
        ask("parent-host-after-hup","snapshot.test")
        ask("old-host-after-hup","snapshot.test",old)
        ask("old-cache-after-hup","seed.test",old,cache_ttl=True)
        ask("parent-cache-after-hup","seed.test",committed=1)
        latest=connect("latest")
        ask("new-cache-after-hup","seed.test",latest,cache_ttl=True)
        ask("new-host-after-hup","snapshot.test",latest)
        for client in connections.values():client.close()
        connections.clear();closed=fixture.wait_metric("tcp_connections",0)
        resources={"closed_metrics":closed,"parent_fds":len(list(Path(f"/proc/{fixture.daemon.pid}/fd").iterdir())),
                   "children_after_close":Path(f"/proc/{fixture.daemon.pid}/task/{fixture.daemon.pid}/children").read_text().split()}
        assert not resources["children_after_close"]
        assert not fixture.upstream.errors,fixture.upstream.errors
        fixture.stop(fixture.daemon);fixture.daemon=None
        assert all(check["pass"] for check in fixture.checks)
        return rows,resources
    finally:
        for client in connections.values():client.close()
        fixture.stop(fixture.daemon);fixture.stop(fixture.bus);fixture.upstream.close()
        (out/"trace.json").write_text(json.dumps({"rows":rows,"raw":fixture.raw,"checks":fixture.checks,
                                                  "upstream":fixture.upstream.events,"upstream_errors":fixture.upstream.errors},indent=2)+"\n")


def calibrate(rows):
    by_name={row["label"]:row for row in rows};assert len(rows)==32
    for label in ("old-inherited","child-hit","parent-writeback","new-inherited-child","old-cache-after-hup","new-cache-after-hup"):
        assert not by_name[label]["upstream"],label
    assert len(by_name["old-did-not-inherit-late"]["upstream"])==1
    assert by_name["old-did-not-inherit-late"]["upstream"][0]["transport"]=="tcp"
    assert not by_name["clock-child-after-wall-expiry"]["upstream"]
    assert by_name["clock-child-after-wall-expiry"]["response"]["records"][0]["ttl"]==1
    assert len(by_name["clock-parent-after-wall-expiry"]["upstream"])==1
    assert by_name["old-inherited"]["response"]["records"][0]["ttl"]==by_name["old-inherited-ttl-still-fixed"]["response"]["records"][0]["ttl"]
    assert by_name["late-clock-parent-writeback"]["response"]["records"][0]["ttl"]<=118
    assert by_name["old-host-after-hup"]["response"]["records"][0]["data"]=="192.0.2.41"
    assert by_name["new-host-after-hup"]["response"]["records"][0]["data"]=="192.0.2.42"


def compare(expected,actual):
    if len(expected)!=len(actual):raise ValueError("observation count differs")
    failures=[]
    for left,right in zip(expected,actual):
        a,b=copy.deepcopy(left),copy.deepcopy(right)
        for row in (a,b):
            for key in ("elapsed","wire","request"):row.pop(key)
        if a["cache_ttl"] and b["cache_ttl"]:
            for c,r in zip(a["response"]["records"],b["response"]["records"]):
                if c["type"]!=41 and abs(c["ttl"]-r["ttl"])<=1:r["ttl"]=c["ttl"]
        if a!=b:failures.append({"label":left["label"],"c":a,"rust":b})
    return failures


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path,required=True)
    parser.add_argument("--rust",type=Path)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();args.reference_build=args.reference_build.resolve();out=args.out.resolve()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1" and [n for _,n in socket.if_nameindex()]==["lo"]
    assert out.is_relative_to(ROOT/"private") and not out.exists();out.mkdir(parents=True)
    reference=args.reference_build/"dnsmasq/dnsmasq";identity=verify_reference(reference,None)
    subprocess.run(["mount","--make-rprivate","/"],check=True)
    subprocess.run(["mount","-t","tmpfs","-o","nosuid,nodev,noexec,mode=0755","tmpfs","/run"],check=True)
    Path(BUS).parent.mkdir(parents=True)
    report={"planned":32,"c_observations":0,"matched":None,"failures":[],"reference":identity,
            "tool_sha256":digest(Path(__file__)),"scope":"real -k child cache snapshot/writeback/fixed-clock and metrics; private ubus"}
    try:
        expected,resources=run(args,reference,out/"c");calibrate(expected);report.update(c_observations=len(expected),c_resources=resources)
        assert not compare(expected,copy.deepcopy(expected))
        bad=copy.deepcopy(expected);bad[0]["response"]["flags"]^=1;assert len(compare(expected,bad))==1
        if args.rust:
            actual,resources=run(args,args.rust,out/"rust");failures=compare(expected,actual)
            report.update(matched=len(expected)-len(failures),failures=failures,rust_resources=resources,rust_sha256=digest(args.rust))
    except Exception as error:report["failures"].append({"infrastructure_or_protocol":repr(error)})
    finally:subprocess.run(["umount","/run"],check=True)
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report));return int(bool(report["failures"]))


if __name__=="__main__":raise SystemExit(main())
