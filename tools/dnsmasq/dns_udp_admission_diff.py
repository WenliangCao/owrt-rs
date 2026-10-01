#!/usr/bin/env python3
"""Real UDP query errors and forwarding-capacity recovery in a private netns.

The exact C daemon produces expected packets, including malformed questions
which cannot be decoded as ordinary DNS. Replies are therefore compared as
bytes; no RCODE, flags, EDE, advertised size or question bytes are normalized.
Only a loopback-only isolated Linux namespace is accepted.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import name, read_name, semantics
from dns_udp_refusal_diff import verify_reference

DROP_WINDOW = 0.20
REPLY_TIMEOUT = 1.0


def header(ident, flags=0x100, qd=1, an=0, ns=0, ar=0):
    return struct.pack("!6H", ident, flags, qd, an, ns, ar)


def question(host="remote.test", kind=1, cls=1):
    return name(host)+struct.pack("!HH",kind,cls)


def opt(advertised=1232, do=True):
    return b"\0"+struct.pack("!HHIH",41,advertised,0x8000 if do else 0,0)


def query(ident, host="remote.test", kind=1, flags=0x100, advertised=None):
    return header(ident,flags,ar=int(advertised is not None))+question(host,kind)+(b"" if advertised is None else opt(advertised))


def sized_question(total):
    budget=total-5  # root byte and fixed type/class
    labels=[]
    while budget:
        take=min(64,budget)
        if budget-take==1: take-=1
        assert take>=2
        labels.append(bytes([take-1])+b"x"*(take-1));budget-=take
    return b"".join(labels)+b"\0\0\1\0\1"


def corpus():
    rows=[]
    def emit(label, packet, outcome): rows.append({"label":label,"packet":packet.hex(),"expected_kind":outcome})
    for length in (0,1,11): emit(f"short-{length}",b"\0"*length,"drop")
    emit("qr-response-not-query",query(0x4100,flags=0x8100,advertised=1232),"drop")
    for opcode in (1,2,15):
        emit(f"opcode-{opcode}-plain",query(0x4110+opcode,flags=opcode<<11|0x770),"reply")
        emit(f"opcode-{opcode}-opt",query(0x4120+opcode,flags=opcode<<11|0x770,advertised=512),"reply")
    emit("opcode-unskippable-question",header(0x4130,0x900)+b"\x06ab","drop")
    emit("zero-questions",header(0x4140,qd=0),"reply")
    emit("zero-questions-opt",header(0x4141,flags=0x770,qd=0,ar=1)+opt(0),"reply")
    emit("two-questions-opt",header(0x4142,qd=2,ar=1)+question("ready.test")+question()+opt(),"reply")
    emit("zero-questions-late-truncated-additional",header(0x4143,qd=0,ar=2)+opt()+b"\0\0","reply")
    emit("two-questions-signed-tkey-opt",header(0x4144,qd=2,ar=1)+question(kind=249)+question()+opt(),"reply")
    for label, encoded in [("bad-pointer",b"\xc0\xff"),("pointer-loop",b"\xc0\x0c"),("bitstring-label",b"\x41\x08x\0")]:
        emit(label+"-opt",header(0x4150+len(rows),ar=1)+encoded+struct.pack("!HH",1,1)+opt(),"reply")
    emit("unskippable-label-type",header(0x4160)+b"\x80x\0\0\1\0\1","drop")
    emit("truncated-question-tail",header(0x4161)+name("ready.test")+b"\0\1","drop")
    emit("expanded-name-over-limit",header(0x4162,ar=1)+(b"\x3f"+b"x"*63)*4+b"\0\0\1\0\1"+opt(),"reply")
    rr=b"\xc0\x0c"+struct.pack("!HHIH",1,1,60,4)+bytes([192,0,2,1])
    emit("query-with-answer-opt",header(0x4170,an=1,ar=1)+question("ready.test")+rr+opt(),"reply")
    emit("query-with-authority-opt",header(0x4171,ns=1,ar=1)+question("ready.test")+rr+opt(),"reply")
    emit("query-with-missing-answer-and-opt",header(0x4172,an=1,ar=1)+question("ready.test")+opt(),"reply")
    for end in (495,496):
        body=sized_question(240)+sized_question(end-12-240)
        emit(f"ede-space-question-end-{end}",header(0x4200+end,qd=2,ar=1)+body+opt(512),"reply")
    for end in (497,498):
        body=sized_question(240)+sized_question(end-12-240)
        emit(f"empty-opt-space-question-end-{end}",header(0x4500+end,flags=0x900,qd=2,ar=1)+body+opt(512),"reply")
    packet=query(0x4600,host="ready.test")
    emit("receive-exact-edns-maximum",packet+b"x"*(1232-len(packet)),"reply")
    emit("receive-over-edns-maximum",packet+b"x"*(1233-len(packet)),"drop")
    return rows


class Upstream:
    def __init__(self, port):
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1",port));self.socket.settimeout(.02)
        self.port=self.socket.getsockname()[1]
        self.lock=threading.Lock();self.events=[];self.pending=[];self.released=set();self.failures=[]
        self.stop=threading.Event();self.thread=threading.Thread(target=self.run);self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: packet,peer=self.socket.recvfrom(65535)
            except socket.timeout: packet=None
            if packet is not None:
                try:
                    host,end=read_name(packet,12);kind,cls=struct.unpack_from("!HH",packet,end)
                    parsed=semantics(packet);parsed["id"]=0
                    with self.lock:
                        self.events.append({"host":host,"kind":kind,"class":cls,"wire":packet.hex(),"semantics":parsed})
                    flags=0x8080|(struct.unpack_from("!H",packet,2)[0]&0x100)
                    answer=packet[:2]+struct.pack("!5H",flags,1,1,0,0)+packet[12:end+4]
                    answer+=b"\xc0\x0c"+struct.pack("!HHIH",1,1,41,4)+bytes([192,0,2,7])
                    with self.lock:
                        self.pending.append((host,answer,peer))
                except Exception as error:
                    self.failures.append(repr(error))
            with self.lock:
                retained=[]
                for host,answer,peer in self.pending:
                    if not host.startswith("hold-") or host in self.released:
                        self.socket.sendto(answer,peer)
                    else: retained.append((host,answer,peer))
                self.pending=retained

    def names(self):
        with self.lock: return [event["host"] for event in self.events]

    def observed(self, first):
        with self.lock: return [event["semantics"] for event in self.events[first:]]

    def wait_for(self, host):
        deadline=time.monotonic()+1
        while host not in self.names():
            assert time.monotonic()<deadline, f"upstream did not receive {host}"
            time.sleep(.005)

    def release(self, host):
        with self.lock: self.released.add(host)

    def close(self):
        self.stop.set();self.thread.join(2);self.socket.close()
        assert not self.thread.is_alive() and not self.failures,self.failures


def fd_count(pid):
    return len(list(Path(f"/proc/{pid}/fd").iterdir()))


def receive(client, timeout):
    client.settimeout(timeout)
    try: return client.recvfrom(65535)[0]
    except socket.timeout: return None


def run(binary, out, config, port, upstream_port, planned):
    out.mkdir();upstream=Upstream(upstream_port);clients=[];rows=[]
    text=config.format(port=port,upstream=upstream.port)
    config_path=out / "dnsmasq.conf";config_path.write_text(text)
    trace={"rows":rows,"status":"failed","config_sha256":hashlib.sha256(text.encode()).hexdigest()}
    process=None
    with (out / "stderr.log").open("w") as log:
        try:
            process=subprocess.Popen([str(binary.resolve()),"-d","-C",str(config_path)],stdout=log,stderr=log)
            destination=("127.0.0.1",port)
            def client():
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);clients.append(sock);return sock
            ready=client();deadline=time.monotonic()+5
            while True:
                assert process.poll() is None,"daemon exited during readiness"
                ready.sendto(query(1,"ready.test"),destination)
                response=receive(ready,.03)
                if response is not None: break
                assert time.monotonic()<deadline,"readiness timeout"
            assert struct.unpack_from("!H",response,6)[0]==1,"positive calibration failed"
            assert upstream.names()==[],"local calibration unexpectedly forwarded"
            trace["fd_ready"]=fd_count(process.pid)
            def record(label,request,response,first_event,expected_kind=None):
                row={"label":label,"request":request.hex(),"response":None if response is None else response.hex(),
                    "upstream":upstream.names()[first_event:],"upstream_semantics":upstream.observed(first_event)}
                rows.append(row)
                if expected_kind is not None:
                    assert (response is None)==(expected_kind=="drop"),f"unexpected reply/drop for {label}"
                if response is not None: assert response[:2]==request[:2],f"ID changed for {label}"
            for case in planned:
                sock=client();packet=bytes.fromhex(case["packet"]);first=len(upstream.names())
                sock.sendto(packet,destination);response=receive(sock,DROP_WINDOW if case["expected_kind"]=="drop" else REPLY_TIMEOUT)
                record(case["label"],packet,response,first,case["expected_kind"])
                assert upstream.names()[first:]==[],f"error/receive-boundary packet forwarded: {case['label']}"
            held=[]
            for i,advertised in [(1,512),(2,None)]:
                sock=client();packet=query(0x6000+i,f"hold-{i}.test",flags=0x130 if i==1 else 0x100,advertised=advertised)
                first=len(upstream.names());sock.sendto(packet,destination);upstream.wait_for(f"hold-{i}.test")
                assert receive(sock,.03) is None,"controlled pending query completed before release"
                record(f"pending-{i}",packet,None,first)
                held.append((sock,packet))
            trace["fd_full"]=fd_count(process.pid)
            rejections=[("full-plain",query(0x6100,"full-plain.test")),
                ("full-opt",query(0x6101,"full-opt.test",flags=0x770,advertised=1232)),
                ("full-tkey",query(0x6102,"full-tkey.test",kind=249,advertised=512)),
                ("invalid-while-full",header(0x6103,qd=0,ar=1)+opt())]
            for label,packet in rejections:
                sock=client();first=len(upstream.names());sock.sendto(packet,destination)
                response=receive(sock,REPLY_TIMEOUT);record(label,packet,response,first,"reply")
                assert struct.unpack_from("!H",response,2)[0]&15==5,"full-table refusal calibration failed"
                assert upstream.names()[first:]==[],"rejected request reached upstream"
            duplicate=client();duplicate_packet=query(0x6200,"hold-1.test",flags=0x130,advertised=512)
            first=len(upstream.names());duplicate.sendto(duplicate_packet,destination)
            response=receive(duplicate,.04);record("coalesced-while-full",duplicate_packet,response,first,"drop")
            assert upstream.names()[first:]==[],"duplicate allocated another upstream query"
            upstream.release("hold-2.test")
            response=receive(held[1][0],REPLY_TIMEOUT);record("complete-unrelated-pending",held[1][1],response,len(upstream.names()),"reply")
            sock=client();packet=query(0x6300,"after-first-release.test");first=len(upstream.names())
            sock.sendto(packet,destination);response=receive(sock,REPLY_TIMEOUT);record("capacity-after-one-release",packet,response,first,"reply")
            assert upstream.names()[first:]==["after-first-release.test"]
            upstream.release("hold-1.test")
            for label,sock,packet in [("complete-original",*held[0]),("complete-coalesced",duplicate,duplicate_packet)]:
                response=receive(sock,REPLY_TIMEOUT);record(label,packet,response,len(upstream.names()),"reply")
            sock=client();packet=query(0x6400,"after-all-release.test");first=len(upstream.names())
            sock.sendto(packet,destination);response=receive(sock,REPLY_TIMEOUT);record("capacity-after-all-release",packet,response,first,"reply")
            assert upstream.names()[first:]==["after-all-release.test"]
            trace["fd_after_release"]=fd_count(process.pid);trace["status"]="ok"
        except Exception as error:
            trace["error"]=repr(error)
        finally:
            for sock in clients: sock.close()
            if process is not None:
                if process.poll() is None: process.send_signal(signal.SIGTERM)
                try: process.wait(3)
                except subprocess.TimeoutExpired: process.kill();process.wait(3)
                trace["exit"]=process.returncode;trace["reaped"]=not Path(f"/proc/{process.pid}").exists()
            upstream.close();trace["upstream_events"]=upstream.events
            (out / "trace.json").write_text(json.dumps(trace,indent=2)+"\n")
    return trace


def compare(expected, actual):
    if len(expected)!=len(actual): raise ValueError("observation count differs")
    return [i for i,(left,right) in enumerate(zip(expected,actual,strict=True)) if left!=right]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--c-identity",type=Path)
    parser.add_argument("--rust",type=Path);parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,args.c_identity);out=args.output.resolve()
    assert "private" in out.parts and not out.exists();out.mkdir(parents=True)
    planned=corpus();(out / "corpus.json").write_text(json.dumps(planned,indent=2)+"\n")
    config="""no-hosts
no-resolv
listen-address=127.0.0.1
port={port}
cache-size=0
dns-forward-max=2
edns-packet-max=1232
local-ttl=37
host-record=ready.test,192.0.2.9
server=127.0.0.1#{upstream}
"""
    with socket.socket() as reserve: reserve.bind(("127.0.0.1",0));port=reserve.getsockname()[1]
    while True:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1",0));upstream_port=reserve.getsockname()[1]
        if upstream_port!=port: break
    report={"reference":identity,"query_cases":len(planned),"scope":"UDP query admission/error packets and capacity recovery, not performance",
        "drop_observation_seconds":DROP_WINDOW,"reply_deadline_seconds":REPLY_TIMEOUT,"failures":[]}
    report["planned_input_datagrams"]=len(planned)+9
    report["planned_observations"]=len(planned)+12
    report["expected_receive_drops"]=sum(row["expected_kind"]=="drop" for row in planned)
    (out / "plan.json").write_text(json.dumps({"config":config.format(port=port,upstream=upstream_port),
        "receive_cases":planned,"forward_capacity":2,"held_queries":2,"coalesced_recipients":1,
        "release_order":["hold-2.test","hold-1.test"],"drop_window":DROP_WINDOW,"reply_timeout":REPLY_TIMEOUT},indent=2)+"\n")
    expected=run(args.c,out / "c",config,port,upstream_port,planned)
    if expected["status"]!="ok" or expected.get("exit")!=0: report["failures"].append({"reference":expected.get("error",expected.get("exit"))})
    else:
        changed=copy.deepcopy(expected["rows"])
        at=next(i for i,row in enumerate(changed) if row["response"])
        packet=bytearray.fromhex(changed[at]["response"]);packet[3]^=1;changed[at]["response"]=packet.hex()
        assert compare(expected["rows"],changed)==[at]
        try: compare(expected["rows"],expected["rows"][:-1])
        except ValueError: pass
        else: raise AssertionError("count calibration failed")
        report["calibration"]={"positive_local_reply":1,"rcode_mutation_detected":1,"short_count_rejected":1,"full_table_and_recovery":1}
        report["reference_observations"]=len(expected["rows"])
        report["reference_replies"]=sum(row["response"] is not None for row in expected["rows"])
        report["reference_no_reply"]=sum(row["response"] is None for row in expected["rows"])
        report["reference_rcodes"]={str(code):sum(row["response"] is not None and
            struct.unpack_from("!H",bytes.fromhex(row["response"]),2)[0]&15==code for row in expected["rows"]) for code in (0,4,5)}
        if args.rust:
            report["rust_sha256"]=hashlib.sha256(args.rust.read_bytes()).hexdigest()
            actual=run(args.rust,out / "rust",config,port,upstream_port,planned)
            assert expected["config_sha256"]==actual["config_sha256"],"C/Rust configuration differs"
            report["rust_observations"]=len(actual["rows"])
            report["rust_unexecuted"]=len(expected["rows"])-len(actual["rows"])
            if actual["status"]!="ok" or actual.get("exit")!=0: report["failures"].append({"rust":actual.get("error",actual.get("exit"))})
            else:
                differing=compare(expected["rows"],actual["rows"])
                report.update(compared=len(expected["rows"]),mismatches=len(differing),mismatch_rows=differing)
                report["failures"].extend({"case":expected["rows"][i]["label"],"c":expected["rows"][i],"rust":actual["rows"][i]} for i in differing)
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n");print(json.dumps(report))
    return int(bool(report["failures"]))


if __name__=="__main__": raise SystemExit(main())
