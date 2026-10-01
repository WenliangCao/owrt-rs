#!/usr/bin/env python3
"""Observe exact-C duplicate-recipient exhaustion in an isolated netns.

One held query and one coalesced recipient fill dns-forward-max=1's duplicate
pool. The next recipient is rejected, then both accepted requests complete.
This observes C's fields and lifecycle using a controlled loopback upstream;
the resulting trace defines the later Rust comparison boundary.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_udp_admission_diff import Upstream, query, receive
from dns_service_probe import read_name
from dns_udp_refusal_diff import verify_reference


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--c-identity",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1" and sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,args.c_identity)
    out=args.output.resolve();assert "private" in out.parts and not out.exists();out.mkdir(parents=True)
    upstream=Upstream(0);clients=[];process=None;rows=[]
    report={"reference":identity,"rows":rows,"scope":"C-only duplicate-recipient capacity, reply fields and accepted-request survival","failures":[]}
    with socket.socket() as reserve:reserve.bind(("127.0.0.1",0));port=reserve.getsockname()[1]
    config=out / "dnsmasq.conf"
    config.write_text(f"no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport={port}\ncache-size=0\ndns-forward-max=1\nedns-packet-max=1232\nhost-record=ready.test,192.0.2.9\nserver=127.0.0.1#{upstream.port}\n")
    def client():
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);clients.append(sock);return sock
    with (out / "stderr.log").open("w") as log:
        try:
            process=subprocess.Popen([str(args.c.resolve()),"-d","-C",str(config)],stdout=log,stderr=log)
            ready=client();deadline=time.monotonic()+5
            while True:
                assert process.poll() is None
                ready.sendto(query(1,"ready.test"),("127.0.0.1",port))
                if receive(ready,.03) is not None: break
                assert time.monotonic()<deadline
            held=[]
            for i,host in [(1,"hold-duplicate.test"),(2,"hold-duplicate.test")]:
                sock=client();packet=query(0x7100+i,host,flags=0x130,advertised=512)
                sock.sendto(packet,("127.0.0.1",port));upstream.wait_for("hold-duplicate.test")
                response=receive(sock,.04);assert response is None
                rows.append({"event":f"accepted-{i}","request":packet.hex(),"response":None})
                held.append((sock,packet))
            assert upstream.names()==["hold-duplicate.test"],"duplicate was forwarded twice"
            upstream_wire=bytes.fromhex(upstream.events[0]["wire"])
            upstream_id=struct.unpack_from("!H",upstream_wire)[0]
            rejected_id=0x7103 if upstream_id!=0x7103 else 0x7104
            rejected=query(rejected_id,"HOLD-DUPLICATE.test",flags=0x130,advertised=1232)
            sock=client();sock.sendto(rejected,("127.0.0.1",port));response=receive(sock,1)
            assert response is not None and struct.unpack_from("!H",response,2)[0]&15==5
            _,reply_end=read_name(response,12);_,upstream_end=read_name(upstream_wire,12)
            _,request_end=read_name(rejected,12)
            row={"event":"rejected-third-recipient","request":rejected.hex(),"response":response.hex(),
                "client_id":rejected_id,"upstream_id":upstream_id,"response_id":struct.unpack_from("!H",response)[0],
                "question_matches_client_bytes":response[12:reply_end+4]==rejected[12:request_end+4],
                "question_matches_stash_bytes":response[12:reply_end+4]==upstream_wire[12:upstream_end+4]}
            rows.append(row);assert upstream.names()==["hold-duplicate.test"]
            upstream.release("hold-duplicate.test")
            for index,(sock,packet) in enumerate(held):
                response=receive(sock,1);assert response is not None and response[:2]==packet[:2]
                assert struct.unpack_from("!H",response,2)[0]&15==0
                rows.append({"event":f"completed-{index+1}","request":packet.hex(),"response":response.hex()})
            report["observed_id_mismatch"]=row["response_id"]!=row["client_id"]
            report["response_used_upstream_id"]=row["response_id"]==row["upstream_id"]
            report["accepted_completed"]=2;report["upstream_queries"]=len(upstream.events)
        except Exception as error:report["failures"].append(repr(error))
        finally:
            for sock in clients:sock.close()
            if process is not None:
                if process.poll() is None:process.send_signal(signal.SIGTERM)
                try:process.wait(3)
                except subprocess.TimeoutExpired:process.kill();process.wait(3)
                report["exit"]=process.returncode;report["reaped"]=not Path(f"/proc/{process.pid}").exists()
            upstream.close();report["upstream_events"]=upstream.events
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("rows","upstream_events")}))
    return int(bool(report["failures"]))


if __name__=="__main__":raise SystemExit(main())
