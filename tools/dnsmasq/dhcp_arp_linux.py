#!/usr/bin/env python3
"""Check ARP neighbour side effects and UDP delivery in private namespaces."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import time

RECEIVER = r'''
import json,socket,sys
print("namespace-ready",flush=True)
assert sys.stdin.readline().strip()=="listen"
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(("192.0.2.2",68))
print("listening",flush=True)
while True:
    packet,peer=sock.recvfrom(2048)
    print(json.dumps({"hex":packet.hex(),"source":peer[0]}),flush=True)
'''


def line(stream, timeout=5):
    if not select.select([stream],[],[],timeout)[0]:raise RuntimeError("missing bounded probe output")
    value=stream.readline().strip()
    if not value:raise RuntimeError("early probe EOF")
    return value


def run(command, **kwargs):
    return subprocess.run(command,check=True,capture_output=True,text=True,**kwargs)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--rust",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True);args=parser.parse_args()
    assert os.uname().sysname=="Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert not Path("/etc/openwrt_release").exists(),"build host only"
    assert {row["ifname"] for row in json.loads(run(["ip","-j","link"]).stdout)}=={"lo"}
    args.out.mkdir(parents=True,exist_ok=False)
    records=[];checks=[];senders=[];receiver=None

    def check(name,actual,expected):
        checks.append({"case":name,"actual":actual,"expected":expected,"pass":actual==expected})

    check("calibration-pass",0,0);check("calibration-fail",1,0)
    assert sum(row["pass"] for row in checks)==1 and sum(not row["pass"] for row in checks)==1
    checks.clear()
    try:
        receiver=subprocess.Popen(["unshare","--net","python3","-u","-c",RECEIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                  stderr=(args.out/"receiver.stderr").open("w"),text=True,bufsize=1)
        assert line(receiver.stdout)=="namespace-ready"
        run(["ip","link","add","arp0","type","veth","peer","name","peer0"])
        run(["ip","link","set","peer0","netns",str(receiver.pid)])
        run(["ip","addr","add","192.0.2.1/24","dev","arp0"]);run(["ip","link","set","arp0","up"])
        ns=["nsenter","-t",str(receiver.pid),"-n"]
        run(ns+["ip","link","set","lo","up"])
        run(ns+["ip","link","set","peer0","address","02:00:00:00:00:02"])
        run(ns+["ip","addr","add","192.0.2.2/24","dev","peer0"]);run(ns+["ip","link","set","peer0","up"])
        receiver.stdin.write("listen\n");receiver.stdin.flush();assert line(receiver.stdout)=="listening"
        index=json.loads(run(["ip","-j","link","show","arp0"]).stdout)[0]["ifindex"]
        command=f"S 192.0.2.2 68 {index} 020000000002\n"
        for implementation,binary in [("c",args.c),("rust",args.rust)]:
            sender=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=(args.out/f"{implementation}.stderr").open("w"),text=True,bufsize=1)
            senders.append(sender);windows=[]
            for attempt in range(8):
                subprocess.run(["ip","neigh","del","192.0.2.2","dev","arp0"],capture_output=True)
                sender.stdin.write(command);sender.stdin.flush();status=line(sender.stdout)
                packet=json.loads(line(receiver.stdout))
                neighbours=json.loads(run(["ip","-j","neigh","show","to","192.0.2.2","dev","arp0"]).stdout)
                windows.append({"status":status,"packet":packet,"neighbours":neighbours,
                    "fd_after":len(list(Path(f"/proc/{sender.pid}/fd").iterdir()))})
                check(f"{implementation}-send-{attempt}",status,"0 0")
                check(f"{implementation}-payload-{attempt}",packet,{"hex":b"dhcp-arp-probe".hex(),"source":"192.0.2.1"})
                check(f"{implementation}-neighbour-{attempt}",[row.get("lladdr") for row in neighbours],["02:00:00:00:00:02"])
                check(f"{implementation}-dynamic-{attempt}",all("PERMANENT" not in row.get("state",[]) for row in neighbours),True)
            check(f"{implementation}-fd-stable",len({row["fd_after"] for row in windows}),1)
            sender.stdin.close();sender.wait(timeout=5)
            check(f"{implementation}-exit",sender.returncode,0)
            check(f"{implementation}-fd-reclaimed",Path(f"/proc/{sender.pid}").exists(),False)
            # Kernel-managed dynamic neighbours intentionally survive daemon
            # socket close in C and Rust; this is not a process-owned leak.
            check(f"{implementation}-neighbour-survives-close",bool(json.loads(run(["ip","-j","neigh","show","to","192.0.2.2","dev","arp0"]).stdout)),True)
            denied=run(["setpriv","--bounding-set=-net_admin","--inh-caps=-all","--ambient-caps=-all","--",str(binary)],input=command)
            packet=json.loads(line(receiver.stdout))
            check(f"{implementation}-permission-warning-send",denied.stdout.strip(),"1 0")
            check(f"{implementation}-permission-delivery",packet["hex"],b"dhcp-arp-probe".hex())
            renamed=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=(args.out/f"{implementation}.rename.stderr").open("w"),text=True,bufsize=1)
            senders.append(renamed)
            renamed.stdin.write("L"+command[1:]);renamed.stdin.flush()
            assert line(renamed.stdout)=="snapshot"
            run(["ip","link","set","arp0","down"])
            run(["ip","link","set","arp0","name","renamed0"])
            run(["ip","link","set","renamed0","up"])
            renamed.stdin.write("continue\n");renamed.stdin.flush()
            rename_status=line(renamed.stdout);packet=json.loads(line(receiver.stdout))
            check(f"{implementation}-rename-old-name-fails",rename_status.split()[0]!="0",True)
            check(f"{implementation}-rename-still-sends",rename_status.split()[1],"0")
            check(f"{implementation}-rename-delivery",packet["hex"],b"dhcp-arp-probe".hex())
            renamed.stdin.close();renamed.wait(timeout=5)
            check(f"{implementation}-rename-exit",renamed.returncode,0)
            run(["ip","link","set","renamed0","down"])
            run(["ip","link","set","renamed0","name","arp0"])
            run(["ip","link","set","arp0","up"])
            records.append({"implementation":implementation,"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
                "windows":windows,"permission":{"stdout":denied.stdout,"stderr":denied.stderr},"rename_status":rename_status})
        # Compare actual kernel side effects, not Rust-generated expectations.
        left=records[0]["windows"][0]["neighbours"]
        right=records[1]["windows"][0]["neighbours"]
        check("c-rust-neighbour-state",right,left)
        check("c-rust-rename-status",records[1]["rename_status"],records[0]["rename_status"])
        run(["ip","link","del","arp0"])
        errors=[]
        for implementation,binary in [("c",args.c),("rust",args.rust)]:
            failed=run([str(binary)],input=command);errors.append(failed.stdout.strip())
            records.append({"implementation":implementation,"removed_interface":{"stdout":failed.stdout,"stderr":failed.stderr}})
        check("removed-interface-errors",errors[1],errors[0])
        check("removed-interface-send-fails",errors[0].split()[1]!="0",True)
    except Exception as error:
        checks.append({"case":"runner-exception","actual":repr(error),"expected":"no exception","pass":False})
        raise
    finally:
        for child in senders+([receiver] if receiver else []):
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();child.wait()
        result={"checks":checks,"runs":records,"success_count":sum(row["pass"] for row in checks),
                "error_count":sum(not row["pass"] for row in checks),
                "scope":"isolated veth/client namespace ARP and UDP boundary, not complete DHCP service"}
        (args.out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({key:value for key,value in result.items() if key not in ("checks","runs")}))
    return int(result["error_count"]!=0)


if __name__=="__main__":raise SystemExit(main())
