#!/usr/bin/env python3
"""Linux arpreq defined-byte and DHCP send-retry comparison with exact C."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
from dhcp_reply_diff import extract
from dhcp_destination_diff import compare, calibrate

ROOT=Path(__file__).resolve().parents[2]
EXPECTED={"dhcp.c":"600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001",
          "network.c":"8229872d30a2fb2d86ec9a9e550e51fbb8d8d97926e7a02b0137f2a7b40c40c9",
          "util.c":"33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973"}
PREFIX=r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
_Static_assert(sizeof(struct arpreq)==68 && _Alignof(struct arpreq)==4,"arpreq ABI");
_Static_assert(offsetof(struct arpreq,arp_ha)==16 && offsetof(struct arpreq,arp_flags)==32,"ARP hardware/flags");
_Static_assert(offsetof(struct arpreq,arp_netmask)==36 && offsetof(struct arpreq,arp_dev)==52,"ARP mask/device");
_Static_assert(SIOCSARP==0x8955 && ATF_COM==2 && IFNAMSIZ==16,"ARP constants");
_Static_assert(SIOCGIFNAME==0x8910 && sizeof(struct ifreq)==40 && offsetof(struct ifreq,ifr_ifindex)==16,"interface-name ABI");
static struct { unsigned short dhcp_client_port; } settings;
#define daemon (&settings)
static size_t decode(const char *text,unsigned char *bytes) {
  if (!strcmp(text,"-")) return 0;
  size_t len=strlen(text)/2;
  for(size_t i=0;i<len;i++){unsigned v;if(sscanf(text+2*i,"%2x",&v)!=1)abort();bytes[i]=v;}
  return len;
}
'''
MAIN=r'''
int main(void) {
  char *line=NULL;size_t capacity=0;
  while(getline(&line,&capacity,stdin)>0){
    if(line[0]=='B'){
      char ip[32],hw[33],name[33];unsigned port,type;
      if(sscanf(line,"B %31s %u %u %32s %32s",ip,&port,&type,hw,name)!=5)return 2;
      struct in_addr address;inet_pton(AF_INET,ip,&address);
      unsigned char hardware[16]={0};size_t len=decode(hw,hardware);char device[17]={0};decode(name,(unsigned char *)device);
      struct arpreq result=build(address,port,type,hardware,len,device);
      for(size_t i=0;i<sizeof(result);i++)printf("%02x",((unsigned char *)&result)[i]);puts("");
    }else if(line[0]=='T'){
      char sequence[8192];int fail;if(sscanf(line,"T %8191s %d",sequence,&fail)!=2)return 2;
      size_t attempts=0;ssize_t result;
      do { char command=attempts<strlen(sequence)?sequence[attempts]:'S';attempts++;
        errno=command=='W'?EAGAIN:command=='I'?EINTR:command=='E'?EACCES:0;
        result=errno?-1:1;
      } while(retry_send(result));
      printf("1 %zu %d %d\n",attempts,result>=0,fail);
    }else if(line[0]=='S'||line[0]=='L'){
      if(!getenv("DNSMASQ_TEST_ISOLATED")||strcmp(getenv("DNSMASQ_TEST_ISOLATED"),"1"))return 3;
      char ip[32],hw[33],device[IFNAMSIZ];unsigned port,index;
      if(sscanf(line+1,"%31s %u %u %32s",ip,&port,&index,hw)!=4)return 2;
      unsigned char hardware[16]={0};size_t len=decode(hw,hardware);
      struct in_addr address;inet_pton(AF_INET,ip,&address);
      int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return 4;
      struct sockaddr_in target={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr=address};
      int prepared=0;if(!indextoname(fd,index,device))prepared=errno;
      if(line[0]=='L'){puts("snapshot");fflush(stdout);char resume[32];if(!fgets(resume,sizeof(resume),stdin)||strcmp(resume,"continue\n"))return 5;}
      if(!prepared){struct arpreq request=build(address,port,1,hardware,len,device);if(ioctl(fd,SIOCSARP,&request)<0)prepared=errno;}
      union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))];} control={0};
      struct iovec iov={.iov_base="dhcp-arp-probe",.iov_len=14};
      struct msghdr message={.msg_name=&target,.msg_namelen=sizeof(target),.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
      struct cmsghdr *header=CMSG_FIRSTHDR(&message);header->cmsg_level=IPPROTO_IP;header->cmsg_type=IP_PKTINFO;header->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));
      ((struct in_pktinfo *)CMSG_DATA(header))->ipi_ifindex=index;
      ssize_t sent;do {sent=sendmsg(fd,&message,0);}while(retry_send(sent));int send_error=sent<0?errno:0;
      close(fd);printf("%d %d\n",prepared,send_error);
    }else return 2;
    fflush(stdout);
  }
  free(line);return 0;
}
'''


def oracle(sources):
    source=sources["dhcp.c"]
    start=source.index("          dest.sin_addr = mess->yiaddr;")
    end=source.index("          if (ioctl(daemon->dhcpfd, SIOCSARP",start)
    build=r'''
static struct arpreq build(struct in_addr address,unsigned short port,unsigned char type,const unsigned char *hw,size_t len,const char *device){
  struct arpreq arp_req;memset(&arp_req,0xa5,sizeof(arp_req));
  struct sockaddr_in dest={.sin_family=AF_INET};
  struct {struct in_addr yiaddr;unsigned char htype,hlen,chaddr[16];} packet={.yiaddr=address,.htype=type,.hlen=len},*mess=&packet;
  memcpy(mess->chaddr,hw,len);settings.dhcp_client_port=port;
  safe_strncpy(arp_req.arp_dev,device,sizeof(arp_req.arp_dev));
'''+source[start:end]+"return arp_req;}\n"
    return PREFIX+extract(sources["util.c"],"safe_strncpy")+extract(sources["network.c"],"indextoname")+extract(sources["util.c"],"retry_send")+build+MAIN


def cases():
    rng=random.Random(0x293a4)
    rows=[]
    for size in [1,6,14]:
        for name in [b"p",b"eth-test",b"a"*15]:
            for kind in [1,6,255]:rows.append(f"B 192.0.2.2 68 {kind} {bytes(range(size)).hex()} {name.hex()}")
    for _ in range(1000):
        rows.append(f"B 192.0.2.{rng.randrange(256)} {rng.randrange(65536)} {rng.randrange(1,256)} {rng.randbytes(rng.randrange(1,15)).hex()} {('if'+str(rng.randrange(100))).encode().hex()}")
    for sequence in ["S","IS","WWS","WIS","E","WE","W"*1000+"S","W"*1001+"S","W"*999+"I"+"W"*1000+"S"]:
        for fail in [0,1]:rows.append(f"T {sequence} {fail}")
    return rows


def normalize(row, output):
    if not row.startswith("B "):return output
    value=bytes.fromhex(output)
    assert len(value)==68
    hwlen=len(row.split()[4])//2
    # C leaves the hardware tail and netmask indeterminate. Those bytes have
    # no meaning without ATF_NETMASK; keep all defined address/flags/dev bytes.
    return (value[:16]+value[16:18+hwlen]+value[32:36]+value[52:68]).hex()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();assert os.uname().sysname=="Linux","Linux headers required"
    calibrate();out=args.out.resolve();assert out.is_relative_to(ROOT/"private")
    out.mkdir(parents=True,exist_ok=False);sources={}
    for name,expected in EXPECTED.items():
        raw=(args.source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==expected;sources[name]=raw.decode()
    (out/"oracle.c").write_text(oracle(sources))
    subprocess.run(["cc","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(out/"oracle.c"),"-o",str(out/"oracle")],check=True)
    subprocess.run(["cargo","build","--quiet","--manifest-path",str(ROOT/"components/dnsmasq/Cargo.toml"),"--lib"],check=True)
    target=ROOT/"components/dnsmasq/target/debug"
    subprocess.run(["rustc","--edition=2021",str(ROOT/"tools/dnsmasq/dhcp_arp_probe.rs"),"--extern",f"dnsmasq_rs={target/'libdnsmasq_rs.rlib'}","-L",f"dependency={target/'deps'}","-o",str(out/"rust-probe")],check=True)
    inputs=cases();payload="\n".join(inputs)+"\n";(out/"input.txt").write_text(payload);outputs=[]
    for name in ["oracle","rust-probe"]:
        run=subprocess.run([str(out/name)],input=payload,text=True,capture_output=True)
        (out/f"{name}.stdout").write_text(run.stdout);(out/f"{name}.stderr").write_text(run.stderr);run.check_returncode()
        lines=run.stdout.splitlines();assert len(lines)==len(inputs)
        outputs.append([normalize(row,line) for row,line in zip(inputs,lines)])
    result=compare(inputs,*outputs);result.update(source_sha256=EXPECTED,
        binary_sha256={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in ["oracle","rust-probe"]},
        scope="Linux arpreq defined fields and source retry_send counts; uninitialized C tail/netmask excluded")
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="mismatches"}));return int(result["error_count"]!=0)


if __name__=="__main__":raise SystemExit(main())
