#!/usr/bin/env python3
"""Prepare audit-only clients from the established checked M6a wire clients.

The DHCP relay variant uses 127.0.0.2:15467 -> 127.0.0.1:15467 only.
No broadcast packets, real MACs, client leases, or product edits are involved.
"""
import argparse
from pathlib import Path


NAMED_DNS_PROBE = r'''
/* Only the first warmup cycle per client verifies published DHCP DNS. */
static bool named_dns_proved[MAX_CLIENTS];
static FILE *named_dns_proofs;
static bool named_dns_reply(const unsigned char *p,size_t size,const char *name,
                            uint16_t id,uint32_t address) {
  if (size<12 || read16(p)!=id || (read16(p+2)&0xfa0f)!=0x8000 ||
      read16(p+4)!=1 || read16(p+6)!=1 || read16(p+8)!=0 || read16(p+10)!=0) return false;
  size_t at=12; char owner[256];
  if (!decode_name(p,size,&at,owner) || strcmp(owner,name) || at+4>size ||
      read16(p+at)!=1 || read16(p+at+2)!=1) return false;
  at+=4;
  if (!decode_name(p,size,&at,owner) || strcmp(owner,name) || at+14!=size ||
      read16(p+at)!=1 || read16(p+at+2)!=1 || read16(p+at+8)!=4) return false;
  return !memcmp(p+at+10,&address,4);
}
static bool check_named_dns(struct client *c) {
  unsigned index=(unsigned)(c-clients); char name[64],path[4096],address[INET_ADDRSTRLEN];
  if (c->phase!=0 || now_ns()+NS>=measure_start) {
    fputs("named DNS proof cannot fit inside warmup\n",stderr); return false;
  }
  snprintf(name,sizeof name,"audit-client-%u.lan",index);
  if (!named_dns_proofs) {
    if (snprintf(path,sizeof path,"%s.named-dns-proof.jsonl",opt.output)>=(int)sizeof path) return false;
    named_dns_proofs=fopen(path,"wx");
    if (!named_dns_proofs) { perror("named DNS proof output"); return false; }
  }
  unsigned char query[256]={0},reply[512]; size_t length=12;
  write16(query,c->id); write16(query+2,0x0100); write16(query+4,1);
  length+=encode_name(query+length,name); write16(query+length,1); write16(query+length+2,1); length+=4;
  struct sockaddr_in local={.sin_family=AF_INET},target={.sin_family=AF_INET,.sin_port=htons(15353)};
  local.sin_addr.s_addr=target.sin_addr.s_addr=htonl(0x7f000001u);
  struct timeval timeout={1,0}; bool correct=false; ssize_t received=-1;
  int fd=socket(AF_INET,SOCK_DGRAM,0);
  if (fd>=0 && !setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout) &&
      !setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof timeout) &&
      !bind(fd,(struct sockaddr *)&local,sizeof local) &&
      !connect(fd,(struct sockaddr *)&target,sizeof target) && now_ns()+NS<measure_start &&
      send(fd,query,length,0)==(ssize_t)length) {
    received=recv(fd,reply,sizeof reply,0);
    if (received>=0 && now_ns()<measure_start) correct=named_dns_reply(reply,(size_t)received,name,c->id,c->address);
  }
  if (fd>=0) close(fd);
  if (!inet_ntop(AF_INET,&c->address,address,sizeof address)) return false;
  fprintf(named_dns_proofs,"{\"client\":%u,\"phase\":%u,\"name\":\"%s\",\"expected_address\":\"%s\","
          "\"correct\":%s,\"response_bytes\":%ld,\"monotonic_ns\":%" PRIu64 "}\n",
          index,c->phase,name,address,correct?"true":"false",(long)received,now_ns());
  if (fflush(named_dns_proofs) || ferror(named_dns_proofs)) { output_failed=true; return false; }
  if (!correct) fprintf(stderr,"named DHCP DNS proof failed for %s\n",name);
  return correct;
}
'''


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'expected one source anchor: {old!r}')
    return text.replace(old, new, 1)


def prepare(out, dhcp_hostnames=False):
    source = Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    text = (source / 'm6a_loadgen.c').read_text()
    # Invalid replies are failure evidence, so never hide them behind the
    # representative-correct-packet limit used by the original M6a client.
    text = replace_once(text,
                        '  if (kind>2 || sample_counts[c->phase][type][kind]++>=10) return;',
                        '  if (correct && (kind>2 || sample_counts[c->phase][type][kind]++>=10)) return;')
    text = replace_once(text, 'memcpy(p+236,"\\x63\\x82\\x53\\x63",4); size_t n=240;',
                        'memset(p+24,255,4); /* audit: dnsmasq local relay-source extension */\n'
                        '  memcpy(p+236,"\\x63\\x82\\x53\\x63",4); size_t n=240;')
    text = replace_once(text, 'if (kind==1 || (kind==3 && c->dhcp_stage==1)) target.sin_addr.s_addr=INADDR_BROADCAST;',
                        '/* audit: every DHCP request stays unicast on loopback. */')
    text = replace_once(text, 'local.sin_port=htons((uint16_t)opt.client_port);',
                        'local.sin_port=htons((uint16_t)opt.client_port);\n'
                        '    local.sin_addr.s_addr=htonl(0x7f000002u);')
    if dhcp_hostnames:
        text = replace_once(text, '  p[n++]=255; return n;',
                            '  char hostname[32];\n'
                            '  int hostname_length=snprintf(hostname,sizeof hostname,"audit-client-%u",index);\n'
                            '  if (hostname_length<=0 || hostname_length>=(int)sizeof hostname) exit(2);\n'
                            '  p[n++]=12; p[n++]=(unsigned char)hostname_length;\n'
                            '  memcpy(p+n,hostname,(size_t)hostname_length); n+=(size_t)hostname_length;\n'
                            '  p[n++]=255; return n;')
        text = replace_once(text, 'static void receive_dhcp(void) {',
                            NAMED_DNS_PROBE + '\nstatic void receive_dhcp(void) {')
        text = replace_once(text, '      counts[c->phase].renew_correct++; c->dhcp_stage=3;',
                            '      counts[c->phase].renew_correct++;\n'
                            '      unsigned index=(unsigned)(c-clients);\n'
                            '      if (c->phase==0 && !named_dns_proved[index]) {\n'
                            '        if (!check_named_dns(c)) { completion(c,WRONG,now_ns()); stopping=1; continue; }\n'
                            '        named_dns_proved[index]=true;\n'
                            '      }\n'
                            '      c->dhcp_stage=3;')
        text = replace_once(text, '  if (fclose(wire_samples)) output_failed=true;',
                            '  if (fclose(wire_samples)) output_failed=true;\n'
                            '  if (named_dns_proofs && fclose(named_dns_proofs)) output_failed=true;')
    # DNS client sockets also explicitly bind loopback, including ephemeral ports.
    text = replace_once(text, 'if (connect(c->fd,(struct sockaddr *)&destination,sizeof(destination))) return false;',
                        'struct sockaddr_in local={.sin_family=AF_INET};\n'
                        '  local.sin_addr.s_addr=htonl(0x7f000001u);\n'
                        '  if (bind(c->fd,(struct sockaddr *)&local,sizeof local)) return false;\n'
                        '  if (connect(c->fd,(struct sockaddr *)&destination,sizeof(destination))) return false;')
    text = text.replace('{192,0,2,1}', '{93,184,215,14}')
    text = text.replace('{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}', '{0x26,6,0x47,0,0x47,0,0,0,0,0,0,0,0,0,0x11,0x11}')
    (out / 'loadgen.c').write_text(text)
    text = (source / 'm6a_upstream.c').read_text()
    text = replace_once(text, '#include <string.h>', '#include <string.h>\n#include <strings.h>')
    text = replace_once(text, '!strncmp(host,"cname-",6)', '!strncasecmp(host,"cname-",6)')
    text = text.replace('{192,0,2,1}', '{93,184,215,14}')
    text = text.replace('{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}', '{0x26,6,0x47,0,0x47,0,0,0,0,0,0,0,0,0,0x11,0x11}')
    (out / 'upstream.c').write_text(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--dhcp-hostnames', action='store_true',
                        help='include option 12 hostnames and prove DHCP DNS publication during warmup')
    args = parser.parse_args()
    prepare(args.output, args.dhcp_hostnames)
