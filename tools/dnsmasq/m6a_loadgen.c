/* M6a measurement client, not product code. Build: cc -O2 -std=c11 -Wall
 * -Wextra -Werror m6a_loadgen.c -o m6a_loadgen. Pin externally to CPU 2.
 * One outstanding transaction per client; all DNS replies are semantically
 * checked. PREFIX.latencies.bin is little endian, 32 bytes per measured
 * completion: sequence:u64, latency_ns:u64, send_mono_ns:u64, client:u16,
 * qtype:u16, status:u8 (0 correct,1 timeout,2 wrong,3 transport), phase:u8
 * (1 steady/2 saturation), kind:u8 (DNS 0 hit/1 miss, DHCP 2 cycle), pad:u8.
 * TCP uses 20 logical clients and rotates each physical connection after 100
 * complete responses, matching dnsmasq TCP_MAX_QUERIES. Unexpected closure
 * and timeout stay in the evidence while a fresh stream serves later work.
 * Release has no protocol reply and is reported separately, never throughput.
 * A=192.0.2.1, AAAA=2001:db8::1, TXT="m6a"; CNAME=m6a.target plus A.
 * PREFIX.send-lag.bin is sequence:u64, actual-minus-scheduled-send-ns:u64.
 * PREFIX.wire-samples.jsonl retains first 10 replies per phase/type/kind
 * (DHCP stage) for independent checks. Closed loop is a concurrency workload:
 * it does not correct coordinated omission or claim offered-rate saturation.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 256
#define PACKET 65536
#define NS 1000000000ULL
enum { CORRECT, TIMEOUT, WRONG, TRANSPORT };
struct counters {
  uint64_t scheduled, sent, correct, timeout, wrong, transport, skipped;
  uint64_t stale, datagrams, release_sent, dora_correct, renew_correct;
  uint64_t correct_in_window, correct_after_window;
  uint64_t send_lag_count, send_lag_sum_ns, send_lag_max_ns;
};
struct client {
  int fd; bool busy, measured, leased; uint64_t seq, sent_at, deadline;
  uint64_t scheduled_at, send_lag_ns;
  unsigned phase;
  uint16_t id, qtype; uint8_t kind, dhcp_stage;
  uint16_t tcp_queries;
  char name[256]; uint32_t address, xid;
  unsigned char tx[1024], rx[PACKET]; size_t tx_len, tx_off, rx_len;
};
struct options {
  const char *mode, *host, *prefix, *output, *profile, *qtype, *interface, *epoch_output, *epoch_file;
  unsigned clients, port, client_port, cache_names, timeout_ms;
  double duration, warmup, rate, saturation; uint64_t seed; uint32_t dhcp_first;
  bool dhcp_renew_only;
};
static struct options opt = {"udp", "127.0.0.1", "m6a.test", NULL, "hit",
  "a", "lo", NULL, NULL, 20, 15353, 68, 4096, 1000, 120, 30, 0, 0, 1, 0, false};
static struct client clients[MAX_CLIENTS];
static struct counters counts[3];
static struct sockaddr_in destination;
static FILE *latencies, *send_lags, *wire_samples, *dhcp_dora; static bool output_failed; static uint64_t sequence;
static uint64_t tcp_connections, tcp_reconnections, tcp_idle_connection_errors;
static bool renew_setup_failed;
static volatile sig_atomic_t stopping;
static uint64_t warmup_start, measure_start, measure_end, saturation_start, run_end;
static unsigned sample_counts[3][4][3];
static bool socket_connect(struct client *c);
static void socket_close(struct client *c);
static void tcp_reset(struct client *c);

static void stop_signal(int signal_number) { (void)signal_number; stopping = 1; }
static uint64_t now_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) { perror("clock_gettime"); exit(2); }
  return (uint64_t)value.tv_sec * NS + (uint64_t)value.tv_nsec;
}
static uint16_t read16(const unsigned char *p) { return (uint16_t)(p[0]*256U+p[1]); }
static uint32_t read32(const unsigned char *p) {
  return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static void write16(unsigned char *p, unsigned value) { p[0]=(unsigned char)(value>>8); p[1]=(unsigned char)value; }
static void write32(unsigned char *p, uint32_t value) {
  p[0]=(unsigned char)(value>>24); p[1]=(unsigned char)(value>>16);
  p[2]=(unsigned char)(value>>8); p[3]=(unsigned char)value;
}
static void le64(unsigned char *p, uint64_t value) {
  for (unsigned i=0;i<8;i++) { p[i]=(unsigned char)value; value>>=8; }
}
static void actual_send_at(struct client *c,uint64_t sent_at) {
  c->sent_at=sent_at; c->deadline=c->sent_at+(uint64_t)opt.timeout_ms*1000000;
  c->send_lag_ns=c->sent_at-c->scheduled_at;
  struct counters *v=&counts[c->phase];v->send_lag_count++;
  v->send_lag_sum_ns+=c->send_lag_ns;
  if (c->send_lag_ns>v->send_lag_max_ns) v->send_lag_max_ns=c->send_lag_ns;
}
static size_t encode_name(unsigned char *data, const char *name) {
  size_t out=0; const char *part=name;
  while (*part) {
    const char *end=strchr(part,'.'); size_t length=end?(size_t)(end-part):strlen(part);
    if (!length || length>63 || out+length+2>255) return 0;
    data[out++]=(unsigned char)length; memcpy(data+out,part,length); out+=length;
    if (!end) break;
    part=end+1;
  }
  data[out++]=0; return out;
}
static void sample_wire(struct client *c,const unsigned char *packet,size_t size,bool correct) {
  bool dhcp=!strcmp(opt.mode,"dhcp");
  unsigned type=dhcp?0:!strncmp(c->name,"cname-",6)?3:c->qtype==28?1:c->qtype==16?2:0;
  unsigned kind=dhcp?c->dhcp_stage:c->kind;
  if (kind>2 || sample_counts[c->phase][type][kind]++>=10) return;
  fprintf(wire_samples,"{\"sequence\":%" PRIu64 ",\"phase\":%u,\"client\":%u,\"qtype\":%u,"
    "\"kind\":%u,\"dhcp_stage\":%u,\"name\":\"%s\",\"correct\":%s,\"query_hex\":\"",
    c->seq,c->phase,(unsigned)(c-clients),c->qtype,c->kind,c->dhcp_stage,c->name,correct?"true":"false");
  size_t framing=!strcmp(opt.mode,"tcp")?2:0;
  for (size_t i=framing;i<c->tx_len;i++) fprintf(wire_samples,"%02x",c->tx[i]);
  fputs("\",\"reply_hex\":\"",wire_samples);
  for (size_t i=0;i<size;i++) fprintf(wire_samples,"%02x",packet[i]);
  fputs("\"}\n",wire_samples);if (ferror(wire_samples)) output_failed=true;
}
static bool publish_epoch(const char *path,bool json) {
  char temporary[4096];
  if (snprintf(temporary,sizeof(temporary),"%s.tmp.%ld",path,(long)getpid())>=(int)sizeof(temporary)) return false;
  FILE *out=fopen(temporary,"wx");if (!out) return false;
  if (json) fprintf(out,"{\"warmup_start_ns\":%" PRIu64 ",\"measurement_start_ns\":%" PRIu64
    ",\"measurement_end_ns\":%" PRIu64 ",\"saturation_start_ns\":%" PRIu64
    "}\n",warmup_start,measure_start,measure_end,saturation_start);
  else fprintf(out,"%" PRIu64 "\n",measure_start);
  bool failed=ferror(out)!=0;if (fclose(out)) failed=true;
  if (!failed && link(temporary,path)) failed=true;
  if (unlink(temporary)) failed=true;
  return !failed;
}
/* Pointer bounds, loop bounds and the expanded wire-name limit all apply. */
static bool decode_name(const unsigned char *p,size_t size,size_t *offset,char *name) {
  size_t pos=*offset, next=0, length=0; bool jumped=false; unsigned steps=0;
  for (;;) {
    if (pos>=size || ++steps>128) return false;
    unsigned label=p[pos++];
    if ((label&0xc0)==0xc0) {
      if (pos>=size) return false;
      size_t target=((size_t)(label&63)<<8)|p[pos++];
      if (!jumped) next=pos;
      jumped=true; pos=target; continue;
    }
    if (label&0xc0) return false;
    if (!label) { name[length]=0; *offset=jumped?next:pos; return true; }
    if (pos+label>size || length+label+(length?1:0)>253) return false;
    if (length) name[length++]='.';
    memcpy(name+length,p+pos,label); length+=label; pos+=label;
  }
}
static bool dns_correct(struct client *c,const unsigned char *p,size_t size) {
  if (size<12 || read16(p)!=c->id || (read16(p+2)&0x820f)!=0x8000 ||
      read16(p+4)!=1 || read16(p+8)!=0) return false;
  size_t offset=12; char owner[256];
  if (!decode_name(p,size,&offset,owner) || strcmp(owner,c->name) ||
      offset+4>size || read16(p+offset)!=c->qtype || read16(p+offset+2)!=1) return false;
  offset+=4; unsigned answers=read16(p+6), additional=read16(p+10);
  bool cname=!strncmp(c->name,"cname-",6), saw_value=false, saw_cname=false;
  if (answers!=(cname?2U:1U)) return false;
  for (unsigned i=0;i<answers+additional;i++) {
    if (!decode_name(p,size,&offset,owner) || offset+10>size) return false;
    unsigned type=read16(p+offset), klass=read16(p+offset+2);
    uint32_t ttl=read32(p+offset+4); size_t length=read16(p+offset+8);
    offset+=10;
    if (offset+length>size) return false;
    if (i<answers) {
      if (klass!=1 || !ttl || ttl>3600) return false;
      if (cname && type==5) {
        size_t end=offset; char target[256];
        if (saw_cname || strcmp(owner,c->name) || !decode_name(p,size,&end,target) ||
            end!=offset+length || strcmp(target,"m6a.target")) return false;
        saw_cname=true;
      } else {
        const char *expected_owner=cname?"m6a.target":c->name;
        static const unsigned char a[]={192,0,2,1};
        static const unsigned char aaaa[]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        static const unsigned char txt[]={3,'m','6','a'};
        const unsigned char *expected=type==1?a:type==28?aaaa:txt;
        size_t expected_len=type==1?4:type==28?16:4;
        if (saw_value || strcmp(owner,expected_owner) || type!=c->qtype ||
            length!=expected_len || memcmp(p+offset,expected,length)) return false;
        saw_value=true;
      }
    }
    offset+=length;
  }
  return offset==size && saw_value && (!cname || saw_cname);
}
static void completion(struct client *c,unsigned status,uint64_t when) {
  struct counters *v=&counts[c->phase];
  if (status==CORRECT) {
    v->correct++;
    if (c->measured) {
      uint64_t phase_end=c->phase==1?saturation_start:measure_end;
      if (when<=phase_end) v->correct_in_window++; else v->correct_after_window++;
    }
  } else if (status==TIMEOUT) v->timeout++;
  else if (status==WRONG) v->wrong++; else v->transport++;
  if (c->measured) {
    unsigned char record[32]={0};
    le64(record,c->seq); le64(record+8,when-c->sent_at); le64(record+16,c->sent_at);
    unsigned index=(unsigned)(c-clients);
    record[24]=(unsigned char)index; record[25]=(unsigned char)(index>>8);
    record[26]=(unsigned char)c->qtype; record[27]=(unsigned char)(c->qtype>>8);
    record[28]=(unsigned char)status; record[29]=(unsigned char)c->phase; record[30]=c->kind;
    if (fwrite(record,1,sizeof(record),latencies)!=sizeof(record)) output_failed=true;
    unsigned char lag[16];le64(lag,c->seq);le64(lag+8,c->send_lag_ns);
    if (fwrite(lag,1,sizeof(lag),send_lags)!=sizeof(lag)) output_failed=true;
  }
  c->busy=false; c->rx_len=0; c->tx_off=0;
  if (!strcmp(opt.mode,"dhcp")) c->dhcp_stage=0;
}
static void choose_dns(struct client *c) {
  bool miss=!strcmp(opt.profile,"miss") ||
    (!strcmp(opt.profile,"mixed") && c->seq%5==4);
  unsigned index=(unsigned)(c->seq%opt.cache_names);
  const char *type=opt.qtype; bool cname=false;
  if (!strcmp(type,"aaaa30")) type=index%10<7?"a":"aaaa";
  if (!strcmp(type,"mix")) {
    unsigned choice=index%20;
    type=choice<10?"a":choice<15?"aaaa":choice<18?"cname":"txt";
  }
  c->qtype=!strcmp(type,"aaaa")?28:!strcmp(type,"txt")?16:1;
  cname=!strcmp(type,"cname"); c->kind=miss?1:0;
  if (miss) snprintf(c->name,sizeof(c->name),"%su%012" PRIx64 ".%s",cname?"cname-":"",c->seq,opt.prefix);
  else snprintf(c->name,sizeof(c->name),"%sq%04x.%s",cname?"cname-":"",index,opt.prefix);
  size_t prefix=!strcmp(opt.mode,"tcp")?2:0;
  unsigned char *packet=c->tx+prefix; memset(packet,0,12);
  write16(packet,c->id); write16(packet+2,0x0100); write16(packet+4,1);
  size_t length=encode_name(packet+12,c->name);
  if (!length) { fprintf(stderr,"name cannot be encoded\n"); exit(2); }
  length+=12; write16(packet+length,c->qtype); write16(packet+length+2,1);
  length+=4; if (prefix) write16(c->tx,(unsigned)length);
  c->tx_len=length+prefix;
}
static size_t dhcp_packet(struct client *c,unsigned kind) {
  unsigned index=(unsigned)(c-clients); unsigned char *p=c->tx;
  memset(p,0,240); p[0]=1; p[1]=1; p[2]=6; write32(p+4,c->xid);
  if (kind==1 || (kind==3 && c->dhcp_stage==1)) write16(p+10,0x8000);
  if ((kind==3 && c->dhcp_stage==2) || kind==7) memcpy(p+12,&c->address,4);
  p[28]=2; p[31]=0x6a; p[32]=(unsigned char)(index>>8); p[33]=(unsigned char)index;
  memcpy(p+236,"\x63\x82\x53\x63",4); size_t n=240;
  p[n++]=53; p[n++]=1; p[n++]=(unsigned char)kind;
  p[n++]=61; p[n++]=7; p[n++]=1; memcpy(p+n,p+28,6); n+=6;
  if (kind==1 || (kind==3 && c->dhcp_stage==1)) {
    p[n++]=50; p[n++]=4; memcpy(p+n,&c->address,4); n+=4;
  }
  if ((kind==3 && c->dhcp_stage==1) || kind==7) {
    p[n++]=54; p[n++]=4; memcpy(p+n,&destination.sin_addr.s_addr,4); n+=4;
  }
  if (kind!=7) {
    p[n++]=55; p[n++]=5; p[n++]=1; p[n++]=3; p[n++]=51; p[n++]=58; p[n++]=59;
  }
  p[n++]=255; return n;
}
static bool send_dhcp(struct client *c,unsigned kind) {
  c->tx_len=dhcp_packet(c,kind);
  struct sockaddr_in target=destination;
  if (kind==1 || (kind==3 && c->dhcp_stage==1)) target.sin_addr.s_addr=INADDR_BROADCAST;
  if (kind==1) actual_send_at(c,now_ns());
  ssize_t n=sendto(clients[0].fd,c->tx,c->tx_len,0,(struct sockaddr *)&target,sizeof(target));
  if (n!=(ssize_t)c->tx_len) return false;
  counts[c->phase].datagrams++; return true;
}
static bool dhcp_correct(struct client *c,const unsigned char *p,size_t size) {
  if (size<241 || p[0]!=2 || p[1]!=1 || p[2]!=6 || read32(p+4)!=c->xid ||
      memcmp(p+28,c->tx+28,6) || memcmp(p+236,"\x63\x82\x53\x63",4) ||
      memcmp(p+16,&c->address,4)) return false;
  unsigned message=0; uint32_t server=0, lease=0,t1=0,t2=0; bool end=false;
  bool seen[256]={false}; size_t offset=240;
  while (offset<size) {
    unsigned code=p[offset++]; if (code==255) { end=true; break; } if (!code) continue;
    if (seen[code] || offset>=size) return false;
    seen[code]=true; size_t length=p[offset++]; if (offset+length>size) return false;
    if (code==53) { if (length!=1) return false; message=p[offset]; }
    if (code==54) { if (length!=4) return false; memcpy(&server,p+offset,4); }
    if (code==51 || code==58 || code==59) {
      if (length!=4) return false;
      uint32_t value=read32(p+offset);
      if (code==51) lease=value; else if (code==58) t1=value; else t2=value;
    }
    offset+=length;
  }
  return end && message==(c->dhcp_stage==0?2U:5U) &&
    server==destination.sin_addr.s_addr && lease>=120 && t1>0 && t1<t2 && t2<lease;
}
static void start_request(struct client *c,uint64_t scheduled,unsigned phase) {
  struct counters *v=&counts[phase]; v->scheduled++;
  if (c->busy) { v->skipped++; return; }
  c->seq=++sequence; c->id=(uint16_t)c->seq; c->xid=(uint32_t)c->seq;
  c->phase=phase;c->measured=phase!=0;c->scheduled_at=scheduled;c->send_lag_ns=0;
  c->sent_at=now_ns(); c->deadline=c->sent_at+(uint64_t)opt.timeout_ms*1000000;
  c->busy=true; c->tx_off=c->rx_len=0;
  if (!strcmp(opt.mode,"dhcp")) {
    c->kind=2; c->qtype=1; c->dhcp_stage=opt.dhcp_renew_only&&c->leased?2:0; v->sent++;
    if (c->dhcp_stage==2) actual_send_at(c,now_ns());
    if (!send_dhcp(c,c->dhcp_stage==2?3:1)) completion(c,TRANSPORT,now_ns());
    return;
  }
  choose_dns(c); v->sent++;
  if (!strcmp(opt.mode,"tcp") && c->fd<0) {
    if (!socket_connect(c)) { completion(c,TRANSPORT,now_ns()); tcp_reset(c); return; }
    tcp_reconnections++;
  }
  if (!strcmp(opt.mode,"udp")) {
    actual_send_at(c,now_ns());
    ssize_t length=send(c->fd,c->tx,c->tx_len,0);
    if (length!=(ssize_t)c->tx_len) completion(c,TRANSPORT,now_ns());
    else v->datagrams++;
  }
}
static bool socket_connect(struct client *c) {
  int type=!strcmp(opt.mode,"tcp")?SOCK_STREAM:SOCK_DGRAM;
  c->fd=socket(AF_INET,type,0); if (c->fd<0) return false;
  if (type==SOCK_STREAM) {
    struct timeval timeout={2,0};int one=1;
    if (setsockopt(c->fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
        setsockopt(c->fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)) ||
        setsockopt(c->fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one))) return false;
  }
  if (connect(c->fd,(struct sockaddr *)&destination,sizeof(destination))) return false;
  int flags=fcntl(c->fd,F_GETFL);
  if (flags<0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return false;
  if (type==SOCK_STREAM) tcp_connections++;
  return true;
}
static void socket_close(struct client *c) { if (c->fd>=0) close(c->fd); c->fd=-1; }
static void tcp_reset(struct client *c) {
  socket_close(c); c->rx_len=0; c->tx_off=0; c->tx_len=0; c->tcp_queries=0;
}
static void receive_dns(struct client *c,uint64_t time) {
  if (!strcmp(opt.mode,"udp")) {
    for (;;) {
      ssize_t size=recv(c->fd,c->rx,sizeof(c->rx),0);
      if (size<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
      if (size<0) { if (c->busy) completion(c,TRANSPORT,time); break; }
      if (!c->busy || size<2 || read16(c->rx)!=c->id) { counts[c->phase].stale++; continue; }
      uint64_t received_at=now_ns();bool correct=dns_correct(c,c->rx,(size_t)size);
      sample_wire(c,c->rx,(size_t)size,correct);completion(c,correct?CORRECT:WRONG,received_at);
    }
    return;
  }
  ssize_t size=recv(c->fd,c->rx+c->rx_len,sizeof(c->rx)-c->rx_len,0);
  if (size<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return;
  if (size<=0) {
    if (c->busy) completion(c,TRANSPORT,time);
    else tcp_idle_connection_errors++;
    tcp_reset(c); return;
  }
  c->rx_len+=(size_t)size;
  if (c->rx_len<2) return;
  size_t length=read16(c->rx);
  if (length<12 || c->rx_len>length+2) {
    if (c->busy) completion(c,WRONG,time); else tcp_idle_connection_errors++;
    tcp_reset(c); return;
  }
  if (c->rx_len==length+2) {
    if (!c->busy) { counts[c->phase].stale++; c->rx_len=0; return; }
    uint64_t received_at=now_ns();bool correct=dns_correct(c,c->rx+2,length);
    sample_wire(c,c->rx+2,length,correct);completion(c,correct?CORRECT:WRONG,received_at);
    if (++c->tcp_queries>=100) {
      /* Count every complete response, including a wrong answer. Close before
       * reading a normal FIN or starting request 101 on the old stream. */
      tcp_reset(c);
    }
  }
}
static void receive_dhcp(void) {
  unsigned char packet[4096];
  for (;;) {
    struct sockaddr_in peer; socklen_t peer_length=sizeof(peer);
    ssize_t length=recvfrom(clients[0].fd,packet,sizeof(packet),0,(struct sockaddr *)&peer,&peer_length);
    if (length<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return;
    if (length<0) { perror("DHCP recvfrom"); stopping=1; return; }
    if (length<8) { counts[now_ns()>=measure_start?1:0].stale++; continue; }
    uint32_t xid=read32(packet+4); struct client *c=NULL;
    for (unsigned i=0;i<opt.clients;i++) if (clients[i].busy && clients[i].xid==xid) { c=&clients[i]; break; }
    if (!c) { counts[now_ns()>=measure_start?1:0].stale++; continue; }
    bool correct=peer.sin_port==destination.sin_port && dhcp_correct(c,packet,(size_t)length);
    sample_wire(c,packet,(size_t)length,correct);
    if (!correct) {
      completion(c,WRONG,now_ns()); continue;
    }
    if (c->dhcp_stage==0) {
      c->dhcp_stage=1;
      if (!send_dhcp(c,3)) completion(c,TRANSPORT,now_ns());
    } else if (c->dhcp_stage==1) {
      counts[c->phase].dora_correct++; c->leased=true;
      if (opt.dhcp_renew_only) {
        uint64_t ack_at=now_ns();
        fprintf(dhcp_dora,"{\"client\":%u,\"sent_ns\":%"PRIu64",\"ack_ns\":%"PRIu64
          ",\"latency_ns\":%"PRIu64"}\n",(unsigned)(c-clients),c->sent_at,ack_at,ack_at-c->sent_at);
        if (ferror(dhcp_dora)) output_failed=true;
        completion(c,CORRECT,ack_at);continue;
      }
      c->dhcp_stage=2;c->xid=(uint32_t)(++sequence);
      if (!send_dhcp(c,3)) completion(c,TRANSPORT,now_ns());
    } else {
      counts[c->phase].renew_correct++;
      if (opt.dhcp_renew_only) {completion(c,CORRECT,now_ns());continue;}
      c->dhcp_stage=3;
      c->xid=(uint32_t)(++sequence);
      if (send_dhcp(c,7)) { counts[c->phase].release_sent++;completion(c,CORRECT,now_ns()); }
      else completion(c,TRANSPORT,now_ns());
    }
  }
}
static void print_counters(FILE *out,const struct counters *v) {
  fprintf(out,"{\"scheduled\":%" PRIu64 ",\"sent\":%" PRIu64 ",\"correct\":%" PRIu64
    ",\"timeout\":%" PRIu64 ",\"wrong\":%" PRIu64 ",\"transport_error\":%" PRIu64
    ",\"scheduled_skipped\":%" PRIu64 ",\"stale_reply\":%" PRIu64 ",\"datagrams_sent\":%" PRIu64
    ",\"release_sent\":%" PRIu64 ",\"dora_correct\":%" PRIu64 ",\"renew_correct\":%" PRIu64
    ",\"correct_in_window\":%" PRIu64 ",\"correct_after_window\":%" PRIu64
    ",\"send_lag_count\":%" PRIu64 ",\"send_lag_sum_ns\":%" PRIu64
    ",\"send_lag_max_ns\":%" PRIu64 "}",
    v->scheduled,v->sent,v->correct,v->timeout,v->wrong,v->transport,v->skipped,
    v->stale,v->datagrams,v->release_sent,v->dora_correct,v->renew_correct,
    v->correct_in_window,v->correct_after_window,v->send_lag_count,v->send_lag_sum_ns,v->send_lag_max_ns);
}
static struct counters aggregate(const struct counters *a,const struct counters *b) {
  struct counters result={0};
#define ADD(field) result.field=a->field+b->field
  ADD(scheduled);ADD(sent);ADD(correct);ADD(timeout);ADD(wrong);ADD(transport);ADD(skipped);
  ADD(stale);ADD(datagrams);ADD(release_sent);ADD(dora_correct);ADD(renew_correct);
  ADD(correct_in_window);ADD(correct_after_window);
  ADD(send_lag_count);ADD(send_lag_sum_ns);
  result.send_lag_max_ns=a->send_lag_max_ns>b->send_lag_max_ns?a->send_lag_max_ns:b->send_lag_max_ns;
#undef ADD
  return result;
}
static bool safe_string(const char *value) {
  for (;*value;value++) if ((unsigned char)*value<32 || *value=='"' || *value=='\\') return false;
  return true;
}
static void usage(void) {
  fprintf(stderr,"m6a_loadgen --mode udp|tcp|dhcp --host IPv4 --port N --clients N\n"
    " --duration-seconds N --warmup-seconds N --rate N (0=closed loop) --seed N\n"
    " --name-prefix DOMAIN --profile hit|miss|mixed --qtype a|aaaa|aaaa30|txt|cname|mix\n"
    " --cache-names N --timeout-ms N --saturation-seconds N --output PREFIX\n"
    " --epoch-output JSON_PATH --epoch-file INTEGER_PATH\n"
    " DHCP: --client-port 68 --interface lo --dhcp-first-address IPv4 --dhcp-renew-only\n");
}
static uint64_t number(const char *text) {
  char *end=NULL; errno=0; unsigned long long result=strtoull(text,&end,0);
  if (errno || !*text || *text=='-' || *end) { fprintf(stderr,"invalid integer: %s\n",text); exit(2); }
  return result;
}
static double decimal(const char *text) {
  char *end=NULL; errno=0; double result=strtod(text,&end);
  if (errno || !*text || *end || !(result>=0) || result>86400) { fprintf(stderr,"invalid number: %s\n",text); exit(2); }
  return result;
}
int main(int argc,char **argv) {
  static const struct option options[]={
    {"mode",1,0,'m'},{"host",1,0,'h'},{"port",1,0,'p'},{"clients",1,0,'c'},
    {"duration-seconds",1,0,'d'},{"warmup-seconds",1,0,'w'},{"rate",1,0,'r'},
    {"seed",1,0,'s'},{"name-prefix",1,0,'n'},{"output",1,0,'o'},
    {"profile",1,0,'f'},{"cache-names",1,0,'a'},{"timeout-ms",1,0,'t'},
    {"qtype",1,0,'q'},{"client-port",1,0,'P'},{"interface",1,0,'i'},
    {"dhcp-first-address",1,0,'A'},{"epoch-output",1,0,'E'},{"epoch-file",1,0,'F'},
    {"saturation-seconds",1,0,'S'},{"dhcp-renew-only",0,0,'R'},{"help",0,0,'H'},{0,0,0,0}};
  int option;
  while ((option=getopt_long(argc,argv,"",options,NULL))!=-1) {
    switch (option) {
      case 'm':opt.mode=optarg;break;case 'h':opt.host=optarg;break;
      case 'p':opt.port=(unsigned)number(optarg);break;case 'c':opt.clients=(unsigned)number(optarg);break;
      case 'd':opt.duration=decimal(optarg);break;case 'w':opt.warmup=decimal(optarg);break;
      case 'r':opt.rate=decimal(optarg);break;case 's':opt.seed=number(optarg);break;
      case 'R':opt.dhcp_renew_only=true;break;
      case 'n':opt.prefix=optarg;break;case 'o':opt.output=optarg;break;case 'f':opt.profile=optarg;break;
      case 'a':opt.cache_names=(unsigned)number(optarg);break;case 't':opt.timeout_ms=(unsigned)number(optarg);break;
      case 'q':opt.qtype=optarg;break;case 'P':opt.client_port=(unsigned)number(optarg);break;
      case 'i':opt.interface=optarg;break;
      case 'E':opt.epoch_output=optarg;break;
      case 'F':opt.epoch_file=optarg;break;case 'S':opt.saturation=decimal(optarg);break;
      case 'A':if (inet_pton(AF_INET,optarg,&opt.dhcp_first)!=1) { usage();return 2; } break;
      default:usage();return option=='H'?0:2;
    }
  }
  if (!opt.output || optind!=argc || !opt.clients || opt.clients>MAX_CLIENTS ||
      !opt.port || opt.port>65535 || !opt.client_port || opt.client_port>65535 ||
      !opt.cache_names || opt.cache_names>65536 || !opt.timeout_ms || opt.timeout_ms>60000 ||
      !opt.duration || opt.saturation>=opt.duration || strlen(opt.prefix)>200 ||
      (opt.dhcp_renew_only && (strcmp(opt.mode,"dhcp") || !opt.warmup)) ||
      (strcmp(opt.mode,"udp")&&strcmp(opt.mode,"tcp")&&strcmp(opt.mode,"dhcp")) ||
      (strcmp(opt.profile,"hit")&&strcmp(opt.profile,"miss")&&strcmp(opt.profile,"mixed")) ||
      (strcmp(opt.qtype,"a")&&strcmp(opt.qtype,"aaaa")&&strcmp(opt.qtype,"aaaa30")&&strcmp(opt.qtype,"txt")&&strcmp(opt.qtype,"cname")&&strcmp(opt.qtype,"mix")) ||
      !safe_string(opt.output)||!safe_string(opt.prefix)||!safe_string(opt.interface)) { usage();return 2; }
  memset(&destination,0,sizeof(destination)); destination.sin_family=AF_INET;
  destination.sin_port=htons((uint16_t)opt.port);
  if (inet_pton(AF_INET,opt.host,&destination.sin_addr)!=1) { usage();return 2; }
  char path[4096]; if (snprintf(path,sizeof(path),"%s.latencies.bin",opt.output)>=(int)sizeof(path)) return 2;
  latencies=fopen(path,"wbx"); if (!latencies) { perror(path);return 2; }
  if (setvbuf(latencies,NULL,_IOFBF,1024*1024)) { perror("setvbuf");return 2; }
  if (snprintf(path,sizeof(path),"%s.send-lag.bin",opt.output)>=(int)sizeof(path)) return 2;
  send_lags=fopen(path,"wbx"); if (!send_lags) { perror(path);return 2; }
  if (setvbuf(send_lags,NULL,_IOFBF,1024*1024)) { perror("setvbuf");return 2; }
  if (snprintf(path,sizeof(path),"%s.wire-samples.jsonl",opt.output)>=(int)sizeof(path)) return 2;
  wire_samples=fopen(path,"wx");if (!wire_samples) { perror(path);return 2; }
  if (opt.dhcp_renew_only) {
    if (snprintf(path,sizeof(path),"%s.dhcp-dora.jsonl",opt.output)>=(int)sizeof(path)) return 2;
    dhcp_dora=fopen(path,"wx");if (!dhcp_dora) {perror(path);return 2;}
  }
  signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);signal(SIGPIPE,SIG_IGN);
  for (unsigned i=0;i<opt.clients;i++) clients[i].fd=-1;
  bool dhcp=!strcmp(opt.mode,"dhcp");
  if (dhcp) {
    if (!opt.dhcp_first) { fprintf(stderr,"DHCP requires --dhcp-first-address\n");return 2; }
    int fd=socket(AF_INET,SOCK_DGRAM,0),one=1;
    if (fd<0 || setsockopt(fd,SOL_SOCKET,SO_BROADCAST,&one,sizeof(one))) { perror("DHCP socket");return 2; }
#ifdef SO_BINDTODEVICE
    if (*opt.interface && setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,opt.interface,strlen(opt.interface)+1)) { perror("SO_BINDTODEVICE");return 2; }
#else
    if (*opt.interface && strcmp(opt.interface,"lo")) { fprintf(stderr,"interface binding requires Linux\n");return 2; }
#endif
    struct sockaddr_in local={0}; local.sin_family=AF_INET;local.sin_port=htons((uint16_t)opt.client_port);
    if (bind(fd,(struct sockaddr *)&local,sizeof(local)) || fcntl(fd,F_SETFL,O_NONBLOCK)) { perror("DHCP bind");return 2; }
    clients[0].fd=fd;
    for (unsigned i=0;i<opt.clients;i++) clients[i].address=htonl(ntohl(opt.dhcp_first)+i);
  } else for (unsigned i=0;i<opt.clients;i++) if (!socket_connect(&clients[i])) { perror("connect");return 2; }
  sequence=opt.seed<<32;
  warmup_start=now_ns(); measure_start=warmup_start+(uint64_t)(opt.warmup*NS);
  measure_end=measure_start+(uint64_t)(opt.duration*NS);
  saturation_start=measure_end-(uint64_t)(opt.saturation*NS);
  if (opt.epoch_output && !publish_epoch(opt.epoch_output,true)) { perror("epoch-output");return 2; }
  if (opt.epoch_file && !publish_epoch(opt.epoch_file,false)) { perror("epoch-file");return 2; }
  uint64_t next=warmup_start, interval=opt.rate>0?(uint64_t)(NS/opt.rate):0;
  unsigned turn=0; bool transition=false; struct pollfd pollfds[MAX_CLIENTS];
  while (!stopping) {
    uint64_t time=now_ns();
    if (!transition && time>=measure_start) {
      if (opt.dhcp_renew_only) {
        for (unsigned i=0;i<opt.clients;i++) if (!clients[i].leased) renew_setup_failed=true;
        if (renew_setup_failed) {stopping=1;break;}
      }
      transition=true;
      next=time;
    }
    unsigned phase=transition?(time>=saturation_start?2:1):0;
    uint64_t active_interval=phase==2?0:interval;
    unsigned outstanding=0;
    for (unsigned i=0;i<opt.clients;i++) {
      struct client *c=&clients[i];
      if (c->busy && time>=c->deadline) {
        completion(c,TIMEOUT,time);
        /* Keep the timeout, then discard the stream before another request. */
        if (!strcmp(opt.mode,"tcp")) tcp_reset(c);
      }
      if (c->busy) outstanding++;
    }
    if (time>=measure_end && !outstanding) break;
    if (time<measure_end) {
      if (!active_interval) {
        for (unsigned i=0;i<opt.clients;i++) if (!clients[i].busy) start_request(&clients[i],time,phase);
      } else while (next<=time) {
        start_request(&clients[turn++%opt.clients],next,phase);next+=active_interval;
      }
    }
    unsigned nfds=dhcp?1:opt.clients;
    for (unsigned i=0;i<nfds;i++) {
      pollfds[i].fd=clients[i].fd; pollfds[i].events=POLLIN;
      if (!dhcp && !strcmp(opt.mode,"tcp") && clients[i].busy && clients[i].tx_off<clients[i].tx_len) pollfds[i].events|=POLLOUT;
      pollfds[i].revents=0;
    }
    uint64_t wake=time+10000000;
    if (active_interval && time<measure_end && next<wake) wake=next;
    if (time<saturation_start && saturation_start<wake) wake=saturation_start;
    if (!transition && measure_start<wake) wake=measure_start;
    if (time<measure_end && measure_end<wake) wake=measure_end;
    for (unsigned i=0;i<opt.clients;i++) if (clients[i].busy && clients[i].deadline<wake) wake=clients[i].deadline;
    uint64_t current=now_ns(); struct timespec delay={0,0};
    if (wake>current) { delay.tv_sec=(time_t)((wake-current)/NS);delay.tv_nsec=(long)((wake-current)%NS); }
#ifdef __linux__
    int ready=ppoll(pollfds,nfds,&delay,NULL);
#else
    int ready=poll(pollfds,nfds,(int)((wake>current?(wake-current):0)/1000000));
#endif
    if (ready<0) { if (errno==EINTR) continue;perror("poll");stopping=1;break; }
    for (unsigned i=0;i<nfds;i++) {
      struct client *c=&clients[i];short events=pollfds[i].revents;
      if (events&POLLOUT) {
        uint64_t first_send=now_ns();
        ssize_t n=send(c->fd,c->tx+c->tx_off,c->tx_len-c->tx_off,0);
        if (n>0) { if (!c->tx_off) actual_send_at(c,first_send);c->tx_off+=(size_t)n; }
        else if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) { completion(c,TRANSPORT,now_ns());tcp_reset(c); }
      }
      if (c->fd>=0 && events&POLLIN) { if (dhcp) receive_dhcp();else receive_dns(c,now_ns()); }
      if (c->fd>=0 && events&(POLLERR|POLLHUP|POLLNVAL)) {
        if (c->busy) completion(c,TRANSPORT,now_ns());else tcp_idle_connection_errors++;
        tcp_reset(c);
      }
    }
  }
  run_end=now_ns();
  for (unsigned i=0;i<opt.clients;i++) if (clients[i].busy) completion(&clients[i],TIMEOUT,run_end);
  if (dhcp) socket_close(&clients[0]);else for (unsigned i=0;i<opt.clients;i++) socket_close(&clients[i]);
  if (fclose(latencies)) output_failed=true;
  if (fclose(send_lags)) output_failed=true;
  if (fclose(wire_samples)) output_failed=true;
  if (dhcp_dora && fclose(dhcp_dora)) output_failed=true;
  if (snprintf(path,sizeof(path),"%s.json",opt.output)>=(int)sizeof(path)) return 2;
  FILE *json=fopen(path,"wx");if (!json) { perror(path);return 2; }
  fprintf(json,"{\n\"schema\":1,\"mode\":\"%s\",\"host\":\"%s\",\"port\":%u,\"clients\":%u,\n"
    "\"profile\":\"%s\",\"qtype\":\"%s\",\"name_prefix\":\"%s\",\"seed\":%" PRIu64 ",\"rate\":%.9g,\n"
    "\"warmup_seconds\":%.9g,\"measurement_seconds\":%.9g,\"saturation_seconds\":%.9g,\"timeout_ms\":%u,\n"
    "\"warmup_start_ns\":%" PRIu64 ",\"measurement_start_ns\":%" PRIu64 ",\"measurement_end_ns\":%" PRIu64 ",\"run_end_ns\":%" PRIu64 ",\n"
    "\"interrupted\":%s,\"output_failed\":%s,\"tcp_connections\":%" PRIu64 ",\"tcp_reconnections\":%" PRIu64 ",\"tcp_idle_connection_errors\":%" PRIu64 ",\"warmup\":",
    opt.mode,opt.host,opt.port,opt.clients,opt.profile,opt.qtype,opt.prefix,opt.seed,opt.rate,
    opt.warmup,opt.duration,opt.saturation,opt.timeout_ms,warmup_start,measure_start,measure_end,run_end,
    stopping?"true":"false",output_failed?"true":"false",tcp_connections,tcp_reconnections,tcp_idle_connection_errors);
  unsigned leased_clients=0;for(unsigned i=0;i<opt.clients;i++) if(clients[i].leased)leased_clients++;
  struct counters measured=aggregate(&counts[1],&counts[2]);
  print_counters(json,&counts[0]);fputs(",\n\"measurement\":",json);print_counters(json,&measured);
  fputs(",\n\"steady\":",json);print_counters(json,&counts[1]);
  fputs(",\n\"saturation\":",json);print_counters(json,&counts[2]);
  fprintf(json,",\n\"saturation_start_ns\":%" PRIu64,saturation_start);
  fprintf(json,",\n\"dhcp_renew_only\":%s,\"renew_setup_failed\":%s,\"leased_clients_final\":%u",
    opt.dhcp_renew_only?"true":"false",renew_setup_failed?"true":"false",leased_clients);
  fputs(",\n\"latency_record_bytes\":32,\"latency_byte_order\":\"little\",\"send_lag_record_bytes\":16\n}\n",json);
  bool json_failed=ferror(json)!=0;if (fclose(json)) json_failed=true;
  return stopping||output_failed||json_failed?2:0;
}
