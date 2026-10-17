/* Fixed M6a upstream: one process, UDP/TCP, no per-query allocation or logging. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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

#define CONNECTIONS 64
#define BUFFER 8192
#define PENDING_UDP 128
static volatile sig_atomic_t running=1, enabled=1;
static int failed;
static unsigned answer_phase, answer_ttl=3600;
static uint64_t delay_ns, delay_queue_dropped;
static uint64_t epoch, steady_ns=90000000000ULL;
static double fault_start=-1, fault_end=-1;
static const char *epoch_file, *output, *ready_file;
struct counts { uint64_t requests,replies,generated,disabled,dropped,invalid,udp,tcp; };
static struct counts total, phases[5]; /* setup/warm, steady, saturation, fault, recovery */
static bool audit_fixed_mixed_cohort;
/* Fixed m6a.test/seed 0x293001 fixture: 800 prefill names and 1000 unique
 * misses among 1000 warmup + 4000 measurement requests. No wall-clock split. */
static struct {
  unsigned char seen[225];
  uint64_t prefill_unique,warmup_miss_unique,measurement_miss_unique;
  uint64_t duplicate_queries,unexpected_queries;
} mixed_cohort;
struct connection { int fd; unsigned char rx[BUFFER],tx[BUFFER]; size_t rn,tn,sent; unsigned phase; uint64_t due; };
static struct connection clients[CONNECTIONS];
struct datagram {
  unsigned char data[4096]; size_t size; struct sockaddr_in peer;
  socklen_t peer_size; unsigned phase; uint64_t due;
};
static struct datagram pending[PENDING_UDP];
static uint64_t now_ns(void) {
  struct timespec t;
  if(clock_gettime(CLOCK_MONOTONIC,&t)) { perror("clock");exit(2); }
  return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static void stop_handler(int n) { if(n==SIGUSR1)enabled=0;else if(n==SIGUSR2)enabled=1;else running=0; }
static unsigned get16(const unsigned char *p) { return ((unsigned)p[0]<<8)|p[1]; }
static void put16(unsigned char *p,unsigned n) { p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)n; }
static void put32(unsigned char *p,uint32_t n) {
  p[0]=(unsigned char)(n>>24);p[1]=(unsigned char)(n>>16);p[2]=(unsigned char)(n>>8);p[3]=(unsigned char)n;
}
static void read_epoch(void);
static void audit_mixed(const char *host,size_t hn,unsigned type,bool tcp,
                        const unsigned char *wire_name) {
  static const unsigned char suffix[]={3,'m','6','a',4,'t','e','s','t',0};
  const uint64_t base=UINT64_C(0x29300100000000);
  unsigned digits,slot,index;uint64_t value=0,*counter;
  if(tcp)goto unexpected;
  if(hn==14 && host[0]=='q')digits=4;
  else if(hn==24 && host[0]=='u')digits=14;
  else goto unexpected;
  /* The main client publishes its epoch after prefill, before sending any
   * request. Refresh here: a packet can wake a poll begun before publication. */
  read_epoch();
  if((digits==4 && epoch) || (digits==14 && !epoch))goto unexpected;
  if(memcmp(host+digits+1,".m6a.test",9) || wire_name[0]!=digits+1 ||
     memcmp(wire_name+digits+2,suffix,sizeof suffix))goto unexpected;
  for(unsigned i=1;i<=digits;i++) {
    unsigned char c=(unsigned char)host[i];unsigned nibble;
    if(c>='0' && c<='9')nibble=c-'0';
    else if(c>='a' && c<='f')nibble=c-'a'+10;
    else goto unexpected;
    value=(value<<4)|nibble;
  }
  if(digits==4) {
    if(value>=800)goto unexpected;
    slot=index=(unsigned)value;counter=&mixed_cohort.prefill_unique;
  } else {
    if(value<=base || value>base+5000 || value%5!=4)goto unexpected;
    unsigned sequence=(unsigned)(value-base);
    index=(unsigned)(value%800);slot=800+(sequence-1)/5;
    counter=sequence<=1000?&mixed_cohort.warmup_miss_unique:&mixed_cohort.measurement_miss_unique;
  }
  if(type!=(index%10<7?1u:28u))goto unexpected;
  unsigned char mask=(unsigned char)(1u<<(slot%8));
  if(mixed_cohort.seen[slot/8]&mask)mixed_cohort.duplicate_queries++;
  else {mixed_cohort.seen[slot/8]|=mask;(*counter)++;}
  return;
unexpected: mixed_cohort.unexpected_queries++;
}
static void read_epoch(void) {
  if(epoch || !epoch_file)return;
  int fd;do fd=open(epoch_file,O_RDONLY);while(fd<0 && errno==EINTR && running);
  if(fd<0)return;
  char b[512];ssize_t n;
  do n=read(fd,b,sizeof b-1);while(n<0 && errno==EINTR && running);
  close(fd);if(n<=0)return;b[n]=0;
  char *p=b;
  if(b[0]=='{') { p=strstr(b,"measurement_start_ns");if(!p)return;p=strchr(p,':');if(!p)return;p++; }
  errno=0;char *end;uint64_t v=strtoull(p,&end,10);
  if(!errno && end!=p && v)epoch=v;
}
static unsigned phase(uint64_t t) {
  if(!epoch || t<epoch)return 0;
  double seconds=(double)(t-epoch)/1e9;
  if(fault_start>=0) return seconds<fault_start?1:seconds<fault_end?3:4;
  return t-epoch<steady_ns?1:2;
}
static size_t record(unsigned char *out,const unsigned char *owner,size_t owner_n,unsigned type,
                     const unsigned char *data,size_t data_n) {
  memcpy(out,owner,owner_n);out+=owner_n;put16(out,type);put16(out+2,1);put32(out+4,answer_ttl);
  put16(out+8,(unsigned)data_n);memcpy(out+10,data,data_n);return owner_n+10+data_n;
}
static size_t answer(const unsigned char *q,size_t n,unsigned char *out,bool tcp) {
  uint64_t t=now_ns();unsigned p=phase(t);answer_phase=p;struct counts *c=&phases[p];
  bool cohort_counted=false;
  total.requests++;c->requests++;if(tcp){total.tcp++;c->tcp++;}else{total.udp++;c->udp++;}
  if(!enabled){total.disabled++;c->disabled++;if(audit_fixed_mixed_cohort)mixed_cohort.unexpected_queries++;return 0;}
  if(p==3){total.dropped++;c->dropped++;if(audit_fixed_mixed_cohort)mixed_cohort.unexpected_queries++;return 0;}
  size_t at=12,hn=0;char host[256];
  if(n<17 || get16(q+4)!=1 || (q[2]&0x80))goto invalid;
  while(at<n && q[at]) {
    unsigned len=q[at++];if(len>63 || at+len>n || hn+len+1>=sizeof host)goto invalid;
    if(hn)host[hn++]='.';
    memcpy(host+hn,q+at,len);hn+=len;at+=len;
  }
  if(at>=n || at+5>n)goto invalid;
  host[hn]=0;at++;unsigned type=get16(q+at);if(get16(q+at+2)!=1)goto invalid;at+=4;
  if(audit_fixed_mixed_cohort){audit_mixed(host,hn,type,tcp,q+12);cohort_counted=true;}
  bool cname=!strncmp(host,"cname-",6);
  if(type!=1 && type!=28 && type!=16)goto invalid;
  memcpy(out,q,at);put16(out+2,0x8180);put16(out+6,cname?2:1);put16(out+8,0);put16(out+10,0);
  static const unsigned char pointer[]={0xc0,0x0c}, a[]={192,0,2,1};
  static const unsigned char aaaa[]={0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
  static const unsigned char txt[]={3,'m','6','a'}, target[]={3,'m','6','a',6,'t','a','r','g','e','t',0};
  size_t size=at;
  if(cname) {
    if(type!=1)goto invalid;
    size+=record(out+size,pointer,sizeof pointer,5,target,sizeof target);
    size+=record(out+size,target,sizeof target,1,a,sizeof a);
  } else {
    const unsigned char *data=type==1?a:type==28?aaaa:txt;
    size_t count=type==1?sizeof a:type==28?sizeof aaaa:sizeof txt;
    size+=record(out+size,pointer,sizeof pointer,type,data,count);
  }
  total.generated++;c->generated++;return size;
invalid:
  if(audit_fixed_mixed_cohort && !cohort_counted)mixed_cohort.unexpected_queries++;
  total.invalid++;c->invalid++;return 0;
}
static int listener(unsigned port,int kind) {
  int fd=socket(AF_INET,kind,0),one=1; if(fd<0){perror("socket");exit(2);}
  if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one)){perror("setsockopt");exit(2);}
  struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons((uint16_t)port)};
  a.sin_addr.s_addr=htonl(0x7f000001u);
  if(bind(fd,(struct sockaddr *)&a,sizeof a)||fcntl(fd,F_SETFL,O_NONBLOCK)) {perror("bind/nonblock");exit(2);}
  if(kind==SOCK_STREAM && listen(fd,128)){perror("listen");exit(2);}return fd;
}
static void close_client(struct connection *c) { close(c->fd);c->fd=-1;c->rn=c->tn=c->sent=0; }
static bool send_datagram(int fd,struct datagram *d) {
  if(sendto(fd,d->data,d->size,0,(struct sockaddr *)&d->peer,d->peer_size)!=(ssize_t)d->size) {
    perror("sendto");return false;
  }
  total.replies++;phases[d->phase].replies++;d->size=0;return true;
}
static unsigned bounded_number(const char *s,unsigned max) {
  char *end;errno=0;unsigned long n=strtoul(s,&end,10);
  if(errno || !*s || *s=='-' || *end || n>max){fprintf(stderr,"invalid argument: %s\n",s);exit(2);}
  return (unsigned)n;
}
static void emit_counts(FILE *f,const struct counts *c) {
  fprintf(f,"{\"requests\":%"PRIu64",\"replies\":%"PRIu64",\"generated_replies\":%"PRIu64",\"disabled_requests\":%"PRIu64
    ",\"dropped_requests\":%"PRIu64",\"invalid_queries\":%"PRIu64",\"udp_requests\":%"PRIu64
    ",\"tcp_requests\":%"PRIu64"}",c->requests,c->replies,c->generated,c->disabled,c->dropped,c->invalid,c->udp,c->tcp);
}
int main(int argc,char **argv) {
  unsigned port=15354;
  for(int i=1;i<argc;i++) {
    if(!strcmp(argv[i],"--disabled")){enabled=0;continue;}
    if(!strcmp(argv[i],"--audit-fixed-mixed-cohort")){audit_fixed_mixed_cohort=true;continue;}
    if(i+1>=argc){fprintf(stderr,"missing argument\n");return 2;}
    const char *key=argv[i],*v=argv[++i];
    if(!strcmp(key,"--port"))port=(unsigned)strtoul(v,NULL,10);
    else if(!strcmp(key,"--epoch-file"))epoch_file=v;
    else if(!strcmp(key,"--output"))output=v;
    else if(!strcmp(key,"--ready-file"))ready_file=v;
    else if(!strcmp(key,"--fault-start"))fault_start=strtod(v,NULL);
    else if(!strcmp(key,"--fault-end"))fault_end=strtod(v,NULL);
    else if(!strcmp(key,"--delay-us"))delay_ns=(uint64_t)bounded_number(v,1000000)*1000;
    else if(!strcmp(key,"--ttl"))answer_ttl=bounded_number(v,3600);
    else if(!strcmp(key,"--steady-seconds"))steady_ns=(uint64_t)(strtod(v,NULL)*1e9);
    else {fprintf(stderr,"unknown argument %s\n",key);return 2;}
  }
  if(!output || !ready_file || !answer_ttl || !port || port>65535 ||
     (audit_fixed_mixed_cohort && !epoch_file) || (fault_start>=0 && fault_end<=fault_start))return 2;
  signal(SIGTERM,stop_handler);signal(SIGINT,stop_handler);signal(SIGUSR1,stop_handler);signal(SIGUSR2,stop_handler);
  signal(SIGPIPE,SIG_IGN);
  int udp=listener(port,SOCK_DGRAM),tcp=listener(port,SOCK_STREAM);
  for(unsigned i=0;i<CONNECTIONS;i++)clients[i].fd=-1;
  FILE *ready=fopen(ready_file,"w");if(!ready){perror("ready");return 2;}
  fprintf(ready,"{\"ready\":true,\"pid\":%ld,\"port\":%u}\n",(long)getpid(),port);fclose(ready);
  while(running) {
    read_epoch();uint64_t now=now_ns(),wake=now+10000000;
    for(unsigned i=0;i<PENDING_UDP;i++) if(pending[i].size) {
      if(pending[i].due<=now) {
        if(!send_datagram(udp,&pending[i])){failed=1;running=0;break;}
      } else if(pending[i].due<wake)wake=pending[i].due;
    }
    if(!running)break;
    struct pollfd fds[CONNECTIONS+2]={{.fd=udp,.events=POLLIN},{.fd=tcp,.events=POLLIN}};
    for(unsigned i=0;i<CONNECTIONS;i++) {
      struct connection *c=&clients[i];fds[i+2].fd=c->fd;
      fds[i+2].events=c->tn?(c->due<=now?POLLOUT:0):POLLIN;
      if(c->tn && c->due>now && c->due<wake)wake=c->due;
    }
    now=now_ns();struct timespec wait={0,(long)(wake>now?wake-now:0)};
    int rc=ppoll(fds,CONNECTIONS+2,&wait,NULL);if(rc<0){if(errno==EINTR)continue;perror("poll");failed=1;break;}
    if(fds[0].revents&POLLIN) {
      for(unsigned batch=0;batch<64;batch++) {
        unsigned char q[4096],a[4096];struct sockaddr_in peer;socklen_t len=sizeof peer;
        ssize_t n=recvfrom(udp,q,sizeof q,0,(struct sockaddr *)&peer,&len);
        if(n<0){if(errno!=EAGAIN && errno!=EWOULDBLOCK)perror("recvfrom");break;}
        size_t count=answer(q,(size_t)n,a,false);
        if(count) {
          unsigned i;for(i=0;i<PENDING_UDP && pending[i].size;i++);
          if(i==PENDING_UDP){delay_queue_dropped++;continue;}
          struct datagram *d=&pending[i];memcpy(d->data,a,count);d->size=count;
          d->peer=peer;d->peer_size=len;d->phase=answer_phase;d->due=now_ns()+delay_ns;
          if(!delay_ns && !send_datagram(udp,d)){failed=1;running=0;break;}
        }
      }
    }
    if(fds[1].revents&POLLIN) {
      int fd=accept(tcp,NULL,NULL);
      if(fd>=0) {
        unsigned i;for(i=0;i<CONNECTIONS && clients[i].fd>=0;i++);
        if(i==CONNECTIONS || fcntl(fd,F_SETFL,O_NONBLOCK))close(fd);else clients[i].fd=fd;
      }
    }
    for(unsigned i=0;i<CONNECTIONS;i++) {
      struct connection *c=&clients[i];short events=fds[i+2].revents;if(c->fd<0 || !events)continue;
      if(events&(POLLERR|POLLNVAL)){close_client(c);continue;}
      if(events&POLLOUT) {
        ssize_t n=send(c->fd,c->tx+c->sent,c->tn-c->sent,0);
        if(n>0){c->sent+=(size_t)n;if(c->sent==c->tn){total.replies++;phases[c->phase].replies++;c->tn=c->sent=0;}}
        else if(n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)){close_client(c);continue;}
      }
      if(events&(POLLIN|POLLHUP)) {
        ssize_t n=recv(c->fd,c->rx+c->rn,sizeof c->rx-c->rn,0);
        if(n>0)c->rn+=(size_t)n;
        else if(n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)){close_client(c);continue;}
      }
      if(c->fd>=0 && !c->tn && c->rn>=2) {
        unsigned n=get16(c->rx);if(n>4096 || n<12){close_client(c);continue;}
        if(c->rn>=n+2) {
          size_t len=answer(c->rx+2,n,c->tx+2,true);if(len){put16(c->tx,(unsigned)len);c->tn=len+2;c->phase=answer_phase;c->due=now_ns()+delay_ns;}
          memmove(c->rx,c->rx+n+2,c->rn-n-2);c->rn-=n+2;
        }
      }
    }
  }
  close(udp);close(tcp);for(unsigned i=0;i<CONNECTIONS;i++)if(clients[i].fd>=0)close_client(&clients[i]);
  FILE *f=fopen(output,"w");if(!f){perror("output");return 2;}
  fprintf(f,"{\"schema\":1,\"epoch_ns\":%"PRIu64",\"disabled\":%s,\"total\":",epoch,enabled?"false":"true");
  emit_counts(f,&total);fprintf(f,",\"delay_us\":%"PRIu64",\"ttl\":%u,\"delay_queue_dropped\":%"PRIu64,delay_ns/1000,answer_ttl,delay_queue_dropped);fprintf(f,",\"requests\":%"PRIu64",\"disabled_requests\":%"PRIu64",\"invalid_queries\":%"PRIu64",\"phases\":{",total.requests,total.disabled,total.invalid);
  static const char *names[]={"setup_warmup","steady","saturation","fault","recovery"};
  for(unsigned i=0;i<5;i++){if(i)fputc(',',f);fprintf(f,"\"%s\":",names[i]);emit_counts(f,&phases[i]);}
  fputc('}',f);
  if(audit_fixed_mixed_cohort)fprintf(f,",\"mixed_cohort\":{\"enabled\":true,\"schema\":1,"
    "\"prefill_unique\":%"PRIu64",\"warmup_miss_unique\":%"PRIu64",\"measurement_miss_unique\":%"PRIu64
    ",\"duplicate_queries\":%"PRIu64",\"unexpected_queries\":%"PRIu64"}",
    mixed_cohort.prefill_unique,mixed_cohort.warmup_miss_unique,mixed_cohort.measurement_miss_unique,
    mixed_cohort.duplicate_queries,mixed_cohort.unexpected_queries);
  fprintf(f,"}\n");if(fclose(f))return 2;return failed?1:0;
}
