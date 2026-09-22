/* Exact-image libubus correctness/latency and bounded-backpressure probe.
 * Separate test ELF; never install it or the link-only libraries on a router.
 * event-stress SOCKET grouped|interleaved|monitor|slow N SUBJECT_PID
 * Normal cases have eight handlers over two owners (monitor: one owner).
 * Slow case stops reading for N sends, then validates surviving frames and
 * a new recovery event. The exact C queue intentionally drops at 1 MiB.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

#define EVENT "r131.stress"
#define HANDLERS 8
#define PAD_BYTES 2048
#define C_TXQ_LIMIT 1048576
static struct ubus_context *owners[2], *monitor;
static struct ubus_event_handler handlers[HANDLERS];
static unsigned owner_of[HANDLERS], received, mirrored, sent, owner_count;
static unsigned counts[HANDLERS], last_serial[HANDLERS];
static uint64_t last_ordinal[2];
static int owner_seen[2], sequence_seen, allow_gaps;
static uint16_t sequence_base, monitor_seq;
static int monitor_seen;
static struct blob_buf data, expected;
static struct blob_attr *serial_attr;
static unsigned padding;

static void need(int ok, const char *s) { if (!ok) { fprintf(stderr, "%s\n", s); exit(1); } }
static void timeout(int sig) { (void)sig; static const char s[]="event-stress timeout\n"; (void)write(2,s,sizeof(s)-1); _exit(124); }
static unsigned number(const char *s, unsigned max) { char *e; errno=0; unsigned long n=strtoul(s,&e,10); need(*s && !*e && !errno && n<=max,"bad argument"); return n; }
static uint64_t clock_ns(clockid_t c) { struct timespec t; need(!clock_gettime(c,&t),"clock failed"); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }
static void pin(pid_t subject) { cpu_set_t m; CPU_ZERO(&m); CPU_SET(0,&m); need(!sched_setaffinity(0,sizeof(m),&m),"pin caller"); need(!sched_getaffinity(subject,sizeof(m),&m) && CPU_COUNT(&m)==1 && CPU_ISSET(1,&m),"daemon not CPU1"); }
static unsigned fd_count(pid_t pid) { char p[64]; snprintf(p,sizeof(p),"/proc/%d/fd",pid); DIR *d=opendir(p); need(d!=NULL,"fd dir"); unsigned n=0; struct dirent *e; errno=0; while((e=readdir(d))) if(e->d_name[0]!='.')n++; need(!errno && !closedir(d),"fd enumerate"); return n; }
static void memory(pid_t pid, const char *phase) {
 char p[64],line[256]; snprintf(p,sizeof(p),"/proc/%d/status",pid); FILE *f=fopen(p,"r"); need(f!=NULL,"status open");
 unsigned rss=0,anon=0,vmdata=0,seen=0; while(fgets(line,sizeof(line),f)) { if(sscanf(line,"VmRSS: %u kB",&rss)==1)seen|=1; if(sscanf(line,"RssAnon: %u kB",&anon)==1)seen|=2; if(sscanf(line,"VmData: %u kB",&vmdata)==1)seen|=4; }
 need(!ferror(f) && !fclose(f) && seen==7,"status fields");
 printf("{\"phase\":\"%s\",\"subject_pid\":%d,\"rss_kib\":%u,\"rssanon_kib\":%u,\"vmdata_kib\":%u,\"fds\":%u}\n",phase,pid,rss,anon,vmdata,fd_count(pid)); fflush(stdout);
}
static void payload(struct blob_buf *b,unsigned serial) {
 static char pad[PAD_BYTES+1]; if(!pad[0]) { for(unsigned i=0;i<PAD_BYTES;i++)pad[i]=(char)('A'+i%23); }
 need(!blob_buf_init(b,0),"payload init"); need(!blobmsg_add_u32(b,"serial",serial),"serial allocation");
 if(padding)need(!blobmsg_add_string(b,"bytes",pad),"pad allocation");
}
static unsigned check_payload(struct blob_attr *msg) {
 static const struct blobmsg_policy p={.name="serial",.type=BLOBMSG_TYPE_INT32}; struct blob_attr *tb[1]={0};
 need(msg && !blobmsg_parse(&p,1,tb,blob_data(msg),blob_len(msg)) && tb[0],"missing serial");
 unsigned serial=blobmsg_get_u32(tb[0]); need(serial<sent,"future serial"); payload(&expected,serial);
 need(blob_len(msg)==blob_len(expected.head) && !memcmp(blob_data(msg),blob_data(expected.head),blob_len(msg)),"payload bytes changed"); return serial;
}
static int event_cb(struct ubus_context *ctx,struct ubus_object *obj,struct ubus_request_data *req,const char *type,struct blob_attr *msg) {
 need(type && !strcmp(type,EVENT),"wrong event name"); unsigned index=HANDLERS;
 for(unsigned i=0;i<HANDLERS;i++)if(obj==&handlers[i].obj)index=i;
 need(index<HANDLERS && ctx==owners[owner_of[index]] && obj->id!=0 && req->object==obj->id && req->peer==0 && req->req_fd<0,"wrong callback target");
 unsigned serial=check_payload(msg), owner=owner_of[index]; uint64_t ordinal=(uint64_t)serial*HANDLERS+index;
 need(!counts[index] || serial>last_serial[index],"duplicate/reordered handler event");
 need(!owner_seen[owner] || ordinal>last_ordinal[owner],"reordered owner frames");
 if(!allow_gaps)need(serial==counts[index],"missing handler event");
 uint16_t seq=req->seq;
 if(!sequence_seen){ sequence_base=(uint16_t)(seq-ordinal); sequence_seen=1; }
 need(seq==(uint16_t)(sequence_base+ordinal),"wire event sequence changed");
 owner_seen[owner]=1;last_ordinal[owner]=ordinal;last_serial[index]=serial;counts[index]++;received++;
 return 0;
}
static const struct ubus_method event_method={.name=NULL,.handler=event_cb};
static void parse_attrs(struct blob_attr **tb,unsigned max,void *ptr,unsigned len) {
 memset(tb,0,max*sizeof(*tb));
 while(len) { struct blob_attr *a=ptr;need(len>=sizeof(*a) && blob_pad_len(a)>=sizeof(*a) && blob_pad_len(a)<=len,"malformed attribute");unsigned id=blob_id(a);if(id<max){need(!tb[id],"duplicate attribute");tb[id]=a;}unsigned size=blob_pad_len(a);ptr=(char *)ptr+size;len-=size; }
}
static void monitor_cb(struct ubus_context *ctx,uint32_t seq,struct blob_attr *msg) {
 (void)ctx; if(monitor_seen)need((uint16_t)seq==(uint16_t)(monitor_seq+1),"monitor sequence gap"); monitor_seen=1;monitor_seq=(uint16_t)seq;
 struct blob_attr *t[UBUS_MONITOR_MAX];parse_attrs(t,UBUS_MONITOR_MAX,blob_data(msg),blob_len(msg));
 need(t[UBUS_MONITOR_TYPE] && t[UBUS_MONITOR_SEND] && t[UBUS_MONITOR_DATA] && t[UBUS_MONITOR_CLIENT] && t[UBUS_MONITOR_SEQ],"monitor envelope");
 if(blob_get_u32(t[UBUS_MONITOR_TYPE])!=UBUS_MSG_INVOKE || !blob_get_u8(t[UBUS_MONITOR_SEND]))return;
 struct blob_attr *a[UBUS_ATTR_MAX];parse_attrs(a,UBUS_ATTR_MAX,blob_data(t[UBUS_MONITOR_DATA]),blob_len(t[UBUS_MONITOR_DATA]));
 if(!a[UBUS_ATTR_METHOD] || strcmp(blob_get_string(a[UBUS_ATTR_METHOD]),EVENT))return;
 need(a[UBUS_ATTR_OBJID] && a[UBUS_ATTR_DATA],"mirror event envelope"); unsigned id=blob_get_u32(a[UBUS_ATTR_OBJID]),index=HANDLERS;
 for(unsigned i=0;i<HANDLERS;i++)if(handlers[i].obj.id==id)index=i;
 need(index<HANDLERS && blob_get_u32(t[UBUS_MONITOR_CLIENT])==owners[owner_of[index]]->local_id,"mirror target changed");
 unsigned serial=check_payload(a[UBUS_ATTR_DATA]); need((uint64_t)serial*HANDLERS+index==mirrored,"mirror event order");
 need(sequence_seen && (uint16_t)blob_get_u32(t[UBUS_MONITOR_SEQ])==(uint16_t)(sequence_base+mirrored),"mirror event sequence"); mirrored++;
}
static void poll_context(struct ubus_context *c,int timeout_ms) {
 struct pollfd p={.fd=c->sock.fd,.events=POLLIN}; int rc;do{rc=poll(&p,1,timeout_ms);}while(rc<0 && errno==EINTR);
 need(rc>=0,"poll failed");if(rc){need((p.revents&POLLIN) && !(p.revents&(POLLERR|POLLHUP|POLLNVAL)),"socket lost");ubus_handle_event(c);}
}
static void pump(unsigned target) {
 uint64_t end=clock_ns(CLOCK_MONOTONIC)+5000000000ULL;
 while(received<target || (monitor && mirrored<target)) {
  for(unsigned i=0;i<owner_count;i++)poll_context(owners[i],received<target?1:0);
  if(monitor)poll_context(monitor,mirrored<target?1:0);
  need(clock_ns(CLOCK_MONOTONIC)<end,"delivery timeout");
 }
 need(received==target && (!monitor || mirrored==target),"extra deliveries");
}
static void send_one(struct ubus_context *sender) { uint32_t value=htonl(sent++);memcpy(blobmsg_data(serial_attr),&value,sizeof(value));need(!ubus_send_event(sender,EVENT,data.head),"event send failed"); }
static void barrier(void) {
 for(unsigned i=0;i<owner_count;i++)need(ubus_lookup(owners[i],"r131.missing",NULL,NULL)==UBUS_STATUS_NOT_FOUND,"listener barrier failed");
 if(monitor)poll_context(monitor,0);
}
int main(int argc,char **argv) {
 need(argc==6 && !strcmp(argv[1],"event-stress"),"event-stress SOCKET grouped|interleaved|monitor|slow N SUBJECT_PID");
 const char *mode=argv[3]; int slow=!strcmp(mode,"slow"),mon=!strcmp(mode,"monitor"),inter=!strcmp(mode,"interleaved");
 need(slow || mon || inter || !strcmp(mode,"grouped"),"unknown scenario");unsigned n=number(argv[4],5000);need(n>0 && (!slow || (n>=192 && n<=512)),"N range");
 pid_t subject=(pid_t)number(argv[5],INT_MAX);need(subject>0 && subject!=getpid(),"subject pid");signal(SIGALRM,timeout);alarm(60);pin(subject);memory(subject,"empty");unsigned base_fds=fd_count(subject);
 clockid_t subject_clock;need(!clock_getcpuclockid(subject,&subject_clock),"subject clock");
 struct ubus_context *sender=ubus_connect(argv[2]);need(sender!=NULL,"sender connect");owner_count=(slow||mon)?1:2;
 for(unsigned i=0;i<owner_count;i++){owners[i]=ubus_connect(argv[2]);need(owners[i]!=NULL,"owner connect");}
 for(unsigned i=0;i<HANDLERS;i++){owner_of[i]=owner_count==1?0:(inter?i%2:i/4);need(!ubus_register_event_handler(owners[owner_of[i]],&handlers[i],EVENT),"register");handlers[i].obj.methods=&event_method;handlers[i].obj.n_methods=1;}
 if(mon){monitor=ubus_connect(argv[2]);need(monitor!=NULL,"monitor connect");monitor->monitor_cb=monitor_cb;need(!ubus_monitor_start(monitor),"monitor start");}
 memory(subject,"registered");need(fd_count(subject)==base_fds+owner_count+1+(unsigned)mon,"connection count");
 padding=slow?PAD_BYTES:0;payload(&data,0);struct blob_attr *tb[1]={0};static const struct blobmsg_policy policy={.name="serial",.type=BLOBMSG_TYPE_INT32};need(!blobmsg_parse(&policy,1,tb,blob_data(data.head),blob_len(data.head)) && tb[0],"serial field");serial_attr=tb[0];
 uint64_t *latency=calloc(n,sizeof(*latency));need(latency!=NULL,"latency allocation");unsigned warmup=slow?0:20;
 for(unsigned i=0;i<warmup;i++){send_one(sender);pump(sent*HANDLERS);} unsigned before=received;
 uint64_t wall=clock_ns(CLOCK_MONOTONIC),cpu=clock_ns(subject_clock),own=clock_ns(CLOCK_PROCESS_CPUTIME_ID);
 if(slow){int rcv=1024;need(!setsockopt(owners[0]->sock.fd,SOL_SOCKET,SO_RCVBUF,&rcv,sizeof(rcv)),"receive buffer");allow_gaps=1;}
 for(unsigned i=0;i<n;i++){uint64_t start=clock_ns(CLOCK_MONOTONIC);send_one(sender);if(!slow)pump(sent*HANDLERS);latency[i]=clock_ns(CLOCK_MONOTONIC)-start;}
 uint64_t cpu_after=clock_ns(subject_clock),own_after=clock_ns(CLOCK_PROCESS_CPUTIME_ID),wall_after=clock_ns(CLOCK_MONOTONIC);memory(subject,slow?"flooded":"delivered");
 unsigned flooded_received=0;
 if(slow){
  /* Drain first so the barrier STATUS has room even at the drop cap. */
  for(;;){unsigned old=received;poll_context(owners[0],100);if(received==old)break;}
  barrier();flooded_received=received;need(received>0 && received<n*HANDLERS,"slow case did not exercise bounded drop");memory(subject,"drained");
  unsigned recovery_target=received+HANDLERS;send_one(sender);pump(recovery_target);need(received==recovery_target,"recovery event lost");
 }else barrier();
 for(unsigned i=0;i<HANDLERS;i++)need(!ubus_unregister_event_handler(owners[owner_of[i]],&handlers[i]),"remove handler");
 if(monitor){need(!ubus_monitor_stop(monitor),"monitor stop");ubus_free(monitor);monitor=NULL;}
 for(unsigned i=0;i<owner_count;i++){ubus_free(owners[i]);}
 ubus_free(sender);blob_buf_free(&data);blob_buf_free(&expected);uloop_done();
 uint64_t end=clock_ns(CLOCK_MONOTONIC)+5000000000ULL;while(fd_count(subject)!=base_fds){need(clock_ns(CLOCK_MONOTONIC)<end,"fd cleanup");usleep(1000);} memory(subject,"closed");
 printf("{\"phase\":\"RESULT\",\"mode\":\"%s\",\"n\":%u,\"warmup\":%u,\"handlers\":8,\"owners\":%u,\"subject_pid\":%d,\"subject_cpu\":1,\"client_cpu\":0,\"received\":%u,\"mirrored\":%u,\"flooded_received\":%u,\"c_txq_limit_bytes\":%u,\"payload_bytes\":%u,\"payload_target_order_sequence_checked\":true,\"handlers_removed\":true,\"fd_baseline_restored\":true,\"wall_ns\":%"PRIu64",\"daemon_cpu_ns\":%"PRIu64",\"caller_cpu_ns\":%"PRIu64",\"latency_ns\":[",mode,n,warmup,owner_count,subject,received-before,mon ? mirrored - warmup * HANDLERS : 0,flooded_received,C_TXQ_LIMIT,padding,wall_after-wall,cpu_after-cpu,own_after-own);
 for(unsigned i=0;i<n;i++){printf("%s%"PRIu64,i?",":"",latency[i]);}
 puts("]}");free(latency);alarm(0);return 0;
}
