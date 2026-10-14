/* Audit-only read-only syscall observer. Attach only to a caller-owned /tmp
 * experiment target; no injection, no target signals, never follow children. */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
struct syscall_info {
  uint8_t op, pad[3]; uint32_t arch; uint64_t ip, sp;
  union {
    struct { uint64_t nr, args[6]; } entry;
    struct { int64_t rval; uint8_t is_error; } exit;
  } data;
};
static volatile sig_atomic_t done;
static void finish(int sig) { (void)sig; done=1; }
static uint64_t ns(clockid_t clock) {
  struct timespec t; if (clock_gettime(clock,&t)) return 0;
  return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static void clocks(void) {
  printf("\"realtime_ns\":%"PRIu64",\"monotonic_ns\":%"PRIu64
         ",\"monotonic_raw_ns\":%"PRIu64",\"boottime_ns\":%"PRIu64,
         ns(CLOCK_REALTIME),ns(CLOCK_MONOTONIC),ns(CLOCK_MONOTONIC_RAW),ns(CLOCK_BOOTTIME));
}
static uint64_t starttime(pid_t pid) {
  char path[64],buf[4096]; snprintf(path,sizeof path,"/proc/%ld/stat",(long)pid);
  FILE *f=fopen(path,"r"); if (!f) return 0;
  char *ok=fgets(buf,sizeof buf,f); fclose(f); if (!ok) return 0;
  char *p=strrchr(buf,')'); if (!p || p[1]!=' ') return 0;
  p+=2; char *save=NULL,*word=strtok_r(p," ",&save);
  for (int field=3;word;field++,word=strtok_r(NULL," ",&save))
    if (field==22) return strtoull(word,NULL,10);
  return 0;
}
static bool owned(pid_t pid,const char *root) {
  char path[64],buf[16384],needle[4096];
  if (strncmp(root,"/tmp/",5) || strlen(root)<12 || strstr(root,"/../") ||
      snprintf(needle,sizeof needle,"%s/",root)>=(int)sizeof needle) return false;
  snprintf(path,sizeof path,"/proc/%ld/cmdline",(long)pid);
  FILE *f=fopen(path,"r");if (!f) return false;
  size_t n=fread(buf,1,sizeof buf-1,f);bool truncated=!feof(f);fclose(f);
  if (!n || truncated) return false;
  buf[n]=0;
  for (size_t i=0;i<n;i++) if (!buf[i]) buf[i]=' ';
  return strstr(buf,needle)!=NULL;
}
static size_t read_target(pid_t pid,uint64_t address,unsigned char *out,size_t length) {
  size_t n=0;
  while (n<length) {
    errno=0;long word=ptrace(PTRACE_PEEKDATA,pid,(void *)(uintptr_t)(address+n),0);
    if (errno) break;
    size_t take=length-n;if (take>sizeof word) take=sizeof word;
    memcpy(out+n,&word,take);n+=take;
  }
  return n;
}
static void hex(const unsigned char *p,size_t n) {
  for (size_t i=0;i<n;i++) printf("%02x",p[i]);
}
static bool network_call(uint64_t nr) {
  return nr==SYS_socket || nr==SYS_bind || nr==SYS_sendto || nr==SYS_sendmsg;
}
static const char *call_name(uint64_t nr) {
  return nr==SYS_socket?"socket":nr==SYS_bind?"bind":nr==SYS_sendto?"sendto":"sendmsg";
}
static void failure(pid_t pid,uint64_t nr,const uint64_t args[6],int error) {
  printf("{\"event\":\"failure\",\"pid\":%ld,\"syscall\":\"%s\",\"errno\":%d,\"fd\":%"PRIu64",",
         (long)pid,call_name(nr),error,args[0]);clocks();
  if (nr==SYS_sendto || nr==SYS_bind) {
    uint64_t address=nr==SYS_sendto?args[4]:args[1];
    uint64_t length=nr==SYS_sendto?args[5]:args[2];
    unsigned char sockaddr[128];size_t n=read_target(pid,address,sockaddr,length<sizeof sockaddr?(size_t)length:sizeof sockaddr);
    printf(",\"sockaddr_hex\":\"");hex(sockaddr,n);printf("\"");
    if (n>=8 && sockaddr[0]==AF_INET && sockaddr[1]==0) {
      printf(",\"destination\":\"%u.%u.%u.%u:%u\"",sockaddr[4],sockaddr[5],sockaddr[6],sockaddr[7],((unsigned)sockaddr[2]<<8)|sockaddr[3]);
    }
  }
  if (nr==SYS_sendto) {
    unsigned char packet[4096];size_t length=args[2]<sizeof packet?(size_t)args[2]:sizeof packet;
    size_t n=read_target(pid,args[1],packet,length);
    printf(",\"send_length\":%"PRIu64",\"query_hex\":\"",args[2]);hex(packet,n);printf("\"");
  }
  printf("}\n");fflush(stdout);
}
int main(int argc,char **argv) {
  if (argc!=4) { fputs("usage: observer TEST_PID /tmp/EXCLUSIVE_ROOT SECONDS\n",stderr);return 2; }
  char *end;long parsed=strtol(argv[1],&end,10);
  if (*end || parsed<=1 || parsed>2147483647L) return 2;
  pid_t pid=(pid_t)parsed;long seconds=strtol(argv[3],&end,10);
  if (*end || seconds<1 || seconds>300 || !owned(pid,argv[2])) { fputs("refused: invalid duration or target cmdline outside exclusive /tmp root\n",stderr);return 2; }
  uint64_t initial=starttime(pid);if (!initial) return 2;
  if (ptrace(PTRACE_SEIZE,pid,0,(void *)(uintptr_t)PTRACE_O_TRACESYSGOOD)) { perror("PTRACE_SEIZE");return 2; }
  int status=0;bool stopped=false;int result=0;
  if (ptrace(PTRACE_INTERRUPT,pid,0,0) || waitpid(pid,&status,__WALL)!=pid || !WIFSTOPPED(status)) { perror("initial stop");result=2;goto detach; }
  stopped=true;
  if (starttime(pid)!=initial || !owned(pid,argv[2])) { fputs("refused: target identity changed\n",stderr);result=2;goto detach; }
  struct sigaction action={0};action.sa_handler=finish;sigemptyset(&action.sa_mask);
  sigaction(SIGALRM,&action,NULL);sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);
  printf("{\"event\":\"attached\",\"pid\":%ld,\"starttime_ticks\":%"PRIu64",\"seconds\":%ld,",(long)pid,initial,seconds);clocks();printf("}\n");fflush(stdout);
  alarm((unsigned)seconds);
  uint64_t nr=0,args[6]={0},entries=0,failures=0;bool pending=false;int deliver=0;
  while (!done) {
    if (ptrace(PTRACE_SYSCALL,pid,0,(void *)(uintptr_t)deliver)) { if (errno!=ESRCH) {perror("resume");result=2;} break; }
    stopped=false;deliver=0;
    pid_t got=waitpid(pid,&status,__WALL);
    if (got<0) { if (errno==EINTR) continue;perror("wait");result=2;break; }
    if (WIFEXITED(status) || WIFSIGNALED(status)) { pid=0;break; }
    if (!WIFSTOPPED(status)) continue;
    stopped=true;
    if (WSTOPSIG(status)==(SIGTRAP|0x80)) {
      struct syscall_info info;memset(&info,0,sizeof info);
      if (ptrace(PTRACE_GET_SYSCALL_INFO,pid,(void *)sizeof info,&info)<0) {perror("syscall info");result=2;break;}
      if (info.op==1) { nr=info.data.entry.nr;memcpy(args,info.data.entry.args,sizeof args);pending=network_call(nr);if (pending) entries++; }
      else if (info.op==2 && pending) { if (info.data.exit.is_error) {failure(pid,nr,args,(int)-info.data.exit.rval);failures++;}pending=false; }
    } else if (((unsigned)status>>16)!=PTRACE_EVENT_STOP) deliver=WSTOPSIG(status);
  }
  alarm(0);
  printf("{\"event\":\"complete\",\"network_entries\":%"PRIu64",\"failures\":%"PRIu64",",entries,failures);clocks();printf("}\n");fflush(stdout);
 detach:
  if (pid && !stopped) {
    if (ptrace(PTRACE_INTERRUPT,pid,0,0)==0) {
      while (waitpid(pid,&status,__WALL)<0 && errno==EINTR) {}
      stopped=WIFSTOPPED(status);
    }
  }
  if (pid && stopped && ptrace(PTRACE_DETACH,pid,0,0)<0 && errno!=ESRCH) {perror("detach");result=2;}
  return result;
}
