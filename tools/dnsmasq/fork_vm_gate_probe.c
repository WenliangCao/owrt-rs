#define _GNU_SOURCE
/* Diagnostic only: witness the Linux CLONE_VM gate at the jailed owner boundary.
 * Build: cc -O2 -static -pthread -std=c11 -Wall -Wextra -Werror FILE -o PROBE
 * Run as root: PROBE EXISTING_EMPTY_ROOT_DIRECTORY
 * Creates only owned child processes; no network services or router config I/O.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int parked, finish;
struct result { int rc, error, uid, gid, proc_absent; };

static void fail(const char *what) { perror(what); _exit(111); }
static void transfer(int fd, void *buffer, size_t size, int writing) {
    unsigned char *p = buffer;
    while (size) {
        ssize_t n = writing ? write(fd, p, size) : read(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail(writing ? "write" : "read/EOF");
        p += n; size -= (size_t)n;
    }
}
static void *second_thread(void *unused) {
    (void)unused;
    if (pthread_mutex_lock(&mutex)) fail("thread mutex");
    parked = 1;
    if (pthread_cond_signal(&condition)) fail("thread signal");
    while (!finish) if (pthread_cond_wait(&condition, &mutex)) fail("thread wait");
    if (pthread_mutex_unlock(&mutex)) fail("thread unlock");
    return NULL;
}
static void worker(const char *root, int threaded, int ready, int release) {
    if (chroot(root) || chdir("/")) fail("chroot");
    if (prctl(PR_SET_KEEPCAPS, 1) || setgroups(0, NULL) || setresgid(453,453,453)
        || setresuid(453,453,453)) fail("credentials");
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0x3400,0x3400,0},{0,0,0}};
    if (syscall(SYS_capset, &header, caps) || prctl(PR_SET_KEEPCAPS, 0)) fail("capset");
    pthread_t thread;
    if (threaded) {
        int error = pthread_create(&thread, NULL, second_thread, NULL);
        if (error) { errno = error; fail("pthread_create"); }
        if (pthread_mutex_lock(&mutex)) fail("main mutex");
        while (!parked) if (pthread_cond_wait(&condition, &mutex)) fail("main wait");
        if (pthread_mutex_unlock(&mutex)) fail("main unlock");
    }
    char byte = 'R'; transfer(ready, &byte, 1, 1);
    transfer(release, &byte, 1, 0); if (byte != 'G') _exit(112);
    struct result r = {.uid=(int)getuid(), .gid=(int)getgid()};
    errno = 0; r.proc_absent = access("/proc", F_OK) == -1 && errno == ENOENT;
    errno = 0; r.rc = unshare(CLONE_VM); r.error = errno;
    transfer(ready, &r, sizeof(r), 1);
    if (threaded) {
        if (pthread_mutex_lock(&mutex)) fail("finish mutex");
        finish = 1;
        if (pthread_cond_signal(&condition) || pthread_mutex_unlock(&mutex)) fail("finish signal");
        if (pthread_join(thread, NULL)) fail("pthread_join");
    }
    _exit(0);
}
static int witness(const char *root, int threaded) {
    int ready[2], release[2];
    if (pipe2(ready, O_CLOEXEC) || pipe2(release, O_CLOEXEC)) fail("pipe2");
    pid_t pid = fork(); if (pid < 0) fail("fork");
    if (!pid) {
        close(ready[0]); close(release[1]); worker(root, threaded, ready[1], release[0]);
    }
    close(ready[1]); close(release[0]);
    char byte; transfer(ready[0], &byte, 1, 0); if (byte != 'R') fail("ready");
    char path[128], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/task", (long)pid);
    DIR *tasks = opendir(path); if (!tasks) fail("task directory");
    unsigned count = 0; struct dirent *entry;
    while ((entry = readdir(tasks))) if (entry->d_name[0] != '.') ++count;
    closedir(tasks);
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    FILE *status = fopen(path, "r"); if (!status) fail("status");
    unsigned uid[4]={0}, gid[4]={0}, seccomp=99, nnp=99, threads=0;
    unsigned long long effective=0, permitted=0, inheritable=1, ambient=1;
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line,"Uid:",4)) (void)sscanf(line+4,"%u %u %u %u",uid,uid+1,uid+2,uid+3);
        if (!strncmp(line,"Gid:",4)) (void)sscanf(line+4,"%u %u %u %u",gid,gid+1,gid+2,gid+3);
        if (!strncmp(line,"Threads:",8)) (void)sscanf(line+8,"%u",&threads);
        if (!strncmp(line,"Seccomp:",8)) (void)sscanf(line+8,"%u",&seccomp);
        if (!strncmp(line,"NoNewPrivs:",11)) (void)sscanf(line+11,"%u",&nnp);
        if (!strncmp(line,"CapEff:",7)) (void)sscanf(line+7,"%llx",&effective);
        if (!strncmp(line,"CapPrm:",7)) (void)sscanf(line+7,"%llx",&permitted);
        if (!strncmp(line,"CapInh:",7)) (void)sscanf(line+7,"%llx",&inheritable);
        if (!strncmp(line,"CapAmb:",7)) (void)sscanf(line+7,"%llx",&ambient);
    }
    fclose(status);
    snprintf(path, sizeof(path), "/proc/%ld/root/proc", (long)pid);
    struct stat statbuf; errno = 0;
    int outside_absent = stat(path, &statbuf) == -1 && errno == ENOENT;
    byte = 'G'; transfer(release[1], &byte, 1, 1); close(release[1]);
    struct result r; transfer(ready[0], &r, sizeof(r), 0); close(ready[0]);
    int exit_status; if (waitpid(pid, &exit_status, 0) != pid) fail("waitpid");
    int ok = count == (unsigned)(threaded+1) && threads == count && r.uid == 453 && r.gid == 453
        && seccomp == 0 && nnp == 0 && effective == 0x3400 && permitted == 0x3400
        && inheritable == 0 && ambient == 0 && r.proc_absent && outside_absent
        && WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0
        && (threaded ? r.rc == -1 && r.error != 0 : r.rc == 0);
    for (unsigned i=0;i<4;++i) if (uid[i]!=453 || gid[i]!=453) ok=0;
    printf("{\"mode\":\"%s\",\"pid\":%ld,\"task_count\":%u,\"status_threads\":%u,"
        "\"uid\":%d,\"gid\":%d,\"cap_eff\":%llu,\"cap_prm\":%llu,\"seccomp\":%u,\"nnp\":%u,"
        "\"inside_proc_absent\":%d,\"outside_proc_absent\":%d,\"unshare_rc\":%d,\"errno\":%d,\"passed\":%d}\n",
        threaded?"two-threads":"single-thread",(long)pid,count,threads,r.uid,r.gid,effective,permitted,seccomp,nnp,
        r.proc_absent,outside_absent,r.rc,r.error,ok);
    fflush(stdout); return ok;
}
int main(int argc, char **argv) {
    if (argc!=2 || geteuid()!=0 || !strcmp(argv[1],"/")) {
        fputs("usage (root): fork_vm_gate_probe EMPTY_ROOT_DIRECTORY\n",stderr); return 2;
    }
    struct utsname kernel; if (uname(&kernel)) fail("uname");
    printf("{\"kernel\":\"%s\",\"machine\":\"%s\",\"clone_vm\":%u}\n",kernel.release,kernel.machine,CLONE_VM);
    int single=witness(argv[1],0), multiple=witness(argv[1],1);
    return single && multiple ? 0 : 1;
}
