/* Fixed self-exec startup supplement derived from device_perf_lifecycle.c.
 * Usage: device_selfexec_lifecycle helper|resolver ELF EMPTY_TMP_DIRECTORY absent|present NOFILE_SOFT NOFILE_HARD
 * Ten starts, 500 ms period; first readiness observation has a 1 ms polling
 * floor plus scheduling delay. Never use these latencies for sub-ms ranking.
 * Run in a private network namespace (host /proc/1 retained), loopback only.
 * This observer creates a private mount namespace; each target gets another
 * mount namespace, PID namespace and minimal chroot, root exec -> UID453.
 * Helper uses absent proc; K/resolver requires present proc, explicitly.
 * Resolver needs independently supervised m6a_upstream on 127.0.0.1:15354.
 * It queries a hostname servers-file route, never the owner's local marker.
 * Helper loads one lease and waits for its real old callback AND local DNS.
 * The subreaper waits for every own descendant before RUSAGE_CHILDREN ends.
 * Whole CPU covers clone/setup, startup, readiness probes, observation and shutdown;
 * the child's exact pre-exec RUSAGE_SELF baseline separately identifies setup.
 * Timed CPU subtracts only this measured baseline, never an estimated wrapper.
 * Ready latency starts at the child's post-handshake pre-exec timestamp.
 * it excludes this observer and the external upstream. Reap counts describe
 * this supervisor's waits, not children already reaped inside the daemon.
 * Resource rows are non-atomic post-ready RSS/Anon/FD snapshots, NOT peaks,
 * PSS or USS. Resolver's snapshot is owner-only after worker reaping.
 * FD pressure and a held resolver-child resource fixture are NOT implemented.
 * Only fresh private namespaces and task-root mounts are changed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NS UINT64_C(1000000000)
#define PERIOD_NS (NS / 2)
#define REPEATS 10
#define MAX_CHILDREN 32
#define PORT 53
static const char fixed_hosts[] = "127.0.0.1 localhost selfexec-resolver.test\n";
static const char callback_text[] = "old 02:00:00:de:00:01 127.0.0.10 startup\n";
static char directory[PATH_MAX], config[PATH_MAX], callback[PATH_MAX], jail[PATH_MAX];
static bool proc_present;
static volatile sig_atomic_t stopped;
static pid_t owner = -1;
static unsigned iteration;

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) { perror("clock_gettime"); exit(2); }
    return (uint64_t)value.tv_sec * NS + (uint64_t)value.tv_nsec;
}
static void interrupted(int sig) { (void)sig; stopped = 1; }
static void delay_ns(uint64_t duration) {
    struct timespec value = {(time_t)(duration / NS), (long)(duration % NS)};
    while (nanosleep(&value, &value) && errno == EINTR) {}
}
static bool path(char *output, const char *suffix) {
    return snprintf(output, PATH_MAX, "%s/%s", directory, suffix) < PATH_MAX;
}
static bool different_namespace(const char *name) {
    char ours[64], init[64]; struct stat left, right;
    snprintf(ours, sizeof ours, "/proc/self/ns/%s", name);
    snprintf(init, sizeof init, "/proc/1/ns/%s", name);
    return !stat(ours, &left) && !stat(init, &right) &&
           (left.st_dev != right.st_dev || left.st_ino != right.st_ino);
}
static bool isolated(void) {
    if (!different_namespace("net")) return false;
    struct if_nameindex *list = if_nameindex();
    if (!list) return false;
    unsigned count = 0; bool ok = true;
    for (struct if_nameindex *item = list; item->if_index; ++item) {
        ++count; if (strcmp(item->if_name, "lo")) ok = false;
    }
    if_freenameindex(list);
    return ok && count == 1;
}
static bool empty_directory(const char *name) {
    DIR *folder = opendir(name);
    if (!folder) return false;
    bool empty = true; struct dirent *entry;
    while ((entry = readdir(folder)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) empty = false;
    closedir(folder); return empty;
}
static int callback_count(bool final) {
    char bytes[4096]; FILE *file = fopen(callback, "r");
    if (!file) return errno == ENOENT ? 0 : -1;
    size_t length = fread(bytes, 1, sizeof bytes, file);
    bool ok = !ferror(file) && feof(file); fclose(file);
    if (!ok) return -1;
    size_t line = strlen(callback_text), complete = length / line, partial = length % line;
    for (size_t i = 0; i < complete; ++i)
        if (memcmp(bytes + i * line, callback_text, line)) return -1;
    if (partial && (final || memcmp(bytes + complete * line, callback_text, partial))) return -1;
    return (int)complete;
}
static bool finish_file(FILE *file) {
    bool ok = !ferror(file);
    return fclose(file) == 0 && ok;
}
static bool prepare(bool helper) {
    char name[PATH_MAX];
    if (!path(jail, "rootfs") || mkdir(jail, 0755)) return false;
    const char *folders[] = {"rootfs/bin", "rootfs/lib", "rootfs/lib64", "rootfs/usr",
        "rootfs/usr/sbin", "rootfs/etc", "rootfs/dev", "rootfs/fixture"};
    for (unsigned i = 0; i < sizeof folders / sizeof folders[0]; ++i)
        if (!path(name, folders[i]) || mkdir(name, 0755)) return false;
    if (proc_present && (!path(name, "rootfs/proc") || mkdir(name, 0755))) return false;
    if (!path(name, "rootfs/fixture") || chown(name, 453, 453)) return false;
    const char *mounts[] = {"rootfs/bin/sh", "rootfs/usr/sbin/dnsmasq", "rootfs/dev/null",
        "rootfs/dev/zero", "rootfs/dev/random", "rootfs/dev/urandom"};
    for (unsigned i = 0; i < sizeof mounts / sizeof mounts[0]; ++i) {
        if (!path(name, mounts[i])) return false;
        int fd = open(name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0755);
        if (fd < 0) return false;
        close(fd);
    }
    const char *etc[][2] = {
        {"rootfs/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nfixture453:x:453:453:fixture:/:/bin/false\n"},
        {"rootfs/etc/group", "root:x:0:\nfixture453:x:453:\n"},
        {"rootfs/etc/hosts", fixed_hosts},
        {"rootfs/etc/resolv.conf", "nameserver 127.0.0.2\noptions timeout:1 attempts:1\n"},
    };
    for (unsigned i = 0; i < sizeof etc / sizeof etc[0]; ++i) {
        if (!path(name, etc[i][0])) return false;
        FILE *out = fopen(name, "wx"); if (!out) return false;
        fputs(etc[i][1], out); if (!finish_file(out)) return false;
    }
    if (!path(config, "rootfs/fixture/config") || !path(callback, "rootfs/fixture/callback")) return false;
    FILE *file = fopen(config, "wx");
    if (!file) return false;
    fprintf(file, "no-hosts\nno-resolv\nno-poll\nuser=fixture453\ngroup=fixture453\n"
                  "interface=lo\nbind-dynamic\nlisten-address=127.0.0.1\n"
                  "port=%u\ncache-size=0\ndns-forward-max=16\n"
                  "pid-file=/fixture/pid\nlog-facility=/fixture/daemon.log\n"
                  "dhcp-authoritative\ndhcp-lease-max=1\n"
                  "dhcp-range=127.0.0.10,127.0.0.10,255.0.0.0,127.255.255.255,12h\n"
                  "dhcp-leasefile=/fixture/leases\n", PORT);
    if (helper)
        fputs("host-record=ready.selfexec.test,192.0.2.1\ndhcp-script=/fixture/script\n", file);
    else fputs("servers-file=/fixture/servers\n", file);
    if (!finish_file(file)) return false;
    if (!helper) {
        if (!path(name, "rootfs/fixture/servers") || !(file = fopen(name, "wx"))) return false;
        fputs("server=/selfexec-upstream.test/selfexec-resolver.test#15354\n", file);
        if (!finish_file(file)) return false;
    }
    if (!path(name, "rootfs/fixture/leases") || !(file = fopen(name, "wx"))) return false;
    fprintf(file, "%lld 02:00:00:de:00:01 127.0.0.10 startup *\n", (long long)time(NULL) + 43200);
    if (!finish_file(file) || chown(name, 453, 453)) return false;
    if (!helper) return true;
    if (!path(name, "rootfs/fixture/script") || !(file = fopen(name, "wx"))) return false;
    fprintf(file, "#!/bin/sh\n"
                  "[ \"$#\" -eq 4 ] && [ \"$1\" = old ] && "
                  "[ \"$2\" = 02:00:00:de:00:01 ] && [ \"$3\" = 127.0.0.10 ] && "
                  "[ \"$4\" = startup ] || exit 64\n"
                  "printf '%%s %%s %%s %%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >> /fixture/callback\n");
    return finish_file(file) && chmod(name, 0755) == 0;
}
struct entry { uint64_t start_ns; struct rusage usage; };
struct launch_args { const char *binary; int report[2], release[2]; };
static bool transfer(int fd, void *bytes, size_t length, bool writing) {
    unsigned char *at = bytes;
    while (length) {
        ssize_t count = writing ? write(fd, at, length) : read(fd, at, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        at += count; length -= (size_t)count;
    }
    return true;
}
static bool bind_into(const char *source, const char *suffix, bool readonly) {
    char name[PATH_MAX];
    if (!path(name, suffix) || mount(source, name, NULL, MS_BIND, NULL)) return false;
    return !readonly || !mount(NULL, name, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
}
static int target_entry(void *opaque) {
    struct launch_args *args = opaque;
    close(args->report[0]); close(args->release[1]);
    char name[PATH_MAX];
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        !bind_into(args->binary, "rootfs/usr/sbin/dnsmasq", true) ||
        !bind_into("/bin/sh", "rootfs/bin/sh", true) ||
        !bind_into("/lib", "rootfs/lib", true) ||
        !bind_into("/dev/null", "rootfs/dev/null", false) ||
        !bind_into("/dev/zero", "rootfs/dev/zero", false) ||
        !bind_into("/dev/random", "rootfs/dev/random", false) ||
        !bind_into("/dev/urandom", "rootfs/dev/urandom", false)) _exit(126);
    if (access("/lib64", F_OK) == 0 && !bind_into("/lib64", "rootfs/lib64", true)) _exit(126);
    if (proc_present && (!path(name, "rootfs/proc") ||
        mount("proc", name, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))) _exit(126);
    if (!path(name, "stderr.log")) _exit(126);
    int fd = open(name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(126);
    if (fd > 2) close(fd);
    if (chroot(jail) || chdir("/")) _exit(126);
    char marker = 'R';
    if (!transfer(args->report[1], &marker, 1, true) ||
        !transfer(args->release[0], &marker, 1, false) || marker != 'G') _exit(126);
    close(args->release[0]);
    struct entry entry = {0};
    if (getrusage(RUSAGE_SELF, &entry.usage)) _exit(126);
    entry.start_ns = now_ns();
    if (!transfer(args->report[1], &entry, sizeof entry, true)) _exit(126);
    close(args->report[1]);
    execl("/usr/sbin/dnsmasq", "/usr/sbin/dnsmasq", "--keep-in-foreground", "--conf-file=/fixture/config", (char *)NULL);
    _exit(127);
}
static bool launch(const char *binary, uint64_t schedule, struct entry *entry) {
    struct launch_args args = {.binary = binary, .report = {-1, -1}, .release = {-1, -1}};
    if (pipe2(args.report, O_CLOEXEC) || pipe2(args.release, O_CLOEXEC)) goto failed;
    size_t size = 128 * 1024;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) goto failed;
    owner = clone(target_entry, (char *)stack + size, CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, &args);
    munmap(stack, size);
    close(args.report[1]); args.report[1] = -1;
    close(args.release[0]); args.release[0] = -1;
    struct pollfd item = {.fd = args.report[0], .events = POLLIN};
    char marker = 0;
    if (owner < 0 || poll(&item, 1, 3000) <= 0 ||
        !transfer(args.report[0], &marker, 1, false) || marker != 'R') goto failed;
    uint64_t current = now_ns();
    if (schedule > current) delay_ns(schedule - current);
    marker = 'G';
    if (stopped || !transfer(args.release[1], &marker, 1, true) ||
        poll(&item, 1, 3000) <= 0 || !transfer(args.report[0], entry, sizeof *entry, false)) goto failed;
    close(args.report[0]); close(args.release[1]); return true;
failed:
    for (unsigned i = 0; i < 2; ++i) {
        if (args.report[i] >= 0) close(args.report[i]);
        if (args.release[i] >= 0) close(args.release[i]);
    }
    return false;
}
static int children(pid_t pid, pid_t output[MAX_CHILDREN]) {
    char name[128]; snprintf(name, sizeof name, "/proc/%ld/task/%ld/children", (long)pid, (long)pid);
    FILE *file = fopen(name, "r");
    if (!file) return -1;
    int count = 0, scanned; long child;
    while ((scanned = fscanf(file, "%ld", &child)) == 1) {
        if (count == MAX_CHILDREN || child <= 0 || child > INT_MAX) { fclose(file); return -1; }
        output[count++] = (pid_t)child;
    }
    bool ok = scanned == EOF && !ferror(file);
    fclose(file); return ok ? count : -1;
}
struct cleanup { unsigned reaped, bad_exits; bool forced, complete, owner_reaped; int owner_status; };
static struct cleanup cleanup(void) {
    struct cleanup result = {.owner_status = -1};
    if (owner > 0) kill(owner, SIGTERM); /* Own unreaped child, never a reused PID. */
    uint64_t deadline = now_ns() + 2 * NS;
    for (;;) {
        int status; pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            ++result.reaped;
            if (!WIFEXITED(status) || WEXITSTATUS(status)) ++result.bad_exits;
            if (pid == owner) { result.owner_reaped = true; result.owner_status = status; }
            printf("{\"kind\":\"reap\",\"index\":%u,\"pid\":%ld,\"owner\":%s,\"wait_status\":%d}\n",
                   iteration, (long)pid, pid == owner ? "true" : "false", status);
        }
        if (pid < 0 && errno == ECHILD) { result.complete = true; break; }
        if (pid < 0 && errno != EINTR) break;
        if (now_ns() >= deadline) {
            if (result.forced) break;
            result.forced = true; deadline = now_ns() + 2 * NS;
        }
        if (result.forced) {
            pid_t direct[MAX_CHILDREN]; int count = children(getpid(), direct);
            if (count < 0) break;
            /* Only unreaped direct/adopted children; no wait occurs between
             * this inventory and signals, so their PIDs cannot be reused. */
            for (int i = 0; i < count; ++i) kill(direct[i], SIGKILL);
        }
        delay_ns(1000000);
    }
    owner = -1; return result;
}
static unsigned read16(const unsigned char *p) { return p[0] * 256U + p[1]; }
static size_t skip_name(const unsigned char *p, size_t length, size_t offset) {
    unsigned steps = 0;
    while (offset < length && ++steps < 128) {
        unsigned label = p[offset++];
        if (!label) return offset;
        if ((label & 0xc0) == 0xc0) return offset < length ? offset + 1 : 0;
        if (label > 63 || offset + label > length) return 0;
        offset += label;
    }
    return 0;
}
static bool reply_correct(const unsigned char *reply, size_t length, const unsigned char *query, size_t size) {
    if (length < size || read16(reply) != read16(query) || (read16(reply + 2) & 0x820f) != 0x8000 ||
        read16(reply + 4) != 1 || read16(reply + 6) != 1 || read16(reply + 8) || read16(reply + 10) ||
        memcmp(reply + 12, query + 12, size - 12)) return false;
    size_t offset = skip_name(reply, length, size);
    return offset && offset + 14 == length && read16(reply + offset) == 1 &&
           read16(reply + offset + 2) == 1 && read16(reply + offset + 8) == 4 &&
           !memcmp(reply + offset + 10, "\300\000\002\001", 4);
}
struct readiness { uint64_t dns, callback, ready; unsigned attempts; };
static struct readiness wait_ready(bool helper) {
    struct readiness result = {0};
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return result;
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&target, sizeof target)) { close(fd); return result; }
    char name[128];
    snprintf(name, sizeof name, helper ? "ready.selfexec.test" : "ready-%02u.selfexec-upstream.test", iteration);
    unsigned char query[256] = {0}, reply[512];
    query[0] = 0x51; query[1] = (unsigned char)iteration; query[2] = 1; query[5] = 1;
    size_t size = 12;
    for (char *label = name, *next; label; label = next) {
        next = strchr(label, '.'); if (next) *next++ = 0;
        size_t length = strlen(label); query[size++] = (unsigned char)length;
        memcpy(query + size, label, length); size += length;
    }
    query[size++] = 0; query[size++] = 0; query[size++] = 1; query[size++] = 0; query[size++] = 1;
    uint64_t deadline = now_ns() + 3 * NS;
    while (!stopped && now_ns() < deadline) {
        uint64_t turn = now_ns();
        if (helper && !result.callback) {
            int callbacks = callback_count(false);
            if (callbacks < 0) break;
            if (callbacks > 0) result.callback = now_ns();
        }
        if (!result.dns) {
            ++result.attempts;
            if (send(fd, query, size, 0) < 0 && errno != ECONNREFUSED && errno != EINTR) break;
            struct pollfd item = {.fd = fd, .events = POLLIN};
            if (poll(&item, 1, 1) > 0) {
                ssize_t length = recv(fd, reply, sizeof reply, MSG_DONTWAIT);
                if (length > 0 && reply_correct(reply, (size_t)length, query, size)) result.dns = now_ns();
            }
        }
        if (result.dns && (!helper || result.callback)) { result.ready = now_ns(); break; }
        uint64_t elapsed = now_ns() - turn;
        if (elapsed < 1000000) delay_ns(1000000 - elapsed);
    }
    close(fd); return result;
}
struct resources { pid_t pid, ppid; uint64_t start, capabilities; unsigned rss, anon, fds, threads, uid, gid; };
static bool identity(pid_t pid, struct resources *value) {
    char name[128], line[8192]; snprintf(name, sizeof name, "/proc/%ld/stat", (long)pid);
    FILE *file = fopen(name, "r"); if (!file) return false;
    char *read = fgets(line, sizeof line, file); fclose(file);
    char *tail = read ? strrchr(line, ')') : NULL; if (!tail) return false;
    char *save = NULL, *token = strtok_r(tail + 2, " ", &save);
    if (!token || *token == 'Z') return false;
    value->pid = pid;
    for (unsigned field = 3; token; ++field, token = strtok_r(NULL, " ", &save)) {
        if (field == 4) value->ppid = (pid_t)strtol(token, NULL, 10);
        if (field == 22) { value->start = strtoull(token, NULL, 10); return true; }
    }
    return false;
}
static bool resource_snapshot(pid_t pid, struct resources *value) {
    if (!identity(pid, value)) return false;
    char name[128], line[512]; snprintf(name, sizeof name, "/proc/%ld/status", (long)pid);
    FILE *file = fopen(name, "r"); if (!file) return false;
    unsigned fields = 0;
    while (fgets(line, sizeof line, file)) {
        if (sscanf(line, "VmRSS: %u", &value->rss) == 1) fields |= 1;
        if (sscanf(line, "RssAnon: %u", &value->anon) == 1) fields |= 2;
        if (sscanf(line, "Threads: %u", &value->threads) == 1) fields |= 4;
        if (sscanf(line, "Uid: %u", &value->uid) == 1) fields |= 8;
        if (sscanf(line, "Gid: %u", &value->gid) == 1) fields |= 16;
        if (sscanf(line, "CapEff: %" SCNx64, &value->capabilities) == 1) fields |= 32;
    }
    bool ok = !ferror(file); fclose(file);
    snprintf(name, sizeof name, "/proc/%ld/fd", (long)pid);
    DIR *folder = opendir(name); if (!folder) return false;
    value->fds = 0; struct dirent *entry;
    while ((entry = readdir(folder))) if (entry->d_name[0] != '.') ++value->fds;
    closedir(folder);
    struct resources after = {0};
    return ok && fields == 63 && value->threads == 1 && identity(pid, &after) &&
           after.start == value->start && after.ppid == value->ppid;
}
static bool owner_boundary(const struct resources *value) {
    char name[128]; struct stat target, observer;
    if (value->uid != 453 || value->gid != 453 || value->capabilities != 0x3400) return false;
    snprintf(name, sizeof name, "/proc/%ld/root/proc", (long)owner);
    if ((access(name, F_OK) == 0) != proc_present) return false;
    const char *spaces[] = {"mnt", "pid"};
    for (unsigned i = 0; i < 2; ++i) {
        snprintf(name, sizeof name, "/proc/%ld/ns/%s", (long)owner, spaces[i]);
        if (stat(name, &target)) return false;
        snprintf(name, sizeof name, "/proc/self/ns/%s", spaces[i]);
        if (stat(name, &observer) || (target.st_dev == observer.st_dev && target.st_ino == observer.st_ino)) return false;
    }
    return true;
}
static bool dump_fds(const struct resources *value, const char *label) {
    char source[128], output[PATH_MAX], bytes[4096], suffix[64];
    snprintf(suffix, sizeof suffix, "%s-fds.raw", label);
    if (!path(output, suffix)) return false;
    FILE *out = fopen(output, "wx"); if (!out) return false;
    snprintf(source, sizeof source, "/proc/%ld/fd", (long)value->pid);
    DIR *folder = opendir(source); if (!folder) { fclose(out); return false; }
    unsigned count = 0; bool ok = true; struct dirent *entry;
    while ((entry = readdir(folder))) {
        if (entry->d_name[0] == '.') continue;
        char *end; long fd = strtol(entry->d_name, &end, 10);
        if (*end || fd < 0 || fd > INT_MAX) { ok = false; break; }
        snprintf(source, sizeof source, "/proc/%ld/fd/%ld", (long)value->pid, fd);
        ssize_t length = readlink(source, bytes, sizeof bytes - 1);
        if (length < 0 || length == (ssize_t)sizeof bytes - 1) { ok = false; break; }
        bytes[length] = 0; fprintf(out, "fd=%ld target=%s\n", fd, bytes);
        snprintf(source, sizeof source, "/proc/%ld/fdinfo/%ld", (long)value->pid, fd);
        FILE *info = fopen(source, "r"); if (!info) { ok = false; break; }
        size_t size;
        while ((size = fread(bytes, 1, sizeof bytes, info)))
            if (fwrite(bytes, 1, size, out) != size) ok = false;
        if (ferror(info)) ok = false;
        fclose(info); ++count;
    }
    closedir(folder);
    struct resources after = {0};
    return finish_file(out) && ok && count == value->fds && identity(value->pid, &after) && after.start == value->start;
}
static bool quiet_snapshot(bool helper, struct resources value[2]) {
    uint64_t deadline = now_ns() + NS / 5;
    do {
        pid_t direct[MAX_CHILDREN], nested[MAX_CHILDREN], after[MAX_CHILDREN];
        int count = children(owner, direct), wanted = helper ? 1 : 0;
        if (count == wanted && resource_snapshot(owner, &value[0]) && owner_boundary(&value[0]) &&
            (!helper || (children(direct[0], nested) == 0 && resource_snapshot(direct[0], &value[1]) &&
                         value[1].ppid == owner)) && children(owner, after) == wanted &&
            (!helper || after[0] == direct[0])) return true;
        delay_ns(1000000);
    } while (!stopped && now_ns() < deadline);
    return false;
}
static void emit_resource(const struct resources *value) {
    printf("{\"pid\":%ld,\"ppid\":%ld,\"starttime_ticks\":%" PRIu64 ",\"rss_kib\":%u,"
           "\"anon_kib\":%u,\"fd_count\":%u,\"threads\":%u,\"uid\":%u,\"gid\":%u,\"cap_eff\":%" PRIu64 "}",
           (long)value->pid, (long)value->ppid, value->start, value->rss, value->anon, value->fds, value->threads,
           value->uid, value->gid, value->capabilities);
}
static uint64_t usec(struct timeval value) { return (uint64_t)value.tv_sec * 1000000 + (uint64_t)value.tv_usec; }
int main(int argc, char **argv) {
    if (argc != 7 || (strcmp(argv[1], "helper") && strcmp(argv[1], "resolver")) ||
        (strcmp(argv[4], "absent") && strcmp(argv[4], "present"))) {
        fputs("usage: device_selfexec_lifecycle helper|resolver ELF EMPTY_TMP_DIRECTORY absent|present NOFILE_SOFT NOFILE_HARD\n", stderr); return 2;
    }
    proc_present = !strcmp(argv[4], "present");
    char *limit_end; errno = 0; unsigned long limit = strtoul(argv[5], &limit_end, 10);
    struct rlimit nofile;
    if (errno || *limit_end || limit < 32 || limit > 1048576 || getrlimit(RLIMIT_NOFILE, &nofile) || limit > nofile.rlim_max) {
        fputs("invalid explicit NOFILE soft limit\n", stderr); return 2;
    }
    errno = 0; unsigned long hard = strtoul(argv[6], &limit_end, 10);
    if (errno || *limit_end || hard < limit || hard > nofile.rlim_max) {
        fputs("invalid explicit NOFILE hard limit\n", stderr); return 2;
    }
    nofile.rlim_cur = limit;
    nofile.rlim_max = hard;
    bool helper = !strcmp(argv[1], "helper"); char root[PATH_MAX], binary[PATH_MAX];
    if (!realpath(argv[3], root) || strncmp(root, "/tmp/", 5) || !empty_directory(root) ||
        !realpath(argv[2], binary) || !isolated() || geteuid() != 0) {
        fputs("requires fresh /tmp directory, root and private loopback-only network namespace\n", stderr); return 2;
    }
    if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) || setrlimit(RLIMIT_NOFILE, &nofile)) {
        perror("private mount namespace or NOFILE setup"); return 2;
    }
    /* NSS/servers files must remain readable after the target drops to453,
     * independently of the invoking shell's private-output umask. */
    umask(022);
    for (const unsigned char *at = (const unsigned char *)root; *at; ++at)
        if (!isalnum(*at) && !strchr("/._-", *at)) { fputs("unsafe fixture path\n", stderr); return 2; }
    pid_t existing[MAX_CHILDREN];
    if (children(getpid(), existing) != 0 || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) {
        fputs("requires child-free supervisor and working subreaper\n", stderr); return 2;
    }
    signal(SIGTERM, interrupted); signal(SIGINT, interrupted); signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct rusage initial, final;
    if (getrusage(RUSAGE_CHILDREN, &initial)) { perror("getrusage"); return 2; }
    bool ok = true; unsigned completed = 0; uint64_t schedule = 0, timed_user = 0, timed_system = 0;
    for (iteration = 0; iteration < REPEATS && !stopped; ++iteration) {
        if (snprintf(directory, sizeof directory, "%s/run-%02u", root, iteration) >= (int)sizeof directory ||
            mkdir(directory, 0700) || !prepare(helper)) { perror("prepare fixture"); ok = false; break; }
        if (stopped) { ok = false; break; }
        struct rusage before, after;
        if (getrusage(RUSAGE_CHILDREN, &before)) { ok = false; break; }
        struct entry entry = {0};
        bool launched = launch(binary, schedule, &entry);
        uint64_t start = launched ? entry.start_ns : now_ns(); if (!schedule) schedule = start;
        uint64_t lag = start > schedule ? start - schedule : 0;
        struct readiness ready = launched ? wait_ready(helper) : (struct readiness){0};
        struct resources resources[2] = {{0}, {0}};
        bool snapshot = ready.ready && quiet_snapshot(helper, resources) && dump_fds(&resources[0], "owner") &&
                        (!helper || dump_fds(&resources[1], "helper"));
        uint64_t snapshot_at = snapshot ? now_ns() : 0;
        struct cleanup closed = cleanup();
        bool cpu = !getrusage(RUSAGE_CHILDREN, &after) && closed.complete;
        uint64_t user = cpu ? usec(after.ru_utime) - usec(before.ru_utime) : 0;
        uint64_t system = cpu ? usec(after.ru_stime) - usec(before.ru_stime) : 0;
        uint64_t setup_user = usec(entry.usage.ru_utime), setup_system = usec(entry.usage.ru_stime);
        cpu = cpu && launched && user >= setup_user && system >= setup_system;
        if (cpu) { timed_user += user - setup_user; timed_system += system - setup_system; }
        int callbacks = helper ? callback_count(true) : 0;
        bool callback_ok = !helper || callbacks > 0;
        uint64_t finished = now_ns(), next = schedule + PERIOD_NS;
        bool passed = launched && ready.ready && snapshot && callback_ok && cpu && closed.owner_reaped &&
                      !closed.forced && !closed.bad_exits && !stopped && finished <= next;
        printf("{\"kind\":\"startup\",\"mode\":\"%s\",\"index\":%u,\"ok\":%s,"
               "\"start_ns\":%" PRIu64 ",\"start_lag_ns\":%" PRIu64 ",\"dns_ready_ns\":%" PRIu64 ","
               "\"callback_ready_ns\":%" PRIu64 ",\"ready_ns\":%" PRIu64 ",\"latency_ns\":%" PRIu64 ","
               "\"probe_attempts\":%u,\"callback_valid\":%s,\"callback_count\":%d,\"callback_exact_once\":%s,"
               "\"snapshot_ns\":%" PRIu64 ",\"resources\":[",
               argv[1], iteration, passed ? "true" : "false", start, lag, ready.dns, ready.callback,
               ready.ready, ready.ready ? ready.ready - start : 0, ready.attempts,
               helper ? (callback_ok ? "true" : "false") : "null", callbacks,
               helper ? (callbacks == 1 ? "true" : "false") : "null", snapshot_at);
        if (snapshot) { emit_resource(&resources[0]); if (helper) { putchar(','); emit_resource(&resources[1]); } }
        printf("],\"proc_mode\":\"%s\",\"nofile_soft\":%lu,\"nofile_hard\":%" PRIu64 ","
               "\"setup_user_usec\":%" PRIu64 ",\"setup_system_usec\":%" PRIu64 ","
               "\"timed_tree_user_usec\":%" PRIu64 ",\"timed_tree_system_usec\":%" PRIu64 ","
               "\"snapshot_scope\":\"%s\",\"cpu_complete\":%s,\"children_user_usec\":%" PRIu64 ","
               "\"children_system_usec\":%" PRIu64 ",\"cpu_scope\":\"whole_start_through_all_owned_reaps\","
               "\"supervisor_reaped\":%u,\"owner_reaped\":%s,\"owner_wait_status\":%d,\"bad_exits\":%u,"
               "\"forced_cleanup\":%s,\"all_children_reaped\":%s,\"finished_ns\":%" PRIu64 ",\"period_overrun_ns\":%" PRIu64 "}\n",
               argv[4], limit, (uint64_t)nofile.rlim_max, setup_user, setup_system,
               cpu ? user - setup_user : 0, cpu ? system - setup_system : 0,
               helper ? "post_ready_owner_and_idle_helper_non_atomic" : "post_ready_owner_after_resolver_reap",
               cpu ? "true" : "false", user, system, closed.reaped,
               closed.owner_reaped ? "true" : "false", closed.owner_status, closed.bad_exits,
               closed.forced ? "true" : "false", closed.complete ? "true" : "false", finished,
               finished > next ? finished - next : 0);
        if (!passed || finished > next) { ok = false; break; }
        ++completed; schedule = next;
    }
    bool cpu_complete = children(getpid(), existing) == 0 && !getrusage(RUSAGE_CHILDREN, &final);
    printf("{\"kind\":\"summary\",\"mode\":\"%s\",\"expected_starts\":%u,\"completed\":%u,\"period_ms\":500,"
           "\"poll_floor_us\":1000,\"ok\":%s,\"cpu_complete\":%s,\"children_user_usec\":%" PRIu64 ","
           "\"children_system_usec\":%" PRIu64 ",\"timed_tree_user_usec\":%" PRIu64 ","
           "\"timed_tree_system_usec\":%" PRIu64 ",\"rusage_unit_us\":1,\"proc_mode\":\"%s\","
           "\"nofile_soft\":%lu,\"nofile_hard\":%lu}\n", argv[1], REPEATS, completed,
           ok && !stopped && completed == REPEATS && cpu_complete ? "true" : "false", cpu_complete ? "true" : "false",
           cpu_complete ? usec(final.ru_utime) - usec(initial.ru_utime) : 0,
           cpu_complete ? usec(final.ru_stime) - usec(initial.ru_stime) : 0,
           timed_user, timed_system, argv[4], limit, hard);
    return ok && !stopped && completed == REPEATS && cpu_complete ? 0 : 1;
}
