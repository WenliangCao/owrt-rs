/* Fixed self-exec startup supplement derived from device_perf_lifecycle.c.
 * Usage: device_selfexec_lifecycle helper|resolver ELF EMPTY_TMP_DIRECTORY
 * Ten starts, 500 ms period; first readiness observation has a 1 ms polling
 * floor plus scheduling delay. Never use these latencies for sub-ms ranking.
 * Run in private mount/net namespaces (host /proc/1 retained), loopback only.
 * Resolver additionally requires this exact privately mounted /etc/hosts:
 *   127.0.0.1 localhost selfexec-resolver.test\n
 * and an independently supervised m6a_upstream on 127.0.0.1:15354.
 * It queries a hostname servers-file route, never the owner's local marker.
 * Helper loads one lease and waits for its real old callback AND local DNS.
 * The subreaper waits for every own descendant before RUSAGE_CHILDREN ends.
 * CPU covers startup, readiness probes, resource observation and shutdown;
 * it excludes this observer and the external upstream. Reap counts describe
 * this supervisor's waits, not children already reaped inside the daemon.
 * Resource rows are non-atomic post-ready RSS/Anon/FD snapshots, NOT peaks,
 * PSS or USS. Resolver's snapshot is owner-only after worker reaping.
 * FD pressure and a held resolver-child resource fixture are NOT implemented.
 * This tool never changes interfaces, mounts, production services or limits.
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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
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
#define PORT 15353
static const char fixed_hosts[] = "127.0.0.1 localhost selfexec-resolver.test\n";
static const char callback_text[] = "old 02:00:00:de:00:01 127.0.0.10 startup\n";
static char directory[PATH_MAX], config[PATH_MAX], callback[PATH_MAX];
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
    if (!different_namespace("net") || !different_namespace("mnt")) return false;
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
static bool exact_file(const char *name, const char *expected) {
    char bytes[256]; FILE *file = fopen(name, "r");
    if (!file) return false;
    size_t length = fread(bytes, 1, sizeof bytes, file);
    bool ok = !ferror(file) && feof(file) && length == strlen(expected) &&
              !memcmp(bytes, expected, length);
    fclose(file); return ok;
}
static bool finish_file(FILE *file) {
    bool ok = !ferror(file);
    return fclose(file) == 0 && ok;
}
static bool prepare(bool helper) {
    char name[PATH_MAX];
    if (!path(config, "config") || !path(callback, "callback")) return false;
    FILE *file = fopen(config, "wx");
    if (!file) return false;
    fprintf(file, "no-hosts\nno-resolv\nno-poll\nuser=root\ngroup=root\n"
                  "interface=lo\nbind-interfaces\nlisten-address=127.0.0.1\n"
                  "port=%u\ncache-size=0\ndns-forward-max=16\n"
                  "pid-file=%s/pid\nlog-facility=%s/daemon.log\n", PORT, directory, directory);
    if (helper)
        fprintf(file, "host-record=ready.selfexec.test,192.0.2.1\nno-ping\ndhcp-authoritative\n"
                      "dhcp-range=127.0.0.10,127.0.0.10,255.0.0.0,127.255.255.255,12h\n"
                      "dhcp-lease-max=1\ndhcp-leasefile=%s/leases\ndhcp-script=%s/script\n",
                      directory, directory);
    else fprintf(file, "servers-file=%s/servers\n", directory);
    if (!finish_file(file)) return false;
    if (!helper) {
        if (!path(name, "servers") || !(file = fopen(name, "wx"))) return false;
        fputs("server=/selfexec-upstream.test/selfexec-resolver.test#15354\n", file);
        return finish_file(file);
    }
    if (!path(name, "leases") || !(file = fopen(name, "wx"))) return false;
    fprintf(file, "%lld 02:00:00:de:00:01 127.0.0.10 startup *\n", (long long)time(NULL) + 43200);
    if (!finish_file(file) || !path(name, "script") || !(file = fopen(name, "wx"))) return false;
    fprintf(file, "#!/bin/sh\n"
                  "[ \"$#\" -eq 4 ] && [ \"$1\" = old ] && "
                  "[ \"$2\" = 02:00:00:de:00:01 ] && [ \"$3\" = 127.0.0.10 ] && "
                  "[ \"$4\" = startup ] || exit 64\n"
                  "printf '%%s %%s %%s %%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >> '%s'\n", callback);
    return finish_file(file) && chmod(name, 0700) == 0;
}
static bool launch(const char *binary) {
    owner = fork();
    if (owner < 0) return false;
    if (!owner) {
        /* Retain the external trial supervisor's emergency process group. */
        char name[PATH_MAX], option[PATH_MAX + 16];
        if (!path(name, "stderr.log")) _exit(126);
        int fd = open(name, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(126);
        if (fd > 2) close(fd);
        if (snprintf(option, sizeof option, "--conf-file=%s", config) >= (int)sizeof option) _exit(126);
        execl(binary, binary, "--keep-in-foreground", option, (char *)NULL);
        _exit(127);
    }
    return true;
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
        if (helper && !result.callback && exact_file(callback, callback_text)) result.callback = now_ns();
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
struct resources { pid_t pid, ppid; uint64_t start; unsigned rss, anon, fds, threads; };
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
    }
    bool ok = !ferror(file); fclose(file);
    snprintf(name, sizeof name, "/proc/%ld/fd", (long)pid);
    DIR *folder = opendir(name); if (!folder) return false;
    value->fds = 0; struct dirent *entry;
    while ((entry = readdir(folder))) if (entry->d_name[0] != '.') ++value->fds;
    closedir(folder);
    struct resources after = {0};
    return ok && fields == 7 && value->threads == 1 && identity(pid, &after) &&
           after.start == value->start && after.ppid == value->ppid;
}
static bool quiet_snapshot(bool helper, struct resources value[2]) {
    uint64_t deadline = now_ns() + NS / 5;
    do {
        pid_t direct[MAX_CHILDREN], nested[MAX_CHILDREN], after[MAX_CHILDREN];
        int count = children(owner, direct), wanted = helper ? 1 : 0;
        if (count == wanted && resource_snapshot(owner, &value[0]) &&
            (!helper || (children(direct[0], nested) == 0 && resource_snapshot(direct[0], &value[1]) &&
                         value[1].ppid == owner)) && children(owner, after) == wanted &&
            (!helper || after[0] == direct[0])) return true;
        delay_ns(1000000);
    } while (!stopped && now_ns() < deadline);
    return false;
}
static void emit_resource(const struct resources *value) {
    printf("{\"pid\":%ld,\"ppid\":%ld,\"starttime_ticks\":%" PRIu64 ",\"rss_kib\":%u,"
           "\"anon_kib\":%u,\"fd_count\":%u,\"threads\":%u}",
           (long)value->pid, (long)value->ppid, value->start, value->rss, value->anon, value->fds, value->threads);
}
static uint64_t usec(struct timeval value) { return (uint64_t)value.tv_sec * 1000000 + (uint64_t)value.tv_usec; }
int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "helper") && strcmp(argv[1], "resolver"))) {
        fputs("usage: device_selfexec_lifecycle helper|resolver ELF EMPTY_TMP_DIRECTORY\n", stderr); return 2;
    }
    bool helper = !strcmp(argv[1], "helper"); char root[PATH_MAX], binary[PATH_MAX];
    if (!realpath(argv[3], root) || strncmp(root, "/tmp/", 5) || !empty_directory(root) ||
        !realpath(argv[2], binary) || !isolated() || (!helper && !exact_file("/etc/hosts", fixed_hosts))) {
        fputs("requires fresh /tmp directory, private mount/net namespaces, loopback only and fixed resolver hosts\n", stderr); return 2;
    }
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
    bool ok = true; unsigned completed = 0; uint64_t schedule = 0;
    for (iteration = 0; iteration < REPEATS && !stopped; ++iteration) {
        if (snprintf(directory, sizeof directory, "%s/run-%02u", root, iteration) >= (int)sizeof directory ||
            mkdir(directory, 0700) || !prepare(helper)) { perror("prepare fixture"); ok = false; break; }
        uint64_t prepared_at = now_ns();
        if (schedule && prepared_at < schedule) delay_ns(schedule - prepared_at);
        if (stopped) { ok = false; break; }
        struct rusage before, after;
        if (getrusage(RUSAGE_CHILDREN, &before)) { ok = false; break; }
        uint64_t start = now_ns(); if (!schedule) schedule = start;
        uint64_t lag = start > schedule ? start - schedule : 0;
        bool launched = launch(binary);
        struct readiness ready = launched ? wait_ready(helper) : (struct readiness){0};
        struct resources resources[2] = {{0}, {0}};
        bool snapshot = ready.ready && quiet_snapshot(helper, resources);
        uint64_t snapshot_at = snapshot ? now_ns() : 0;
        struct cleanup closed = cleanup();
        bool cpu = !getrusage(RUSAGE_CHILDREN, &after) && closed.complete;
        bool callback_ok = !helper || exact_file(callback, callback_text);
        uint64_t finished = now_ns(), next = schedule + PERIOD_NS;
        bool passed = launched && ready.ready && snapshot && callback_ok && cpu && closed.owner_reaped &&
                      !closed.forced && !closed.bad_exits && !stopped && finished <= next;
        printf("{\"kind\":\"startup\",\"mode\":\"%s\",\"index\":%u,\"ok\":%s,"
               "\"start_ns\":%" PRIu64 ",\"start_lag_ns\":%" PRIu64 ",\"dns_ready_ns\":%" PRIu64 ","
               "\"callback_ready_ns\":%" PRIu64 ",\"ready_ns\":%" PRIu64 ",\"latency_ns\":%" PRIu64 ","
               "\"probe_attempts\":%u,\"callback_exact_once\":%s,\"snapshot_ns\":%" PRIu64 ",\"resources\":[",
               argv[1], iteration, passed ? "true" : "false", start, lag, ready.dns, ready.callback,
               ready.ready, ready.ready ? ready.ready - start : 0, ready.attempts,
               helper ? (callback_ok ? "true" : "false") : "null", snapshot_at);
        if (snapshot) { emit_resource(&resources[0]); if (helper) { putchar(','); emit_resource(&resources[1]); } }
        printf("],\"snapshot_scope\":\"%s\",\"cpu_complete\":%s,\"children_user_usec\":%" PRIu64 ","
               "\"children_system_usec\":%" PRIu64 ",\"cpu_scope\":\"whole_start_through_all_owned_reaps\","
               "\"supervisor_reaped\":%u,\"owner_reaped\":%s,\"owner_wait_status\":%d,\"bad_exits\":%u,"
               "\"forced_cleanup\":%s,\"all_children_reaped\":%s,\"finished_ns\":%" PRIu64 ",\"period_overrun_ns\":%" PRIu64 "}\n",
               helper ? "post_ready_owner_and_idle_helper_non_atomic" : "post_ready_owner_after_resolver_reap",
               cpu ? "true" : "false", cpu ? usec(after.ru_utime) - usec(before.ru_utime) : 0,
               cpu ? usec(after.ru_stime) - usec(before.ru_stime) : 0, closed.reaped,
               closed.owner_reaped ? "true" : "false", closed.owner_status, closed.bad_exits,
               closed.forced ? "true" : "false", closed.complete ? "true" : "false", finished,
               finished > next ? finished - next : 0);
        if (!passed || finished > next) { ok = false; break; }
        ++completed; schedule = next;
    }
    bool cpu_complete = children(getpid(), existing) == 0 && !getrusage(RUSAGE_CHILDREN, &final);
    printf("{\"kind\":\"summary\",\"mode\":\"%s\",\"expected_starts\":%u,\"completed\":%u,\"period_ms\":500,"
           "\"poll_floor_us\":1000,\"ok\":%s,\"cpu_complete\":%s,\"children_user_usec\":%" PRIu64 ","
           "\"children_system_usec\":%" PRIu64 "}\n", argv[1], REPEATS, completed,
           ok && !stopped && completed == REPEATS && cpu_complete ? "true" : "false", cpu_complete ? "true" : "false",
           cpu_complete ? usec(final.ru_utime) - usec(initial.ru_utime) : 0,
           cpu_complete ? usec(final.ru_stime) - usec(initial.ru_stime) : 0);
    return ok && !stopped && completed == REPEATS && cpu_complete ? 0 : 1;
}
