/* Router-local lifecycle measurement, never a product/service controller.
 * Must run in a fresh loopback-only network namespace. Only children created
 * here are signalled. All files are placed in a caller-created /tmp directory.
 * Usage: device_perf_lifecycle MODE ELF DIRECTORY HOST_COUNT REPEATS PERIOD_MS [LEASE_COUNT]
 * MODE=startup: exec to first correct hosts answer, new child each iteration.
 * MODE=hup: hosts replacement (rename), then SIGHUP to first new hosts answer.
 * MODE=config: replace startup config, stop old child and start new child;
 *              measure stop request to first answer with the new config.
 * SIGHUP does NOT re-read the primary config. Observation resolution is at
 * most 1 ms plus scheduler delay; records preserve attempts and raw duration.
 * File preparation/rename precedes the timer; daemon file reading is timed.
 * HUP CPU is the parent's ticks plus waited-child ticks between signal/ready.
 * Startup/config CPU is only the new process up to ready, not old shutdown.
 * Final RUSAGE_CHILDREN is whole-run child CPU including shutdown and idle.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT 15353
#define NS 1000000000ULL
static char directory[PATH_MAX], config[PATH_MAX], hosts[PATH_MAX];
static pid_t child = -1;
static volatile sig_atomic_t stopped;
static unsigned sequence;
static unsigned lease_count;

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock_gettime"); exit(2); }
    return (uint64_t)t.tv_sec * NS + (uint64_t)t.tv_nsec;
}
static void interrupted(int sig) { (void)sig; stopped = 1; }
static void delay_ns(uint64_t duration) {
    struct timespec t = {(time_t)(duration / NS), (long)(duration % NS)};
    while (nanosleep(&t, &t) && errno == EINTR && !stopped) {}
}
static void die(const char *message) { perror(message); stopped = 1; }
static int path(char *out, const char *suffix) {
    return snprintf(out, PATH_MAX, "%s/%s", directory, suffix) < PATH_MAX;
}
static int isolated(void) {
    struct stat ours, init;
    if (stat("/proc/self/ns/net", &ours) || stat("/proc/1/ns/net", &init) ||
        (ours.st_dev == init.st_dev && ours.st_ino == init.st_ino)) return 0;
    struct if_nameindex *list = if_nameindex();
    if (!list) return 0;
    unsigned count = 0; int ok = 1;
    for (struct if_nameindex *it = list; it->if_index; ++it) {
        ++count; if (strcmp(it->if_name, "lo")) ok = 0;
    }
    if_freenameindex(list);
    return ok && count == 1;
}
static int write_hosts(unsigned count, unsigned version) {
    char temporary[PATH_MAX];
    if (!path(temporary, "hosts.new")) return 0;
    FILE *f = fopen(temporary, "w");
    if (!f) return 0;
    for (unsigned i = 0; i < count; ++i)
        fprintf(f, "192.0.2.%u host%06u.device-perf.test\n", i % 250 + 1, i);
    fprintf(f, "192.0.2.%u marker.device-perf.test\n", version);
    int error = ferror(f);
    if (fclose(f)) error = 1;
    return !error && !rename(temporary, hosts);
}
static int write_config(unsigned version) {
    char temporary[PATH_MAX];
    if (!path(temporary, "config.new")) return 0;
    FILE *f = fopen(temporary, "w");
    if (!f) return 0;
    fprintf(f, "no-hosts\nno-resolv\nno-poll\nuser=root\ngroup=root\n"
            "interface=lo\nbind-interfaces\nlisten-address=127.0.0.1\n"
            "port=%u\ncache-size=1000\nlocal-ttl=120\n"
            "local=/device-perf.test/\naddn-hosts=%s\n"
            "address=/config.device-perf.test/192.0.2.%u\n"
            "pid-file=%s/pid\nlog-facility=%s/daemon.log\n",
            PORT, hosts, version, directory, directory);
    if (lease_count)
        fprintf(f, "no-ping\ndhcp-authoritative\n"
                "dhcp-range=127.0.0.10,127.0.0.%u,255.0.0.0,127.255.255.255,12h\n"
                "dhcp-lease-max=150\ndhcp-leasefile=%s/leases\ndomain=device-perf.test\n",
                lease_count+9, directory);
    int error = ferror(f);
    if (fclose(f)) error = 1;
    return !error && !rename(temporary, config);
}
static int write_initial_leases(void) {
    if (!lease_count) return 1;
    char filename[PATH_MAX];
    if (!path(filename, "leases")) return 0;
    FILE *f = fopen(filename, "wx");
    if (!f) return 0;
    time_t expiry = time(NULL) + 43200;
    for (unsigned i=0; i<lease_count; ++i)
        fprintf(f, "%lld 02:00:00:de:00:%02x 127.0.0.%u lease%03u *\n",
                (long long)expiry, i, i+10, i);
    int error = ferror(f);
    if (fclose(f)) error = 1;
    return !error;
}
static int launch(const char *binary) {
    child = fork();
    if (child < 0) return 0;
    if (!child) {
        /* Keep the external trial supervisor's process group. Its emergency
         * group kill must include this child even if this helper is killed. */
        char log[PATH_MAX];
        if (!path(log, "stderr.log")) _exit(126);
        int fd = open(log, O_CREAT | O_APPEND | O_WRONLY, 0600);
        if (fd < 0 || dup2(fd, STDERR_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(126);
        close(fd);
        char config_option[PATH_MAX + 16];
        if (snprintf(config_option, sizeof(config_option), "--conf-file=%s", config) >= (int)sizeof(config_option)) _exit(126);
        execl(binary, binary, "--keep-in-foreground", config_option, (char *)NULL);
        _exit(127);
    }
    return 1;
}
static int end_child(void) {
    if (child <= 0) return 1;
    pid_t own = child;
    /* The PID is our unreaped direct child, so it cannot have been reused. */
    kill(own, SIGTERM);
    uint64_t end = now_ns() + 2 * NS;
    int status;
    for (;;) {
        pid_t result = waitpid(own, &status, WNOHANG);
        if (result == own || (result < 0 && errno == ECHILD)) { child = -1; return 1; }
        if (result < 0 && errno != EINTR) { child = -1; return 0; }
        if (now_ns() >= end) break;
        delay_ns(1000000);
    }
    kill(own, SIGKILL);
    while (waitpid(own, &status, 0) < 0 && errno == EINTR) {}
    child = -1;
    return 0;
}
static unsigned read16(const unsigned char *p) { return p[0] * 256U + p[1]; }
static size_t skip_name(const unsigned char *p, size_t n, size_t offset) {
    unsigned steps = 0;
    while (offset < n && ++steps < 128) {
        unsigned label = p[offset++];
        if (!label) return offset;
        if ((label & 0xc0) == 0xc0) return offset < n ? offset + 1 : 0;
        if (label > 63 || offset + label > n) return 0;
        offset += label;
    }
    return 0;
}
static int reply_correct(const unsigned char *p, size_t n, unsigned id, unsigned expected) {
    if (n < 12 || read16(p) != id || (read16(p+2) & 0x820f) != 0x8000 ||
        read16(p+4) != 1 || read16(p+6) != 1) return 0;
    size_t offset = skip_name(p, n, 12);
    if (!offset || offset + 4 > n || read16(p+offset) != 1 || read16(p+offset+2) != 1) return 0;
    offset = skip_name(p, n, offset + 4);
    return offset && offset + 14 <= n && read16(p+offset) == 1 &&
        read16(p+offset+2) == 1 && read16(p+offset+8) == 4 &&
        p[offset+10] == 192 && p[offset+11] == 0 && p[offset+12] == 2 && p[offset+13] == expected;
}
static int visible(const char *name, unsigned expected, uint64_t *when, unsigned *attempts) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct sockaddr_in target = {.sin_family=AF_INET, .sin_port=htons(PORT)};
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&target, sizeof(target))) { close(fd); return 0; }
    unsigned char request[512] = {0}, reply[512];
    unsigned id = ++sequence & 65535;
    request[0] = (unsigned char)(id >> 8); request[1] = (unsigned char)id;
    request[2] = 1; request[5] = 1;
    size_t size = 12;
    const char *label = name;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t length = dot ? (size_t)(dot-label) : strlen(label);
        if (length > 63 || size+length+6 >= sizeof(request)) { close(fd); return 0; }
        request[size++] = (unsigned char)length;
        memcpy(request+size, label, length); size += length;
        if (!dot) break;
        label = dot+1;
    }
    request[size++] = 0; request[size++] = 0; request[size++] = 1;
    request[size++] = 0; request[size++] = 1;
    uint64_t deadline = now_ns() + 3 * NS;
    *attempts = 0;
    while (!stopped && now_ns() < deadline) {
        if (kill(child, 0)) break;
        ++*attempts;
        uint64_t sent = now_ns();
        if (send(fd, request, size, 0) < 0 && errno != ECONNREFUSED) break;
        struct pollfd item = {.fd=fd, .events=POLLIN};
        if (poll(&item, 1, 1) > 0) {
            ssize_t length = recv(fd, reply, sizeof(reply), MSG_DONTWAIT);
            if (length > 0 && reply_correct(reply, (size_t)length, id, expected)) {
                *when = now_ns(); close(fd); return 1;
            }
        }
        uint64_t elapsed = now_ns() - sent;
        if (elapsed < 1000000) delay_ns(1000000 - elapsed);
    }
    close(fd); return 0;
}
struct metrics { uint64_t ticks; unsigned rss, anon, shmem, file, fds, threads; };
static struct metrics metrics(void) {
    struct metrics m = {0};
    char name[PATH_MAX], line[8192];
    snprintf(name, sizeof(name), "/proc/%ld/stat", (long)child);
    FILE *f = fopen(name, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            char *at = strrchr(line, ')');
            if (at) {
                char *save = NULL, *token = strtok_r(at+2, " ", &save);
                for (unsigned field=3; token; ++field, token=strtok_r(NULL," ",&save))
                    if (field >= 14 && field <= 17) m.ticks += strtoull(token, NULL, 10);
            }
        }
        fclose(f);
    }
    snprintf(name, sizeof(name), "/proc/%ld/status", (long)child);
    f = fopen(name, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "VmRSS: %u", &m.rss) == 1) continue;
            if (sscanf(line, "RssAnon: %u", &m.anon) == 1) continue;
            if (sscanf(line, "RssShmem: %u", &m.shmem) == 1) continue;
            if (sscanf(line, "RssFile: %u", &m.file) == 1) continue;
            (void)sscanf(line, "Threads: %u", &m.threads);
        }
        fclose(f);
    }
    snprintf(name, sizeof(name), "/proc/%ld/fd", (long)child);
    DIR *d = opendir(name);
    if (d) { struct dirent *entry; while ((entry=readdir(d))) if (entry->d_name[0] != '.') ++m.fds; closedir(d); }
    return m;
}
int main(int argc, char **argv) {
    if ((argc != 7 && argc != 8) || (strcmp(argv[1], "startup") && strcmp(argv[1], "hup") && strcmp(argv[1], "config"))) {
        fputs("usage: device_perf_lifecycle startup|hup|config ELF DIRECTORY HOST_COUNT REPEATS PERIOD_MS [LEASE_COUNT]\n", stderr);
        return 2;
    }
    char *end;
    unsigned count = (unsigned)strtoul(argv[4], &end, 10); if (*end || count > 10000) return 2;
    unsigned repeats = (unsigned)strtoul(argv[5], &end, 10); if (*end || !repeats || repeats > 1000) return 2;
    unsigned period = (unsigned)strtoul(argv[6], &end, 10); if (*end || period < 100 || period > 60000) return 2;
    if (argc == 8) { lease_count = (unsigned)strtoul(argv[7], &end, 10); if (*end || lease_count > 150) return 2; }
    if (!realpath(argv[3], directory) || strncmp(directory, "/tmp/", 5) ||
        !path(config, "config") || !path(hosts, "hosts") || !isolated()) {
        fputs("requires an existing /tmp directory and isolated loopback-only netns\n", stderr); return 2;
    }
    signal(SIGINT, interrupted); signal(SIGTERM, interrupted); signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    int startup = !strcmp(argv[1], "startup"), hup = !strcmp(argv[1], "hup");
    int ok = 1;
    if (!write_initial_leases() || !write_hosts(count, 10) || !write_config(10)) { die("initial files"); return 2; }
    if (!startup) {
        uint64_t ignored; unsigned attempts;
        if (!launch(argv[2]) || !visible("marker.device-perf.test", 10, &ignored, &attempts)) {
            end_child(); fputs("initial readiness failed\n", stderr); return 1;
        }
        delay_ns(NS);
    }
    for (unsigned i=0; i<repeats && !stopped; ++i) {
        unsigned version = 11 + i % 200;
        struct metrics before = startup ? (struct metrics){0} : metrics();
        if (!write_hosts(count, version) || !write_config(version)) { die("replace files"); ok=0; break; }
        uint64_t start = now_ns(), when = 0;
        if (startup) ok = launch(argv[2]);
        else if (hup) ok = kill(child, SIGHUP) == 0;
        else { ok = end_child(); if (ok) ok = launch(argv[2]); }
        unsigned attempts = 0;
        if (ok) ok = visible(hup || startup ? "marker.device-perf.test" : "config.device-perf.test", version, &when, &attempts);
        struct metrics after = metrics();
        printf("{\"mode\":\"%s\",\"index\":%u,\"hosts\":%u,\"initial_leases\":%u,\"ok\":%s,\"pid\":%ld,"
               "\"start_ns\":%" PRIu64 ",\"visible_ns\":%" PRIu64 ",\"latency_ns\":%" PRIu64 ","
               "\"probe_attempts\":%u,\"cpu_ticks\":%" PRIu64 ",\"clk_tck\":%ld,"
               "\"cpu_scope\":\"%s\","
               "\"rss_kib\":%u,\"anon_kib\":%u,\"file_kib\":%u,\"shmem_kib\":%u,\"fds\":%u,\"threads\":%u}\n",
               argv[1], i, count+1, lease_count, ok?"true":"false", (long)child, start, when, when?when-start:0,
               attempts, after.ticks-(hup?before.ticks:0), sysconf(_SC_CLK_TCK),
               hup?"signal_to_ready_parent_plus_waited_children":"new_process_through_ready_excludes_old_shutdown",
               after.rss, after.anon, after.file, after.shmem, after.fds, after.threads);
        if (startup && !end_child()) ok = 0;
        if (!ok) break;
        uint64_t elapsed = now_ns()-start, interval = (uint64_t)period*1000000;
        if (elapsed < interval) delay_ns(interval-elapsed);
    }
    if (!end_child()) ok = 0;
    struct rusage usage;
    if (!getrusage(RUSAGE_CHILDREN, &usage))
        fprintf(stderr, "children_cpu_usec=%ld clk_tck=%ld\n",
                (long)(usage.ru_utime.tv_sec+usage.ru_stime.tv_sec)*1000000L+usage.ru_utime.tv_usec+usage.ru_stime.tv_usec,
                sysconf(_SC_CLK_TCK));
    return ok && !stopped ? 0 : 1;
}
