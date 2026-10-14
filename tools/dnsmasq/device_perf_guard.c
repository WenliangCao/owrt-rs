/* Read-only production health monitor for an isolated, disposable device test.
 * Usage: device_perf_guard /tmp/dnsmasq-perf-DATE PROD_PID MAXSECONDS
 * active.group contains "PID STARTTIME\n". The runner must check STOP before
 * starting a group and after publishing active.group, and must never detach
 * children from that group. SIGTERM ends this monitor without killing a group.
 * Build on Linux: cc -O2 -Wall -Wextra -Werror device_perf_guard.c -o guard
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MIN_MEMORY_KIB 81920ULL
#define CPU_LIMIT 35.0
#define PROBE_TIMEOUT_MS 700

static volatile sig_atomic_t interrupted;

static void on_signal(int sig) { (void)sig; interrupted = 1; }

static double monotime(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int parse_number(const char *s, unsigned long long *value)
{
    char *end;
    unsigned long long n;
    if (!s || *s < '0' || *s > '9')
        return -1;
    errno = 0;
    n = strtoull(s, &end, 10);
    if (errno || *end)
        return -1;
    *value = n;
    return 0;
}

static int read_small(const char *path, char *buf, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, buf, size - 1);
    close(fd);
    if (n <= 0 || (size_t)n == size - 1)
        return -1;
    buf[n] = 0;
    return (int)n;
}

static int process_start(pid_t pid, unsigned long long *start)
{
    char path[64], buf[4096], *p, *save = NULL, *field;
    int number = 3;
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (read_small(path, buf, sizeof(buf)) < 0)
        return -1;
    p = strrchr(buf, ')');
    if (!p || p[1] != ' ')
        return -1;
    for (field = strtok_r(p + 2, " \n", &save); field;
         field = strtok_r(NULL, " \n", &save), number++) {
        if (number == 22)
            return parse_number(field, start);
    }
    return -1;
}

static int cpu_sample(unsigned long long *total, unsigned long long *idle)
{
    FILE *f = fopen("/proc/stat", "r");
    unsigned long long v[8];
    int n, i;
    if (!f)
        return -1;
    n = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]);
    fclose(f);
    if (n != 8)
        return -1;
    *total = 0;
    for (i = 0; i < 8; i++)
        *total += v[i];
    *idle = v[3] + v[4];
    return 0;
}

static int available_memory(unsigned long long *available)
{
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    int found = -1;
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemAvailable: %llu kB", available) == 1) {
            found = 0;
            break;
        }
    }
    fclose(f);
    return found;
}

/* This is informational unless a main-table default existed at startup. */
static int ipv4_default(void)
{
    FILE *f = fopen("/proc/net/route", "r");
    char line[512], iface[64];
    unsigned long dest, gateway;
    unsigned flags;
    int found = 0;
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%63s %lx %lx %x", iface, &dest, &gateway, &flags) == 4
            && dest == 0 && (flags & 1)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int wait_fd(int fd, short events, double deadline)
{
    struct pollfd p = { .fd = fd, .events = events };
    while (!interrupted) {
        double remaining = deadline - monotime();
        int n;
        if (remaining <= 0)
            return -1;
        n = poll(&p, 1, (int)(remaining * 1000) + 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n > 0 && (p.revents & events))
            return 0;
        return -1;
    }
    return -1;
}

static int loopback_socket(int type, unsigned port, double deadline)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, type, 0), flags, error = 0;
    socklen_t len = sizeof(error);
    if (fd < 0)
        return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
        return fd;
    if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline) < 0
        || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error)
        goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static int dns_health(void)
{
    unsigned char query[] = {
        0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        7, 'O', 'p', 'e', 'n', 'W', 'r', 't', 3, 'l', 'a', 'n',
        0, 0, 1, 0, 1
    };
    unsigned char answer[2048];
    static uint16_t id;
    double deadline = monotime() + PROBE_TIMEOUT_MS / 1000.0;
    int fd = loopback_socket(SOCK_DGRAM, 53, deadline), good = 0;
    ssize_t n;
    if (fd < 0)
        return 0;
    id++;
    query[0] = (unsigned char)(id >> 8);
    query[1] = (unsigned char)id;
    if (send(fd, query, sizeof(query), MSG_NOSIGNAL) != (ssize_t)sizeof(query)
        || wait_fd(fd, POLLIN, deadline) < 0)
        goto done;
    n = recv(fd, answer, sizeof(answer), 0);
    good = n >= 12 && answer[0] == query[0] && answer[1] == query[1]
        && (answer[2] & 0x80) && !(answer[2] & 0x02)
        && !(answer[3] & 0x0f) && (answer[6] || answer[7]);
done:
    close(fd);
    return good;
}

static int http_health(void)
{
    const char request[] = "GET /cgi-bin/luci/ HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    char reply[512];
    size_t sent = 0, used = 0;
    double deadline = monotime() + PROBE_TIMEOUT_MS / 1000.0;
    int fd = loopback_socket(SOCK_STREAM, 80, deadline), status = 0;
    if (fd < 0)
        return 0;
    while (sent < sizeof(request) - 1) {
        ssize_t n;
        if (wait_fd(fd, POLLOUT, deadline) < 0)
            goto done;
        n = send(fd, request + sent, sizeof(request) - 1 - sent, MSG_NOSIGNAL);
        if (n <= 0)
            goto done;
        sent += (size_t)n;
    }
    while (used < sizeof(reply) - 1) {
        ssize_t n;
        if (wait_fd(fd, POLLIN, deadline) < 0)
            goto done;
        n = recv(fd, reply + used, sizeof(reply) - 1 - used, 0);
        if (n <= 0)
            goto done;
        used += (size_t)n;
        reply[used] = 0;
        if (strchr(reply, '\n')) {
            if (sscanf(reply, "HTTP/%*u.%*u %d", &status) != 1)
                status = 0;
            break;
        }
    }
done:
    close(fd);
    return status;
}

static int command_in_root(pid_t pid, const char *root)
{
    char path[64], buf[4096];
    size_t rootlen = strlen(root), offset = 0;
    int n;
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    n = read_small(path, buf, sizeof(buf));
    if (n < 0)
        return 0;
    while (offset < (size_t)n) {
        size_t len = strnlen(buf + offset, (size_t)n - offset);
        if (len >= rootlen && !memcmp(buf + offset, root, rootlen)
            && (len == rootlen || buf[offset + rootlen] == '/'))
            return 1;
        offset += len + 1;
    }
    return 0;
}

/* Return 1 only when an independently identified group received SIGKILL.
 * The PID file is never trusted as sufficient authority to signal a process. */
static int stop_active(int rootfd, const char *root, pid_t production)
{
    char buf[128], extra;
    unsigned long long pidnum, expected, actual;
    struct stat st;
    int fd = openat(rootfd, "active.group", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n;
    pid_t pid;
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
        close(fd);
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0 || n == (ssize_t)sizeof(buf) - 1)
        return -1;
    buf[n] = 0;
    if (sscanf(buf, "%llu %llu %c", &pidnum, &expected, &extra) != 2
        || pidnum <= 1 || pidnum > INT_MAX || expected == 0)
        return -1;
    pid = (pid_t)pidnum;
    if (pid == production || pid == getpid() || pid == getpgrp()
        || getpgid(pid) != pid || getpgid(production) == pid
        || process_start(pid, &actual) < 0 || actual != expected
        || !command_in_root(pid, root)
        || process_start(pid, &actual) < 0 || actual != expected
        || getpgid(pid) != pid)
        return -1;
    return kill(-pid, SIGKILL) == 0 ? 1 : -1;
}

static int stop_test(int rootfd, const char *root, pid_t production,
                     const char *reason, double elapsed)
{
    int fd, saved_errno, killed;
    if (interrupted)
        return 0;
    fd = openat(rootfd, "STOP", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC
                | O_NOFOLLOW, 0600);
    saved_errno = errno;
    if (fd >= 0) {
        dprintf(fd, "%s\n", reason);
        close(fd);
    }
    killed = interrupted ? 0 : stop_active(rootfd, root, production);
    printf("{\"event\":\"stop\",\"epoch\":%lld,\"elapsed_s\":%.3f,"
           "\"reason\":\"%s\",\"stop_file\":%s,\"group_killed\":%d}\n",
           (long long)time(NULL), elapsed, reason,
           fd >= 0 || saved_errno == EEXIST ? "true" : "false", killed);
    return 2;
}

int main(int argc, char **argv)
{
    unsigned long long pidnum, seconds, production_start, current_start;
    unsigned long long total, idle, previous_total, previous_idle, available;
    struct sigaction sa;
    struct stat st;
    pid_t production;
    double started, next_tick, next_dns = 0, next_http = 0;
    int rootfd, high_cpu = 0, had_default, result = 0;
    const char *root, *reason;
    if (argc != 4 || parse_number(argv[2], &pidnum) < 0 || pidnum <= 1
        || pidnum > INT_MAX || parse_number(argv[3], &seconds) < 0
        || seconds < 1 || seconds > 3600 || geteuid() != 0) {
        fprintf(stderr, "usage (root): %s /tmp/dnsmasq-perf-DATE PROD_PID SECONDS(1..3600)\n", argv[0]);
        return 1;
    }
    root = argv[1];
    if (strncmp(root, "/tmp/dnsmasq-perf-", 18) || strlen(root) < 19
        || strspn(root + 18, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_")
           != strlen(root + 18)) {
        fprintf(stderr, "unsafe task root\n");
        return 1;
    }
    production = (pid_t)pidnum;
    rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (rootfd < 0 || fstat(rootfd, &st) < 0 || st.st_uid != 0
        || (st.st_mode & 0022) || fstatat(rootfd, "STOP", &st, AT_SYMLINK_NOFOLLOW) == 0
        || process_start(production, &production_start) < 0
        || cpu_sample(&previous_total, &previous_idle) < 0) {
        fprintf(stderr, "unsafe/unavailable root, existing STOP, or missing production process/metrics\n");
        if (rootfd >= 0)
            close(rootfd);
        return 1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    started = next_tick = monotime();
    had_default = ipv4_default();
    printf("{\"event\":\"start\",\"epoch\":%lld,\"production_pid\":%ld,"
           "\"production_starttime\":%llu,\"deadline_s\":%llu,"
           "\"min_memory_kib\":%llu,\"cpu_limit_pct\":%.1f,"
           "\"ipv4_default_initial\":%d}\n", (long long)time(NULL),
           (long)production, production_start, seconds, MIN_MEMORY_KIB,
           CPU_LIMIT, had_default);
    while (!interrupted) {
        double now = monotime(), elapsed = now - started, cpu = 0;
        int dns = -1, http = -1, route;
        reason = NULL;
        if (elapsed >= (double)seconds)
            reason = "deadline";
        else if (fstatat(rootfd, "STOP", &st, AT_SYMLINK_NOFOLLOW) == 0)
            reason = "external_stop";
        else if (process_start(production, &current_start) < 0
                 || current_start != production_start)
            reason = "production_identity_changed";
        else if (available_memory(&available) < 0)
            reason = "memory_metric_unavailable";
        else if (available < MIN_MEMORY_KIB)
            reason = "low_memory";
        else if (cpu_sample(&total, &idle) < 0 || total < previous_total
                 || idle < previous_idle)
            reason = "cpu_metric_unavailable";
        if (reason) {
            result = stop_test(rootfd, root, production, reason, elapsed);
            break;
        }
        if (total > previous_total)
            cpu = 100.0 * (1.0 - (double)(idle - previous_idle)
                           / (double)(total - previous_total));
        previous_total = total;
        previous_idle = idle;
        high_cpu = elapsed >= 0.8 && cpu > CPU_LIMIT ? high_cpu + 1 : 0;
        route = ipv4_default();
        if (high_cpu >= 3)
            reason = "host_cpu_high_three_samples";
        else if (had_default == 1 && route != 1)
            reason = "ipv4_default_lost";
        if (!reason && elapsed >= next_dns) {
            dns = dns_health();
            next_dns = elapsed + 2;
            if (!dns && !interrupted)
                reason = "production_dns_failed";
        }
        if (!reason && !interrupted && elapsed >= next_http) {
            http = http_health();
            next_http = elapsed + 5;
            if (http != 200 && http != 301 && http != 302 && http != 401
                && http != 403 && !interrupted)
                reason = "luci_http_failed";
        }
        printf("{\"event\":\"sample\",\"epoch\":%lld,\"elapsed_s\":%.3f,"
               "\"cpu_pct\":%.3f,\"high_cpu_samples\":%d,\"mem_available_kib\":%llu,"
               "\"production_pid\":%ld,\"production_starttime\":%llu,"
               "\"dns_ok\":%d,\"http_status\":%d,\"ipv4_default\":%d}\n",
               (long long)time(NULL), elapsed, cpu, high_cpu, available,
               (long)production, production_start, dns, http, route);
        if (reason && !interrupted) {
            result = stop_test(rootfd, root, production, reason, monotime() - started);
            break;
        }
        next_tick += 1;
        now = monotime();
        if (next_tick < now)
            next_tick = now;
        while (!interrupted && (now = monotime()) < next_tick) {
            double left = next_tick - now;
            struct timespec wait = { .tv_sec = (time_t)left,
                                    .tv_nsec = (long)((left - (time_t)left) * 1e9) };
            nanosleep(&wait, NULL);
        }
    }
    if (interrupted)
        printf("{\"event\":\"monitor_stopped\",\"epoch\":%lld,\"elapsed_s\":%.3f}\n",
               (long long)time(NULL), monotime() - started);
    close(rootfd);
    return result;
}
