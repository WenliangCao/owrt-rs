/* Bounded CPU-clock capability probe and read-only endpoint sampler.
 * "selftest" owns one forked worker; "read PID STARTTIME" never signals PID.
 * Nanosecond units and clock_getres are not an accuracy or precision claim.
 * Build once with the image SDK: cc -O2 -std=c11 -Wall -Wextra -Werror -static.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NS UINT64_C(1000000000)
#define READS 256
struct proc { uint64_t start, user, system, child_user, child_system; };
struct cpu { clockid_t id; int id_error, time_error, res_error; uint64_t ns, res; };
struct reply { char command; uint64_t checksum; };

static void fail(const char *what) { perror(what); exit(2); }
static uint64_t as_ns(struct timespec t) { return (uint64_t)t.tv_sec * NS + (uint64_t)t.tv_nsec; }
static uint64_t monotonic(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) fail("monotonic");
    return as_ns(t);
}
static void pause_ns(long ns) {
    struct timespec t = {0, ns};
    while (nanosleep(&t, &t)) if (errno != EINTR) fail("nanosleep");
}
static void transfer(int fd, void *data, size_t size, int writing) {
    char *p = data;
    while (size) {
        ssize_t n = writing ? write(fd, p, size) : read(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EPIPE; fail("pipe"); }
        p += n; size -= (size_t)n;
    }
}
static int proc_stat(pid_t pid, struct proc *out) {
    char path[64], line[4096], *save = NULL;
    memset(out, 0, sizeof *out);
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int ok = fgets(line, sizeof line, f) != NULL;
    fclose(f);
    if (!ok) return 0;
    char *end = strrchr(line, ')');
    if (!end || end[1] != ' ') return 0;
    unsigned field = 3;
    for (char *v = strtok_r(end + 2, " \n", &save); v; v = strtok_r(NULL, " \n", &save), field++) {
        uint64_t n = strtoull(v, NULL, 10);
        if (field == 14) out->user = n;
        if (field == 15) out->system = n;
        if (field == 16) out->child_user = n;
        if (field == 17) out->child_system = n;
        if (field == 22) out->start = n;
    }
    return field > 22;
}
static struct cpu cpu_read(pid_t pid) {
    struct cpu c = {.time_error = -1, .res_error = -1};
    struct timespec t;
    c.id_error = clock_getcpuclockid(pid, &c.id); /* Returns errno directly. */
    if (!c.id_error) {
        c.time_error = clock_gettime(c.id, &t) ? errno : 0;
        if (!c.time_error) c.ns = as_ns(t);
        c.res_error = clock_getres(c.id, &t) ? errno : 0;
        if (!c.res_error) c.res = as_ns(t);
    }
    return c;
}
static void emit_cpu(struct cpu c) {
    printf("{\"getcpuclockid_error\":%d,\"clock_id\":%ld,\"gettime_error\":%d,\"getres_error\":%d,\"cpu_ns\":",
           c.id_error, (long)c.id, c.time_error, c.res_error);
    if (!c.id_error && !c.time_error) printf("%" PRIu64, c.ns); else fputs("null", stdout);
    fputs(",\"reported_resolution_ns\":", stdout);
    if (!c.id_error && !c.res_error) printf("%" PRIu64, c.res); else fputs("null", stdout);
    putchar('}');
}
static int snapshot(const char *phase, pid_t pid, uint64_t expected) {
    struct proc before, after;
    uint64_t begin = monotonic();
    int exists = proc_stat(pid, &before);
    struct cpu c = cpu_read(pid);
    int same = exists && proc_stat(pid, &after) && before.start == after.start &&
               (!expected || before.start == expected);
    printf("{\"event\":\"snapshot\",\"phase\":\"%s\",\"pid\":%ld,\"same_identity\":%s,"
           "\"starttime_ticks\":%" PRIu64 ",\"user_ticks\":%" PRIu64 ",\"system_ticks\":%" PRIu64
           ",\"waited_child_user_ticks\":%" PRIu64 ",\"waited_child_system_ticks\":%" PRIu64
           ",\"monotonic_before_ns\":%" PRIu64 ",\"monotonic_after_ns\":%" PRIu64 ",\"clock\":",
           phase, (long)pid, same ? "true" : "false", before.start, before.user, before.system,
           before.child_user, before.child_system, begin, monotonic());
    emit_cpu(c); puts("}");
    return same;
}
static uint64_t work(void) {
    uint64_t until = monotonic() + NS / 10, sum = 1;
    do { for (unsigned i = 0; i < 1024; i++) sum = (sum ^ (sum >> 7)) * 33 + i; }
    while (monotonic() < until);
    return sum;
}
static void worker(int input, int output, pid_t parent) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(2);
    for (;;) {
        char command;
        transfer(input, &command, 1, 0);
        struct reply r = {.command = command};
        if (command == 'S') pause_ns(100000000);
        else if (command == 'B') {
            char ready = 'B'; transfer(output, &ready, 1, 1);
            r.checksum = work();
        } else if (command != 'X') _exit(2);
        transfer(output, &r, sizeof r, 1);
        if (command == 'X') _exit(0);
    }
}
static void samples(clockid_t id, int available, int paced) {
    printf("{\"event\":\"samples\",\"paced\":%s,\"requested_pause_ns\":%d,\"readings\":[",
           paced ? "true" : "false", paced ? 200000 : 0);
    for (unsigned i = 0; i < READS; i++) {
        struct timespec t;
        int error = available ? (clock_gettime(id, &t) ? errno : 0) : -1;
        if (i) putchar(',');
        printf("[ %" PRIu64 ",", monotonic());
        if (!error) printf("%" PRIu64, as_ns(t)); else fputs("null", stdout);
        printf(",%d]", error);
        if (paced) pause_ns(200000);
    }
    puts("]}");
}
static int selftest(void) {
    int commands[2], responses[2];
    if (pipe(commands) || pipe(responses)) fail("pipe");
    pid_t parent = getpid(), child = fork();
    if (child < 0) fail("fork");
    if (!child) { close(commands[1]); close(responses[0]); worker(commands[0], responses[1], parent); }
    close(commands[0]); close(responses[1]);
    struct proc p;
    if (!proc_stat(child, &p)) fail("child stat");
    struct cpu saved = cpu_read(child);
    printf("{\"event\":\"identity\",\"observer_pid\":%ld,\"worker_pid\":%ld,\"worker_starttime_ticks\":%" PRIu64
           ",\"clock_ticks_per_second\":%ld,\"scope\":\"capability only; units/resolution/minimum observed step are not accuracy\"}\n",
           (long)parent, (long)child, p.start, sysconf(_SC_CLK_TCK));
    const char phases[] = {'S', 'B'};
    for (unsigned i = 0; i < sizeof phases; i++) {
        char command = phases[i];
        snapshot(command == 'S' ? "sleep-before" : "work-before", child, p.start);
        snapshot(command == 'S' ? "observer-sleep-before" : "observer-work-before", parent, 0);
        transfer(commands[1], &command, 1, 1);
        if (command == 'B') {
            char ready; transfer(responses[0], &ready, 1, 0);
            if (ready != 'B') { errno = EPROTO; fail("worker ready"); }
            samples(saved.id, !saved.id_error, 0); samples(saved.id, !saved.id_error, 1);
        }
        struct reply r; transfer(responses[0], &r, sizeof r, 0);
        if (r.command != command) { errno = EPROTO; fail("worker reply"); }
        snapshot(command == 'S' ? "sleep-after" : "work-after", child, p.start);
        snapshot(command == 'S' ? "observer-sleep-after" : "observer-work-after", parent, 0);
    }
    char command = 'X'; transfer(commands[1], &command, 1, 1);
    struct reply r; transfer(responses[0], &r, sizeof r, 0);
    siginfo_t status;
    if (waitid(P_PID, (id_t)child, &status, WEXITED | WNOWAIT)) fail("waitid");
    snapshot("exited-not-reaped", child, p.start);
    snapshot("observer-before-reap", parent, 0);
    int exit_status;
    if (waitpid(child, &exit_status, 0) != child) fail("waitpid");
    snapshot("observer-after-reap", parent, 0);
    snapshot("reaped", child, p.start);
    struct timespec t;
    int error = saved.id_error ? -1 : (clock_gettime(saved.id, &t) ? errno : 0);
    printf("{\"event\":\"saved_clock_after_reap\",\"gettime_error\":%d,\"cpu_ns\":", error);
    if (!error) printf("%" PRIu64, as_ns(t)); else fputs("null", stdout);
    printf(",\"worker_exit_status\":%d}\n", exit_status);
    close(commands[1]); close(responses[0]);
    return !WIFEXITED(exit_status) || WEXITSTATUS(exit_status) != 0;
}
int main(int argc, char **argv) {
    alarm(5); /* A failed capability check cannot leave an unbounded worker. */
    if (argc == 2 && !strcmp(argv[1], "selftest")) return selftest();
    if (argc == 4 && !strcmp(argv[1], "read")) {
        char *end; long pid = strtol(argv[2], &end, 10);
        if (pid <= 0 || pid > 2147483647L || *end) return 2;
        uint64_t start = strtoull(argv[3], &end, 10);
        if (!start || *end) return 2;
        return snapshot("endpoint", (pid_t)pid, start) ? 0 : 2;
    }
    fputs("usage: device_cpu_clock_probe selftest | read PID STARTTIME_TICKS\n", stderr);
    return 2;
}
