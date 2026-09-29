/* One real UCI -> reload_config -> procd -> probe-service reload cycle.
 * Only the owned owrtstackprobe configuration may be changed. The observed
 * value comes from the service's reload callback, not the event ACK.
 * stdout stays empty for the existing verified exec benchmark. Stage timings
 * append to a private journal. This helper never changes network settings.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock_gettime"); exit(1); }
    return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
}

static void run(char *const argv[]) {
    pid_t p = fork();
    if (p < 0) { perror("fork"); exit(1); }
    if (!p) { execv(argv[0], argv); _exit(127); }
    int s;
    while (waitpid(p, &s, 0) < 0) {
        if (errno != EINTR) { perror("waitpid"); exit(1); }
    }
    if (!WIFEXITED(s) || WEXITSTATUS(s)) { fprintf(stderr, "cycle command failed: %s\n", argv[0]); exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 2 || strncmp(argv[1], "/tmp/owrt-stack-", 16)) return 2;
    char journal[512];
    if (snprintf(journal, sizeof journal, "%s/config-cycle.jsonl", argv[1]) >= (int)sizeof journal) return 2;
    FILE *in = fopen("/tmp/owrt-stack-probe/sequence", "r");
    unsigned long value;
    if (!in || fscanf(in, "%lu", &value) != 1 || value >= 1000000) return 2;
    if (fclose(in)) return 1;
    value++;
    char assignment[128];
    snprintf(assignment, sizeof assignment, "owrtstackprobe.state.value=%lu", value);
    unsigned long long start = now_ns();
    char *set[] = {"/sbin/uci", "-q", "set", assignment, NULL};
    char *commit[] = {"/sbin/uci", "-q", "commit", "owrtstackprobe", NULL};
    char *reload[] = {"/sbin/reload_config", NULL};
    run(set); run(commit);
    unsigned long long committed = now_ns();
    run(reload);
    unsigned long long dispatched = now_ns();
    unsigned polls = 0;
    for (;;) {
        unsigned long seen = 0;
        FILE *f = fopen("/tmp/owrt-stack-probe/observed", "r");
        int found = f ? fscanf(f, "%lu", &seen) : 0;
        if (f) fclose(f);
        if (found == 1 && seen == value) break;
        if (now_ns() - dispatched > 5000000000ULL) { fprintf(stderr, "service reload deadline\n"); return 1; }
        struct timespec delay = {0, 5000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
        polls++;
    }
    unsigned long long completed = now_ns();
    FILE *seq = fopen("/tmp/owrt-stack-probe/sequence", "w");
    if (!seq || fprintf(seq, "%lu\n", value) < 0 || fclose(seq)) return 1;
    FILE *log = fopen(journal, "a");
    if (!log) return 1;
    if (fprintf(log, "{\"value\":%lu,\"commit_ns\":%llu,\"dispatch_ns\":%llu,\"completion_ns\":%llu,\"polls\":%u}\n",
                value, committed-start, dispatched-committed, completed-start, polls) < 0 || fclose(log)) return 1;
    return 0;
}
