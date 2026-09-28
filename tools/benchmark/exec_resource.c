/* Separate full-lifetime diagnostics, never latency samples.
 * Usage: exec-resource OUTPUT.json PROGRAM [ARG...]
 * wait4 covers the direct child and descendants it reaped. Linux ru_maxrss
 * is a maximum, not the sum of simultaneous process RSS. It can include the
 * tiny fork-to-exec launcher interval and must not be called UCI-only for sh.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (!pid) {
        execvp(argv[2], argv + 2);
        perror("execvp");
        _exit(127);
    }
    struct rusage usage;
    int status;
    pid_t waited;
    do { waited = wait4(pid, &status, 0, &usage); } while (waited < 0 && errno == EINTR);
    if (waited != pid) { perror("wait4"); return 2; }
    FILE *out = fopen(argv[1], "wx");
    if (!out) { perror("fopen"); return 2; }
    int result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    int failed = fprintf(out,
        "{\"schema\":1,\"method\":\"wait4\",\"exit\":%d,"
        "\"maxrss_kib\":%ld,\"minor_faults\":%ld,\"major_faults\":%ld,"
        "\"user_us\":%lld,\"system_us\":%lld,"
        "\"voluntary_switches\":%ld,\"involuntary_switches\":%ld}\n",
        result, usage.ru_maxrss, usage.ru_minflt, usage.ru_majflt,
        (long long)usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec,
        (long long)usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec,
        usage.ru_nvcsw, usage.ru_nivcsw) < 0;
    if (fclose(out)) failed = 1;
    return failed ? 2 : result;
}
