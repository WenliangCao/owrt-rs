/* One explicitly requested fw4 sample. Setup/validation belongs to the caller.
 * Direct exec wall time includes fork/exec/reap; wait4 CPU includes the child
 * and descendants it reaped (fw4 waits for nft). No ptrace, logging wrapper,
 * cache eviction, repetition or statistical policy is hidden in this helper.
 * Usage: exec-sample RESULT STDOUT STDERR PROGRAM [ARGS...]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t ns(struct timespec value)
{
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc < 5) return 2;
    FILE *out = fopen(argv[1], "wx");
    int stdout_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    int stderr_fd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (!out || stdout_fd < 0 || stderr_fd < 0 || fcntl(fileno(out), F_SETFD, FD_CLOEXEC)) {
        perror("sample outputs"); return 2;
    }
    struct timespec before, after, resolution;
    if (clock_getres(CLOCK_MONOTONIC, &resolution) || clock_gettime(CLOCK_MONOTONIC, &before)) {
        perror("sample clock"); return 2;
    }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 2; }
    if (!child) {
        if (dup2(stdout_fd, STDOUT_FILENO) < 0 || dup2(stderr_fd, STDERR_FILENO) < 0) _exit(125);
        execv(argv[4], argv + 4);
        _exit(127);
    }
    struct rusage usage;
    int status;
    pid_t waited;
    do { waited = wait4(child, &status, 0, &usage); } while (waited < 0 && errno == EINTR);
    if (clock_gettime(CLOCK_MONOTONIC, &after) || waited != child) { perror("reap sample"); return 2; }
    close(stdout_fd);
    close(stderr_fd);
    int result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    long long user_us = (long long)usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec;
    long long system_us = (long long)usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec;
    int failed = fprintf(out,
        "{\"schema\":1,\"exit\":%d,\"wall_ns\":%llu,\"cpu_us\":%lld,"
        "\"user_us\":%lld,\"system_us\":%lld,\"start_monotonic_ns\":%llu,"
        "\"end_monotonic_ns\":%llu,\"wall_resolution_ns\":%llu,\"cpu_resolution_us\":1,"
        "\"maxrss_kib\":%ld,\"minor_faults\":%ld,\"major_faults\":%ld}\n",
        result, (unsigned long long)(ns(after) - ns(before)), user_us + system_us,
        user_us, system_us, (unsigned long long)ns(before), (unsigned long long)ns(after),
        (unsigned long long)ns(resolution), usage.ru_maxrss, usage.ru_minflt, usage.ru_majflt) < 0;
    if (fclose(out)) failed = 1;
    return failed ? 2 : result;
}
