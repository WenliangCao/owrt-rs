/* Separate task-lifecycle diagnostic; never use its timings, CPU or RSS.
 * Usage: exec-task-counts OUTPUT.json PROGRAM [ARG...]
 * Linux ptrace fork/vfork/clone events cover short-lived descendants without
 * sampling. threads counts all created tasks, including process leaders.
 * Reference: https://man7.org/linux/man-pages/man2/ptrace.2.html
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

struct task { pid_t pid; int live; };
static struct task tasks[65536];
static unsigned count, processes, live, peak;

static int record(pid_t pid)
{
    for (unsigned i = 0; i < count; i++)
        if (tasks[i].pid == pid && tasks[i].live) return (int)i;
    if (count == sizeof(tasks) / sizeof(tasks[0])) {
        errno = EOVERFLOW;
        return -1;
    }
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    int tgid = -1;
    while (fgets(line, sizeof(line), file))
        if (sscanf(line, "Tgid: %d", &tgid) == 1) break;
    fclose(file);
    if (tgid < 1) { errno = EINVAL; return -1; }
    processes += tgid == pid;
    tasks[count] = (struct task){pid, 1};
    if (++live > peak) peak = live;
    return (int)count++;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 2; }
    if (!child) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) _exit(125);
        raise(SIGSTOP);
        execvp(argv[2], argv + 2);
        _exit(127);
    }
    int status;
    pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != child || !WIFSTOPPED(status)) return 2;
    unsigned long options = PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, options) < 0 || record(child) < 0)
        goto fail;
    if (ptrace(PTRACE_CONT, child, NULL, 0) < 0) goto fail;
    unsigned forks = 0, vforks = 0, clones = 0, execs = 0;
    int result = -1;
    for (;;) {
        got = waitpid(-1, &status, __WALL);
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD && live == 0) break;
            goto fail;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            int found = 0;
            for (unsigned i = 0; i < count; i++) {
                if (tasks[i].pid == got && tasks[i].live) {
                    tasks[i].live = 0; live--; found = 1; break;
                }
            }
            if (!found) { errno = EINVAL; goto fail; }
            if (got == child)
                result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            continue;
        }
        if (!WIFSTOPPED(status) || record(got) < 0) goto fail;
        unsigned event = (unsigned)status >> 16;
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long newborn = 0;
            if (ptrace(PTRACE_GETEVENTMSG, got, NULL, &newborn) < 0 ||
                record((pid_t)newborn) < 0) goto fail;
            forks += event == PTRACE_EVENT_FORK;
            vforks += event == PTRACE_EVENT_VFORK;
            clones += event == PTRACE_EVENT_CLONE;
        } else if (event == PTRACE_EVENT_EXEC) {
            unsigned long previous = 0;
            if (ptrace(PTRACE_GETEVENTMSG, got, NULL, &previous) < 0) goto fail;
            /* This fixture never execs from a nonleader thread. Reject that
             * identity transition instead of producing incomplete counts. */
            if (previous && previous != (unsigned long)got) { errno = ENOTSUP; goto fail; }
            execs++;
        }
        int signal = event || WSTOPSIG(status) == SIGSTOP ? 0 : WSTOPSIG(status);
        if (ptrace(PTRACE_CONT, got, NULL, signal) < 0) goto fail;
    }
    if (result < 0 || count != 1 + forks + vforks + clones) { errno = EINVAL; goto fail; }
    FILE *out = fopen(argv[1], "wx");
    if (!out) goto fail;
    int failed = fprintf(out,
        "{\"schema\":1,\"method\":\"ptrace\",\"exit\":%d,"
        "\"processes\":%u,\"threads\":%u,\"additional_threads\":%u,"
        "\"peak_live_tasks\":%u,\"live_remaining\":%u,"
        "\"fork_events\":%u,\"vfork_events\":%u,\"clone_events\":%u,\"exec_events\":%u}\n",
        result, processes, count, count - processes, peak, live, forks, vforks, clones, execs) < 0;
    if (fclose(out)) failed = 1;
    return failed ? 2 : result;
fail:
    perror("task lifecycle probe");
    /* EXITKILL kills every attached task on exit, including descendants. */
    kill(child, SIGKILL);
    return 2;
}
