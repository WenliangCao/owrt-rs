/* Bound a diagnostic namespace launcher's lifetime. This never touches the
 * hardware watchdog or production services. The guarded ns-exec owns all its
 * children via a PID namespace and its init's parent-death signal. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid;
static volatile sig_atomic_t interrupted;

static void stop(int sig) {
    int saved = errno;
    interrupted = sig;
    if (child_pid > 0) kill(child_pid, SIGKILL);
    errno = saved;
}

int main(int argc, char **argv) {
    char *end;
    unsigned long seconds;
    pid_t parent, child, reaped;
    int status;
    struct sigaction action = { .sa_handler = stop };
    if (argc < 3) return 64;
    errno = 0;
    seconds = strtoul(argv[1], &end, 10);
    if (errno || *end || seconds == 0 || seconds > 600) return 64;
    sigemptyset(&action.sa_mask);
    for (int i = 0; i < 4; i++) {
        const int signals[] = { SIGALRM, SIGINT, SIGTERM, SIGHUP };
        if (sigaction(signals[i], &action, NULL)) return 125;
    }
    parent = getpid();
    child = fork();
    if (child < 0) return 125;
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
        execvp(argv[2], argv + 2);
        perror("guard exec");
        _exit(127);
    }
    child_pid = child;
    if (interrupted) kill(child, SIGKILL);
    alarm((unsigned)seconds);
    do { reaped = waitpid(child, &status, 0); } while (reaped < 0 && errno == EINTR);
    alarm(0);
    child_pid = 0;
    if (interrupted) return interrupted == SIGALRM ? 124 : 128 + interrupted;
    if (reaped != child) return 125;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
