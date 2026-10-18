/* Minimal Linux namespace launcher for an OpenWrt image without util-linux
 * unshare. The command is PID 2, never PID 1; the namespace init's exit
 * destroys every descendant, including daemons that call setsid().
 * Build with the matching OpenWrt SDK: $CC -Os -static -Wall -Wextra -Werror.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what) { perror(what); exit(125); }
static int status_code(int status) {
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

int main(int argc, char **argv) {
    pid_t init, command, reaped, owner;
    int lifetime[2];
    int status;
    if (argc < 2) { fputs("usage: ns-exec COMMAND [ARGS...]\n", stderr); return 125; }
    /* Preserve ownership all the way to the caller, not only from this
     * launcher to namespace PID 1. A dead controller must not leave its
     * namespace running until an external watchdog reaches its deadline. */
    owner = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGKILL)) die("owner pdeathsig");
    if (getppid() != owner) return 125;
    if (unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS)) die("unshare");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("private mounts");
    if (pipe2(lifetime, O_CLOEXEC | O_NONBLOCK)) die("lifetime pipe");
    init = fork();
    if (init < 0) die("fork init");
    if (init != 0) {
        close(lifetime[0]);
        do { reaped = waitpid(init, &status, 0); } while (reaped < 0 && errno == EINTR);
        if (reaped < 0) die("wait init");
        return status_code(status);
    }
    close(lifetime[1]);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL)) die("pdeathsig");
    /* getppid() is 0 for an outside parent whether alive or dead. An EOF on
     * the parent's pipe closes the race where it died before prctl(). */
    char unused;
    ssize_t alive = read(lifetime[0], &unused, 1);
    if (alive == 0) return 125;
    if (alive != -1 || errno != EAGAIN) die("parent lifetime check");
    close(lifetime[0]);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL)) die("mount proc");
    command = fork();
    if (command < 0) die("fork command");
    if (command == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL)) die("command pdeathsig");
        if (getppid() != 1) return 125;
        if (setenv("OWRT_BENCH_NAMESPACE", "1", 1)) die("setenv");
        execvp(argv[1], argv + 1); die("exec command");
    }
    do { reaped = waitpid(-1, &status, 0); }
    while ((reaped > 0 && reaped != command) || (reaped < 0 && errno == EINTR));
    if (reaped < 0) die("wait command");
    return status_code(status);
}
