/* Training-only replacement for device_perf_lifecycle.c's end_child block.
 * The caller freezes both this fragment and the original source hash. */
static int record_child_exit(pid_t own, int status, int error, int forced)
{
    int exited = !error && WIFEXITED(status);
    int signalled = !error && WIFSIGNALED(status);
    int code = exited ? WEXITSTATUS(status) : -1;
    fprintf(stderr, "pgo_child_exit {\"pid\":%ld,\"wait_status\":%d,\"wait_errno\":%d,"
            "\"exited\":%s,\"exit_code\":%d,\"signal\":%d,\"forced\":%s}\n",
            (long)own, status, error, exited ? "true" : "false", code,
            signalled ? WTERMSIG(status) : 0, forced ? "true" : "false");
    child = -1;
    return !forced && !error && exited && code == 0;
}

static int end_child(void)
{
    if (child <= 0) return 1;
    pid_t own = child;
    /* This is the same unreaped direct child and two-second TERM grace. */
    kill(own, SIGTERM);
    uint64_t end = now_ns() + 2 * NS;
    int status = -1;
    for (;;) {
        pid_t result = waitpid(own, &status, WNOHANG);
        if (result == own) return record_child_exit(own, status, 0, 0);
        if (result < 0 && errno != EINTR) return record_child_exit(own, -1, errno, 0);
        if (now_ns() >= end) break;
        delay_ns(1000000);
    }
    kill(own, SIGKILL);
    pid_t result;
    do { result = waitpid(own, &status, 0); } while (result < 0 && errno == EINTR);
    return record_child_exit(own, result == own ? status : -1,
                             result == own ? 0 : errno, 1);
}
