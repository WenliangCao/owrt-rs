/* Keep raw ubus connections alive after one valid PING frame. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void on_signal(int signal_number) { (void)signal_number; stop = 1; }
static void require(int ok, const char *message) {
    if (!ok) { fprintf(stderr, "%s\n", message); exit(1); }
}
static unsigned number(const char *s, unsigned max) {
    char *end; errno = 0; unsigned long n = strtoul(s, &end, 10);
    require(*s && !*end && !errno && n <= max, "invalid numeric argument");
    return (unsigned)n;
}
static int connect_socket(const char *path) {
    struct sockaddr_un address = {0};
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    require(fd >= 0, "socket failed");
    address.sun_family = AF_UNIX;
    require(strlen(path) < sizeof(address.sun_path), "socket path too long");
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd); perror("connect"); exit(1);
    }
    return fd;
}
static void send_ping(int fd, unsigned seq) {
    unsigned char frame[12] = {
        0, 3, (unsigned char)(seq >> 8), (unsigned char)seq,
        0, 0, 0, 0, 0, 0, 0, 4,
    };
    size_t sent = 0;
    while (sent < sizeof(frame)) {
        ssize_t n = send(fd, frame + sent, sizeof(frame) - sent, 0);
        require(n > 0, "PING send failed");
        sent += (size_t)n;
    }
}
int main(int argc, char **argv) {
    if (argc >= 4 && !strcmp(argv[1], "exec-cpu")) {
        unsigned cpu = number(argv[2], 1); cpu_set_t set;
        CPU_ZERO(&set); CPU_SET(cpu, &set);
        require(!sched_setaffinity(0, sizeof(set), &set), "exec pin failed");
        execvp(argv[3], &argv[3]); perror("execvp"); return 1;
    }
    require(argc == 5 && !strcmp(argv[1], "rx-idle"),
            "usage: rx-idle SOCKET CLIENTS HOLD_SECONDS");
    unsigned clients = number(argv[3], 512);
    unsigned hold_seconds = number(argv[4], 30);
    require(clients > 0 && hold_seconds > 0, "invalid client count or hold time");
    int *fds = calloc(clients, sizeof(*fds));
    require(fds != NULL, "fd array allocation failed");
    for (unsigned i = 0; i < clients; i++) {
        fds[i] = connect_socket(argv[2]);
        send_ping(fds[i], i);
    }
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal);
    printf("{\"clients\":%u,\"ping_frames_sent\":%u,\"holding\":true}\n", clients, clients);
    fflush(stdout);
    for (unsigned i = 0; i < hold_seconds * 10 && !stop; i++) usleep(100000);
    for (unsigned i = 0; i < clients; i++) close(fds[i]);
    free(fds); return 0;
}
