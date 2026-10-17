/* Small measurement helper: a pre-exec clock marker and a plain UDP echo.
 * Build on Linux: cc -O2 -Wall -Wextra -Werror -o HELPER this-file.c
 * Run only in the latency fixture's private namespaces. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fail(const char *operation)
{
    perror(operation);
    return 1;
}

static uint64_t nanoseconds(struct timespec time)
{
    return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

static int launch(int argc, char **argv)
{
    if (argc < 5)
        return 2;
    int marker = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker < 0)
        return fail("open marker");
    if (chroot(argv[2]) || chdir("/"))
        return fail("private chroot");
    struct timespec stamp;
    if (clock_gettime(CLOCK_MONOTONIC, &stamp))
        return fail("clock_gettime");
    char buffer[32];
    int length = snprintf(buffer, sizeof(buffer), "%" PRIu64 "\n", nanoseconds(stamp));
    if (write(marker, buffer, (size_t)length) != length || close(marker))
        return fail("write marker");
    /* Timestamp includes this one marker write/close and execv. No chroot,
     * namespace construction or parent Python process creation is timed. */
    execv(argv[4], &argv[4]);
    return fail("exec daemon");
}

static int echo(const char *device, const char *port_text, const char *count_text)
{
    char *end;
    long port = strtol(port_text, &end, 10);
    if (*end || port < 1 || port > 65535)
        return 2;
    long count = strtol(count_text, &end, 10);
    if (*end || count < 1 || count > 32)
        return 2;
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return fail("socket");
    int one = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) ||
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1))
        return fail("setsockopt");
    struct sockaddr_in6 address = { .sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port) };
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)))
        return fail("bind");
    puts("{\"ready\":true}");
    fflush(stdout);
    alarm(15);
    for (long i = 0; i < count; ++i) {
        unsigned char buffer[4096];
        struct sockaddr_in6 peer;
        socklen_t peer_length = sizeof(peer);
        ssize_t length;
        do {
            length = recvfrom(fd, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&peer, &peer_length);
        } while (length < 0 && errno == EINTR);
        if (length < 0)
            return fail("recvfrom");
        if (sendto(fd, buffer, (size_t)length, 0,
                   (struct sockaddr *)&peer, peer_length) != length)
            return fail("sendto");
    }
    return close(fd) ? fail("close") : 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "clock")) {
        struct timespec resolution, current;
        if (clock_getres(CLOCK_MONOTONIC, &resolution) ||
            clock_gettime(CLOCK_MONOTONIC, &current))
            return fail("clock");
        printf("{\"resolution_ns\":%" PRIu64 ",\"current_ns\":%" PRIu64 "}\n",
               nanoseconds(resolution), nanoseconds(current));
        return 0;
    }
    if (argc >= 5 && !strcmp(argv[1], "launch"))
        return launch(argc, argv);
    if (argc == 5 && !strcmp(argv[1], "echo"))
        return echo(argv[2], argv[3], argv[4]);
    fprintf(stderr, "usage: %s clock | launch ROOT MARKER COMMAND [ARG...] | echo DEVICE PORT COUNT\n", argv[0]);
    return 2;
}
