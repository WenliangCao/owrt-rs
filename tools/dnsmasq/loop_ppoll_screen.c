/* Excluded count-only upper-cost screen for one zero-timeout UDP interest.
 * No service timing, sleeps, or product behavior are changed. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    assert(argc == 3);
    unsigned iterations = strtoul(argv[2], NULL, 10);
    int skip = strcmp(argv[1], "skip") == 0;
    int ready = strcmp(argv[1], "ready") == 0;
    assert(iterations && (skip || ready || strcmp(argv[1], "empty") == 0));
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)&address, sizeof address) == 0);
    if (ready) {
        socklen_t size = sizeof address;
        assert(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
        assert(sendto(fd, "x", 1, 0, (struct sockaddr *)&address, sizeof address) == 1);
    }
    struct pollfd interest = {.fd = fd, .events = POLLIN};
    const struct timespec timeout = {0};
    unsigned observed = 0;
    for (unsigned i = 0; i < iterations; ++i) {
        if (skip) {
            __asm__ volatile("" : "+m" (interest) : : "memory");
            observed += interest.revents != 0;
        } else {
            int count = ppoll(&interest, 1, &timeout, NULL);
            assert(count == ready);
            observed += count;
        }
    }
    assert(observed == (ready ? iterations : 0));
    close(fd);
    printf("{\"mode\":\"%s\",\"iterations\":%u,\"ready_results\":%u}\n", argv[1], iterations, observed);
}
