/* Excluded readiness count screen; no product behavior or timing acceptance.
 * MODE ITERATIONS [FDS [READY_INDEX]]; old two-argument cases retain one UDP fd.
 * FDS is 1, 6 or 14. ready-wait is already ready with a nonzero timeout;
 * deferred uses one periodic timerfd plus idle UDP fds, not a socket workload.
 * External perf counts include setup/cleanup. Deferred prechecks and timer
 * reads are fixed extra work: compare cardinalities within the same mode. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Build this count screen without NDEBUG: assertions perform required I/O."
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

static unsigned number(const char *value) {
    char *end;
    errno = 0;
    unsigned long result = strtoul(value, &end, 10);
    assert(value[0] && !*end && !errno && result <= UINT_MAX);
    return (unsigned)result;
}

static int wait_ready(struct pollfd *fds, unsigned count,
                      const struct timespec *timeout, unsigned *interrupts) {
    for (;;) {
        int result = ppoll(fds, count, timeout, NULL);
        if (result >= 0 || errno != EINTR) return result;
        ++*interrupts;
    }
}

int main(int argc, char **argv) {
    assert(argc >= 3 && argc <= 5);
    unsigned iterations = number(argv[2]);
    unsigned count = argc >= 4 ? number(argv[3]) : 1;
    unsigned selected = argc >= 5 ? number(argv[4]) : 0;
    int skip = strcmp(argv[1], "skip") == 0;
    int ready_wait = strcmp(argv[1], "ready-wait") == 0;
    int ready = strcmp(argv[1], "ready") == 0 || ready_wait;
    int deferred = strcmp(argv[1], "deferred") == 0;
    assert(iterations && iterations <= 1000000);
    assert(count == 1 || count == 6 || count == 14);
    assert(selected < count && (!deferred || iterations <= 10000));
    assert(skip || ready || deferred || strcmp(argv[1], "empty") == 0);
    struct pollfd interests[14] = {0};
    for (unsigned i = 0; i < count; ++i) {
        int fd;
        if (deferred && i == selected) {
            fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        } else {
            fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
            assert(fd >= 0);
            struct sockaddr_in address = {
                .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
            };
            assert(bind(fd, (struct sockaddr *)&address, sizeof address) == 0);
            if (ready && i == selected) {
                socklen_t size = sizeof address;
                assert(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
                assert(sendto(fd, "x", 1, 0, (struct sockaddr *)&address, sizeof address) == 1);
            }
        }
        assert(fd >= 0);
        for (unsigned old = 0; old < i; ++old) assert(interests[old].fd != fd);
        interests[i] = (struct pollfd){.fd = fd, .events = POLLIN};
    }

    const struct timespec immediate = {0}, finite = {.tv_sec = 1};
    const struct timespec *timeout = deferred ? NULL : ready_wait ? &finite : &immediate;
    struct itimerspec timer = {.it_interval = {.tv_nsec = 1000000},
                              .it_value = {.tv_nsec = 1000000}};
    if (deferred) assert(timerfd_settime(interests[selected].fd, 0, &timer, NULL) == 0);
    struct rusage before, after;
    assert(getrusage(RUSAGE_SELF, &before) == 0);
    unsigned observed = 0, interrupts = 0, early_ready = 0, not_ready = 0, coalesced = 0;
    uint64_t expirations = 0, maximum_expirations = 0;
    for (unsigned i = 0; i < iterations; ++i) {
        if (skip) {
            __asm__ volatile("" : "+m" (interests) : : "memory");
            for (unsigned j = 0; j < count; ++j) observed += interests[j].revents != 0;
        } else {
            if (deferred) {
                struct pollfd probe = {.fd = interests[selected].fd, .events = POLLIN};
                int available = wait_ready(&probe, 1, &immediate, &interrupts);
                assert(available == 0 || (available == 1 && probe.revents == POLLIN));
                early_ready += available == 1;
                not_ready += available == 0;
            }
            int found = wait_ready(interests, count, timeout, &interrupts);
            assert(found == (ready || deferred));
            if (ready || deferred) assert(interests[selected].revents == POLLIN);
            observed += found;
            if (deferred) {
                uint64_t ticks;
                ssize_t got;
                do { got = read(interests[selected].fd, &ticks, sizeof ticks); }
                while (got < 0 && errno == EINTR);
                assert(got == (ssize_t)sizeof ticks && ticks > 0);
                expirations += ticks;
                if (ticks > maximum_expirations) maximum_expirations = ticks;
                coalesced += ticks > 1;
            }
        }
    }
    assert(getrusage(RUSAGE_SELF, &after) == 0);
    assert(observed == ((ready || deferred) ? iterations : 0));
    if (deferred) {
        assert(early_ready + not_ready == iterations && expirations >= iterations);
        timer = (struct itimerspec){0};
        assert(timerfd_settime(interests[selected].fd, 0, &timer, NULL) == 0);
    }
    for (unsigned i = 0; i < count; ++i) assert(close(interests[i].fd) == 0);
    printf("{\"mode\":\"%s\",\"iterations\":%u,\"ready_results\":%u,"
           "\"fds\":%u,\"ready_index\":%u,\"poll_interrupts\":%u,"
           "\"precheck_ready\":%u,\"precheck_not_ready\":%u,"
           "\"timer_period_ns\":%u,\"timer_expirations\":%" PRIu64 ","
           "\"coalesced_reads\":%u,\"maximum_expirations\":%" PRIu64 ","
           "\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld,"
           "\"timing_eligible\":false}\n",
           argv[1], iterations, observed, count, selected, interrupts, early_ready, not_ready,
           deferred ? 1000000U : 0U, expirations, coalesced, maximum_expirations,
           after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw);
}
