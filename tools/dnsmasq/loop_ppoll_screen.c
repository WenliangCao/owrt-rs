/* Excluded readiness count screen; no product behavior or timing acceptance.
 * MODE ITERATIONS [FDS [READY_INDEX [direct|group [CHURN]]]]
 * Old two-argument cases retain one UDP fd. "controls" runs mask/EOF checks.
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
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

static int udp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    assert(bind(fd, (struct sockaddr *)&address, sizeof address) == 0);
    return fd;
}

static void group_ctl(int group, int operation, int fd, uint32_t mask, uint64_t token) {
    struct epoll_event event = {.events = mask, .data.u64 = token};
    assert(epoll_ctl(group, operation, fd, &event) == 0);
}

static void controls(void) {
    int pair[2], group = epoll_create1(EPOLL_CLOEXEC);
    assert(group >= 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    group_ctl(group, EPOLL_CTL_ADD, pair[0], EPOLLIN, 1);
    assert(write(pair[1], "x", 1) == 1);
    struct epoll_event event;
    assert(epoll_wait(group, &event, 1, 0) == 1 && event.data.u64 == 1 && event.events == EPOLLIN);
    /* Leave data unread: level readiness must survive both retrieval and MOD. */
    assert(epoll_wait(group, &event, 1, 0) == 1 && event.events == EPOLLIN);
    group_ctl(group, EPOLL_CTL_MOD, pair[0], EPOLLOUT, 2);
    assert(epoll_wait(group, &event, 1, 0) == 1 && event.data.u64 == 2 && event.events == EPOLLOUT);
    group_ctl(group, EPOLL_CTL_MOD, pair[0], EPOLLIN, 3);
    assert(close(pair[1]) == 0);
    struct pollfd direct = {.fd = pair[0], .events = POLLIN};
    assert(poll(&direct, 1, 0) == 1);
    assert(epoll_wait(group, &event, 1, 0) == 1 && event.data.u64 == 3);
    assert(event.events == (uint32_t)direct.revents && (event.events & EPOLLHUP));
    group_ctl(group, EPOLL_CTL_DEL, pair[0], 0, 0);
    int old = pair[0];
    assert(close(old) == 0);
    assert(epoll_wait(group, &event, 1, 0) == 0);
    int replacement = udp_socket();
    assert(replacement == old); /* Lowest free descriptor, no concurrent opener. */
    group_ctl(group, EPOLL_CTL_ADD, replacement, EPOLLOUT, 4);
    assert(epoll_wait(group, &event, 1, 0) == 1 && event.data.u64 == 4 && event.events == EPOLLOUT);
    group_ctl(group, EPOLL_CTL_DEL, replacement, 0, 0);
    assert(close(replacement) == 0 && close(group) == 0);
    puts("{\"mode\":\"controls\",\"mask_level_eof_close_reuse\":true,\"timing_eligible\":false}");
}

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
    if (argc == 2 && strcmp(argv[1], "controls") == 0) { controls(); return 0; }
    assert(argc >= 3 && argc <= 7);
    unsigned iterations = number(argv[2]);
    unsigned count = argc >= 4 ? number(argv[3]) : 1;
    unsigned selected = argc >= 5 ? number(argv[4]) : 0;
    int grouped = argc >= 6 && strcmp(argv[5], "group") == 0;
    assert(argc < 6 || grouped || strcmp(argv[5], "direct") == 0);
    unsigned churn = argc >= 7 ? number(argv[6]) : 0;
    int skip = strcmp(argv[1], "skip") == 0;
    int ready_wait = strcmp(argv[1], "ready-wait") == 0;
    int ready = strcmp(argv[1], "ready") == 0 || ready_wait;
    int deferred = strcmp(argv[1], "deferred") == 0;
    assert(iterations && iterations <= 1000000);
    assert(count == 1 || count == 6 || count == 14);
    assert(selected < count && (!deferred || iterations <= 10000));
    assert(!grouped || (count == 14 && selected >= 6 && !skip));
    assert(!churn || (count == 14 && selected >= 6 && churn <= iterations));
    assert(skip || ready || deferred || strcmp(argv[1], "empty") == 0);
    struct pollfd interests[14] = {0};
    for (unsigned i = 0; i < count; ++i) {
        int fd;
        if (deferred && i == selected) {
            fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        } else {
            fd = udp_socket();
            if (ready && i == selected) {
                struct sockaddr_in address;
                socklen_t size = sizeof address;
                assert(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
                assert(sendto(fd, "x", 1, 0, (struct sockaddr *)&address, sizeof address) == 1);
            }
        }
        assert(fd >= 0);
        for (unsigned old = 0; old < i; ++old) assert(interests[old].fd != fd);
        interests[i] = (struct pollfd){.fd = fd, .events = POLLIN};
    }

    int group = grouped ? epoll_create1(EPOLL_CLOEXEC) : -1;
    unsigned adds = 0, deletes = 0, extracts = 0, replaced = 0, reuse = 0;
    uint64_t generations[14] = {0};
    struct pollfd outer[7] = {0};
    if (grouped) {
        assert(group >= 0);
        memcpy(outer, interests, 6 * sizeof *interests);
        outer[6] = (struct pollfd){.fd = group, .events = POLLIN};
        for (unsigned i = 6; i < 14; ++i) {
            generations[i] = 1;
            group_ctl(group, EPOLL_CTL_ADD, interests[i].fd, EPOLLIN, (generations[i] << 8) | i);
            ++adds;
        }
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
            int found = wait_ready(grouped ? outer : interests, grouped ? 7 : count, timeout, &interrupts);
            assert(found == (ready || deferred));
            if (grouped && found) {
                assert(outer[6].revents == POLLIN);
                struct epoll_event event[8];
                int received;
                do { received = epoll_wait(group, event, 8, 0); ++extracts; }
                while (received < 0 && errno == EINTR);
                assert(received == 1 && event[0].events == EPOLLIN);
                assert(event[0].data.u64 == ((generations[selected] << 8) | selected));
            } else if (ready || deferred) assert(interests[selected].revents == POLLIN);
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
        if (churn && (uint64_t)(i + 1) * churn / iterations > (uint64_t)i * churn / iterations) {
            unsigned slot = 6 + replaced % 8;
            if (slot == selected) slot = 6 + (slot - 6 + 1) % 8;
            int old = interests[slot].fd;
            if (grouped) { group_ctl(group, EPOLL_CTL_DEL, old, 0, 0); ++deletes; }
            assert(close(old) == 0);
            interests[slot].fd = udp_socket();
            reuse += interests[slot].fd == old;
            if (grouped) {
                ++generations[slot];
                group_ctl(group, EPOLL_CTL_ADD, interests[slot].fd, EPOLLIN, (generations[slot] << 8) | slot);
                ++adds;
            }
            ++replaced;
        }
    }
    assert(getrusage(RUSAGE_SELF, &after) == 0);
    assert(observed == ((ready || deferred) ? iterations : 0));
    if (deferred) {
        assert(early_ready + not_ready == iterations && expirations >= iterations);
        timer = (struct itimerspec){0};
        assert(timerfd_settime(interests[selected].fd, 0, &timer, NULL) == 0);
    }
    assert(replaced == churn);
    for (unsigned i = 0; i < count; ++i) {
        if (grouped && i >= 6) { group_ctl(group, EPOLL_CTL_DEL, interests[i].fd, 0, 0); ++deletes; }
        assert(close(interests[i].fd) == 0);
    }
    if (grouped) assert(close(group) == 0);
    printf("{\"mode\":\"%s\",\"iterations\":%u,\"ready_results\":%u,"
           "\"fds\":%u,\"ready_index\":%u,\"poll_interrupts\":%u,"
           "\"precheck_ready\":%u,\"precheck_not_ready\":%u,"
           "\"timer_period_ns\":%u,\"timer_expirations\":%" PRIu64 ","
           "\"coalesced_reads\":%u,\"maximum_expirations\":%" PRIu64 ","
           "\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld,"
           "\"grouped\":%s,\"outer_fds\":%u,\"group_adds\":%u,\"group_deletes\":%u,"
           "\"group_extracts\":%u,\"churn\":%u,\"fd_reuses\":%u,"
           "\"timing_eligible\":false}\n",
           argv[1], iterations, observed, count, selected, interrupts, early_ready, not_ready,
           deferred ? 1000000U : 0U, expirations, coalesced, maximum_expirations,
           after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw,
           grouped ? "true" : "false", grouped ? 7 : count, adds, deletes, extracts, replaced, reuse);
}
