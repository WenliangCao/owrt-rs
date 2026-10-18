/* Static device-side instrument; run only through odhcpd_device_probe.sh.
 * No network configuration here. The private bridge has no physical ports.
 * First RA is AF_PACKET outgoing capture, not delivery to a remote client.
 * Build on Linux: cc -O2 -static -Wall -Wextra -Werror -o PROBE this-file.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAPACITY 8192
static pid_t daemon_pid = -1;
static unsigned index_number;
static struct in6_addr client_address, server_address;

static void cleanup(void) {
    if (daemon_pid > 0) {
        kill(daemon_pid, SIGTERM);
        for (unsigned i = 0; i < 50; i++) {
            if (waitpid(daemon_pid, NULL, WNOHANG) == daemon_pid) return;
            struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL);
        }
        kill(daemon_pid, SIGKILL);
        while (waitpid(daemon_pid, NULL, 0) < 0 && errno == EINTR) {}
    }
}
static void die(const char *message) { perror(message); exit(1); }
static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(1); }
}
static uint64_t nanoseconds(struct timespec t) {
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) die("clock_gettime");
    return nanoseconds(t);
}
static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void put16(unsigned char *p, unsigned value) { p[0] = (unsigned char)(value >> 8); p[1] = (unsigned char)value; }
static void set_int(int fd, int level, int option, int value) {
    if (setsockopt(fd, level, option, &value, sizeof(value))) die("setsockopt");
}
static void hex(const unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}
static int readable(int fd, uint64_t deadline) {
    for (;;) {
        uint64_t stamp = now();
        if (stamp >= deadline) return 0;
        int milliseconds = (int)((deadline - stamp + 999999) / 1000000);
        struct pollfd p = {fd, POLLIN, 0};
        int result = poll(&p, 1, milliseconds);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) die("poll");
        if (result && (p.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            errno = EIO; die("socket poll error");
        }
        if (result && (p.revents & POLLIN)) return 1;
    }
}
static struct sockaddr_in6 endpoint(const char *text, unsigned port) {
    struct sockaddr_in6 address = { .sin6_family = AF_INET6,
        .sin6_port = htons((uint16_t)port), .sin6_scope_id = index_number };
    require(inet_pton(AF_INET6, text, &address.sin6_addr) == 1, "invalid fixed IPv6 address");
    return address;
}
static int client_socket(int protocol) {
    int kind = protocol == IPPROTO_ICMPV6 ? SOCK_RAW : SOCK_DGRAM;
    int fd = socket(AF_INET6, kind | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    if (fd < 0) die("client socket");
    set_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1);
    set_int(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1);
    set_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (int)index_number);
    set_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1);
    set_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255);
    if (protocol == IPPROTO_ICMPV6) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
        if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter))) die("ICMP filter");
    }
    struct sockaddr_in6 address = endpoint("fe80::2", protocol == IPPROTO_UDP ? 546 : 0);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) die("client bind");
    return fd;
}
static int capture_socket(void) {
    /* dev_queue_xmit_nit delivers outgoing frames to ETH_P_ALL listeners. */
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) die("AF_PACKET socket");
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)index_number};
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) die("AF_PACKET bind");
    return fd;
}
static void first_ra(int fd, uint64_t start) {
    unsigned char bytes[CAPACITY];
    uint64_t deadline = start + UINT64_C(5000000000);
    while (readable(fd, deadline)) {
        struct sockaddr_ll source;
        socklen_t size = sizeof(source);
        ssize_t length = recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&source, &size);
        uint64_t received = now();
        if (length < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (length < 0) die("AF_PACKET receive");
        if (length < 70 || source.sll_ifindex != (int)index_number || source.sll_pkttype != PACKET_OUTGOING
            || be16(bytes + 12) != ETH_P_IPV6 || bytes[14] >> 4 != 6
            || bytes[20] != IPPROTO_ICMPV6 || bytes[21] != 255
            || memcmp(bytes + 22, &server_address, 16) || bytes[54] != ND_ROUTER_ADVERT) continue;
        require((size_t)length >= 54u + be16(bytes + 18), "truncated captured RA");
        printf("{\"kind\":\"first_ra\",\"start_ns\":%" PRIu64 ",\"received_ns\":%" PRIu64
            ",\"elapsed_ns\":%" PRIu64 ",\"capture\":\"AF_PACKET/PACKET_OUTGOING/br-lan\",\"hex\":\"",
            start, received, received - start);
        hex(bytes + 54, be16(bytes + 18)); puts("\"}"); fflush(stdout);
        return;
    }
    require(0, "no outgoing first RA within 5 seconds");
}
static size_t receive6(int fd, unsigned char *bytes, struct sockaddr_in6 *source,
                       struct in6_addr *destination, int *hop_limit, uint64_t deadline,
                       uint64_t *received) {
    while (readable(fd, deadline)) {
        union { struct cmsghdr alignment; unsigned char bytes[128]; } control;
        struct iovec iov = {bytes, CAPACITY};
        struct msghdr message = {.msg_name = source, .msg_namelen = sizeof(*source),
            .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
            .msg_controllen = sizeof(control.bytes)};
        ssize_t length = recvmsg(fd, &message, 0);
        *received = now();
        if (length < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (length < 0) die("client recvmsg");
        require(!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)), "truncated client reply");
        unsigned ingress = 0;
        *hop_limit = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO
                && c->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
                struct in6_pktinfo packet;
                memcpy(&packet, CMSG_DATA(c), sizeof(packet));
                ingress = packet.ipi6_ifindex; *destination = packet.ipi6_addr;
            } else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT
                       && c->cmsg_len == CMSG_LEN(sizeof(int))) memcpy(hop_limit, CMSG_DATA(c), sizeof(int));
        }
        /* Local-unicast delivery may use lo. Destination binding, source and
         * private namespace are checked; report this path instead of claiming
         * a separate LAN client's ingress latency. */
        require(ingress != 0, "reply missing packet info");
        if (memcmp(destination, &client_address, 16) || memcmp(&source->sin6_addr, &server_address, 16)) continue;
        return (size_t)length;
    }
    require(0, "reply timed out"); return 0;
}
static void send6(int fd, const unsigned char *bytes, size_t length, struct sockaddr_in6 destination) {
    if (sendto(fd, bytes, length, 0, (struct sockaddr *)&destination, sizeof(destination)) != (ssize_t)length)
        die("client sendto");
}
static void rs_reply(int fd) {
    unsigned char bytes[CAPACITY], rs[8] = {133};
    uint64_t start = now();
    send6(fd, rs, sizeof(rs), endpoint("ff02::2", 0));
    uint64_t received;
    struct sockaddr_in6 source;
    struct in6_addr destination;
    int hop_limit;
    size_t length = receive6(fd, bytes, &source, &destination, &hop_limit,
        start + UINT64_C(3000000000), &received);
    require(length >= 16 && bytes[0] == 134 && bytes[1] == 0 && hop_limit == 255, "invalid RS reply");
    printf("{\"kind\":\"rs\",\"start_ns\":%" PRIu64 ",\"received_ns\":%" PRIu64
        ",\"elapsed_ns\":%" PRIu64 ",\"hex\":\"", start, received, received - start);
    hex(bytes, length); puts("\"}"); fflush(stdout);
}
static const unsigned char *option(const unsigned char *bytes, size_t length, unsigned type, size_t *size) {
    while (length) {
        require(length >= 4, "truncated DHCP option header");
        size_t amount = be16(bytes + 2);
        require(amount <= length - 4, "truncated DHCP option value");
        if (be16(bytes) == type) { *size = amount; return bytes + 4; }
        bytes += 4 + amount; length -= 4 + amount;
    }
    return NULL;
}
static size_t add_option(unsigned char *bytes, size_t at, unsigned type, const void *value, size_t length) {
    require(at + 4 + length <= CAPACITY && length <= UINT16_MAX, "DHCP request exceeds capacity");
    put16(bytes + at, type); put16(bytes + at + 2, (unsigned)length);
    memcpy(bytes + at + 4, value, length); return at + 4 + length;
}
static size_t exchange(int fd, unsigned char *request, size_t size, unsigned response_type,
                       unsigned client, const char *kind, unsigned char *reply) {
    uint64_t start = now(), received;
    send6(fd, request, size, endpoint("ff02::1:2", 547));
    uint64_t deadline = start + UINT64_C(3000000000);
    struct sockaddr_in6 source;
    struct in6_addr destination;
    int hop_limit;
    for (;;) {
        size_t length = receive6(fd, reply, &source, &destination, &hop_limit, deadline, &received);
        if (length < 4 || reply[0] != response_type || memcmp(reply + 1, request + 1, 3)) continue;
        require(source.sin6_port == htons(547), "wrong DHCP server port");
        size_t amount;
        const unsigned char *ia = option(reply + 4, length - 4, 3, &amount);
        require(ia && amount >= 12, "reply omitted IA_NA");
        size_t sub_size;
        const unsigned char *status = option(ia + 12, amount - 12, 13, &sub_size);
        require(!status || (sub_size >= 2 && be16(status) == 0), "DHCP IA failure status");
        const unsigned char *address = option(ia + 12, amount - 12, 5, &sub_size);
        require(address && sub_size == 24, "reply has no IA_ADDR");
        printf("{\"kind\":\"%s\",\"client\":%u,\"start_ns\":%" PRIu64
            ",\"received_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"hex\":\"",
            kind, client, start, received, received - start);
        hex(reply, length); puts("\"}"); fflush(stdout);
        return length;
    }
}
static void bind_client(int fd, unsigned client) {
    unsigned char request[CAPACITY] = {1, 0x12, 0x30, 0}, reply[CAPACITY];
    unsigned char duid[10] = {0, 3, 0, 1, 2, 0, 0, 0, 0, 0};
    unsigned char ia[12] = {0};
    duid[9] = (unsigned char)(client + 2); ia[3] = (unsigned char)(client + 1);
    request[3] = (unsigned char)client;
    size_t length = add_option(request, 4, 1, duid, sizeof(duid));
    length = add_option(request, length, 3, ia, sizeof(ia));
    size_t response = exchange(fd, request, length, 2, client, "advertise", reply);
    size_t server_length, ia_length;
    const unsigned char *server = option(reply + 4, response - 4, 2, &server_length);
    const unsigned char *offered = option(reply + 4, response - 4, 3, &ia_length);
    require(server && server_length >= 2 && offered && ia_length >= 12, "invalid Advertise identity");
    request[0] = 3; request[2] = 0x40;
    length = add_option(request, 4, 1, duid, sizeof(duid));
    length = add_option(request, length, 2, server, server_length);
    length = add_option(request, length, 3, offered, ia_length);
    exchange(fd, request, length, 7, client, "request", reply);
}
static void memory(void) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)daemon_pid);
    FILE *file = fopen(path, "r");
    if (!file) die("daemon status");
    unsigned rss = 0, anon = 0;
    while (fgets(line, sizeof(line), file)) {
        unsigned value;
        if (sscanf(line, "VmRSS: %u kB", &value) == 1) rss = value;
        if (sscanf(line, "RssAnon: %u kB", &value) == 1) anon = value;
    }
    fclose(file);
    require(rss != 0 && kill(daemon_pid, 0) == 0, "daemon is not resident");
    printf("{\"kind\":\"memory\",\"stage\":\"three_bound_na\",\"pid\":%ld,\"rss_kib\":%u,\"rss_anon_kib\":%u}\n", (long)daemon_pid, rss, anon);
}
int main(int argc, char **argv) {
    require(argc == 2, "usage: odhcpd-device-probe /tmp/bench/subject");
    require(getenv("OWRT_BENCH_NAMESPACE") && !strcmp(getenv("OWRT_BENCH_NAMESPACE"), "1"), "private namespace required");
    atexit(cleanup); alarm(20);
    index_number = if_nametoindex("br-lan");
    require(index_number != 0, "private bridge missing");
    require(inet_pton(AF_INET6, "fe80::2", &client_address) == 1
        && inet_pton(AF_INET6, "fe80::1", &server_address) == 1, "address parsing");
    int capture = capture_socket(), raw = client_socket(IPPROTO_ICMPV6), udp = client_socket(IPPROTO_UDP);
    struct timespec resolution, quiet = {1, 0};
    if (clock_getres(CLOCK_MONOTONIC, &resolution) || nanosleep(&quiet, NULL)) die("quiet/clock");
    int marker[2];
    if (pipe2(marker, O_CLOEXEC)) die("marker pipe");
    daemon_pid = fork();
    if (daemon_pid < 0) die("fork daemon");
    if (daemon_pid == 0) {
        close(marker[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() == 1) _exit(125);
        int log = open("/tmp/out/daemon.log", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0) _exit(125);
        close(log);
        uint64_t start = now();
        if (write(marker[1], &start, sizeof(start)) != sizeof(start)) _exit(125);
        close(marker[1]);
        execl(argv[1], argv[1], "-u", "-f", "-c", "/etc/config", (char *)NULL);
        _exit(125);
    }
    close(marker[1]);
    uint64_t start;
    require(read(marker[0], &start, sizeof(start)) == sizeof(start), "missing exec marker");
    close(marker[0]);
    printf("{\"kind\":\"instrument\",\"resolution_ns\":%" PRIu64 ",\"exec_start_ns\":%" PRIu64
        ",\"pid\":%ld,\"ifindex\":%u,\"path\":\"empty_bridge_local_client\"}\n",
        nanoseconds(resolution), start, (long)daemon_pid, index_number); fflush(stdout);
    first_ra(capture, start);
    rs_reply(raw);
    for (unsigned client = 0; client < 3; client++) bind_client(udp, client);
    struct timespec settle = {0, 20000000};
    if (nanosleep(&settle, NULL)) die("memory settle");
    memory();
    puts("{\"kind\":\"complete\",\"three_na_bound\":true}"); fflush(stdout);
    close(capture); close(raw); close(udp);
    return 0;
}
