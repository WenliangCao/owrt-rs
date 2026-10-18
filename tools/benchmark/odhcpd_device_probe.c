/* Static device-side instrument; run only through the private AB driver.
 * No network configuration here. The private bridge has no physical ports.
 * Update RA is AF_PACKET outgoing capture, not delivery to a remote client.
 * RS/DHCP travel through the namespace's local multicast/unicast socket path.
 * Process CPU uses clock_getcpuclockid (all target threads, no child CPU).
 * The fixed per-process protocol and counts are part of the frozen AB plan;
 * neither this program nor the driver selects or retries favorable samples.
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAPACITY 8192
static pid_t daemon_pid = -1, helper_pid = -1;
static clockid_t daemon_clock;
static unsigned index_number;
static struct in6_addr client_address, server_address;
static struct in6_addr last_reply_source;

struct identity { uint64_t start_ticks, exe_dev, exe_ino; };
static struct identity initial_identity;

static void cleanup(void) {
    /* The wrapper owns the daemon; only reap helpers created by this probe. */
    if (helper_pid > 0) {
        kill(helper_pid, SIGTERM);
        for (unsigned i = 0; i < 50; i++) {
            if (waitpid(helper_pid, NULL, WNOHANG) == helper_pid) return;
            struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL);
        }
        kill(helper_pid, SIGKILL);
        while (waitpid(helper_pid, NULL, 0) < 0 && errno == EINTR) {}
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
static void pause_ns(uint64_t duration) {
    struct timespec delay = {(time_t)(duration / UINT64_C(1000000000)), (long)(duration % UINT64_C(1000000000))};
    while (nanosleep(&delay, &delay)) if (errno != EINTR) die("nanosleep");
}
static uint64_t cpu(void) {
    struct timespec stamp;
    if (clock_gettime(daemon_clock, &stamp)) die("daemon process CPU clock");
    return nanoseconds(stamp);
}
static struct identity identity(void) {
    char path[64], line[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)daemon_pid);
    FILE *file = fopen(path, "r");
    if (!file || !fgets(line, sizeof(line), file)) die("daemon stat");
    fclose(file);
    char *cursor = strrchr(line, ')');
    require(cursor != NULL, "invalid daemon stat");
    cursor++;
    char *saved = NULL, *token = strtok_r(cursor, " ", &saved);
    uint64_t start = 0;
    for (unsigned field = 3; token && field <= 22; field++, token = strtok_r(NULL, " ", &saved)) {
        if (field == 3) require(strcmp(token, "Z") && strcmp(token, "X"), "daemon died");
        if (field == 22) start = strtoull(token, NULL, 10);
    }
    require(start != 0, "missing daemon start time");
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)daemon_pid);
    struct stat metadata;
    if (stat(path, &metadata)) die("daemon exe identity");
    return (struct identity){start, (uint64_t)metadata.st_dev, (uint64_t)metadata.st_ino};
}
static void same_process(void) {
    struct identity value = identity();
    require(value.start_ticks == initial_identity.start_ticks && value.exe_dev == initial_identity.exe_dev
        && value.exe_ino == initial_identity.exe_ino, "daemon PID/start/executable changed");
}
static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void put16(unsigned char *p, unsigned value) { p[0] = (unsigned char)(value >> 8); p[1] = (unsigned char)value; }
static void set_int(int fd, int level, int option, int value) {
    if (setsockopt(fd, level, option, &value, sizeof(value))) die("setsockopt");
}
static int private_linklocal(const struct in6_addr *address) {
    /* Both addresses belong to the one private bridge. Linux may select the
     * local client's ::2 as a unicast reply's source (same-address rule).
     * Port/type, transaction/IA identity and payload remain independently
     * validated; this is not presented as a remote client topology. */
    return !memcmp(address, &server_address, 16) || !memcmp(address, &client_address, 16);
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
/* Returns 0 for no queued frame, -1 for a consumed unrelated frame, and the
 * ICMP length for a server RA. No wall-clock decision is taken from a cache. */
static int captured_ra(int fd, unsigned char *bytes, uint64_t *received) {
    unsigned char frame[CAPACITY];
    struct sockaddr_ll source;
    socklen_t size = sizeof(source);
    ssize_t length = recvfrom(fd, frame, sizeof(frame), 0, (struct sockaddr *)&source, &size);
    *received = now();
    if (length < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    if (length < 0) die("AF_PACKET receive");
    struct in6_addr ipv6_source;
    if (length >= 38) memcpy(&ipv6_source, frame + 22, 16);
    if (length < 70 || source.sll_ifindex != (int)index_number || source.sll_pkttype != PACKET_OUTGOING
        || be16(frame + 12) != ETH_P_IPV6 || frame[14] >> 4 != 6
        || frame[20] != IPPROTO_ICMPV6 || frame[21] != 255
        || !private_linklocal(&ipv6_source) || frame[54] != ND_ROUTER_ADVERT) return -1;
    unsigned amount = be16(frame + 18);
    require(amount >= 16 && (size_t)length >= 54u + amount && amount <= CAPACITY, "truncated captured RA");
    memcpy(bytes, frame + 54, amount);
    last_reply_source = ipv6_source;
    return (int)amount;
}
static unsigned drain_capture(int fd) {
    unsigned count = 0;
    unsigned char packet[CAPACITY]; uint64_t stamp;
    for (unsigned i = 0; i < 4096; i++) {
        int length = captured_ra(fd, packet, &stamp);
        if (length == 0) return count;
        if (length > 0) count++;
    }
    require(0, "capture queue did not drain"); return 0;
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
        if (memcmp(destination, &client_address, 16) || !private_linklocal(&source->sin6_addr)) continue;
        last_reply_source = source->sin6_addr;
        return (size_t)length;
    }
    require(0, "reply timed out"); return 0;
}
static void send6(int fd, const unsigned char *bytes, size_t length, struct sockaddr_in6 destination) {
    if (sendto(fd, bytes, length, 0, (struct sockaddr *)&destination, sizeof(destination)) != (ssize_t)length)
        die("client sendto");
}
static void rs_reply(int fd, unsigned index) {
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
    char source_text[INET6_ADDRSTRLEN];
    require(inet_ntop(AF_INET6, &source.sin6_addr, source_text, sizeof(source_text)) != NULL, "RS source format");
    printf("{\"kind\":\"rs\",\"index\":%u,\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64
        ",\"elapsed_ns\":%" PRIu64 ",\"source\":\"%s\",\"hex\":\"", index, start, received, received - start, source_text);
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
                       unsigned client, unsigned index, unsigned ia_kind, const char *kind, unsigned char *reply) {
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
        // Preserve the matching reply even when its status or IA is invalid.
        // An incomplete/failed sample remains evidence and never gets replaced.
        char source_text[INET6_ADDRSTRLEN];
        require(inet_ntop(AF_INET6, &source.sin6_addr, source_text, sizeof(source_text)) != NULL, "DHCP source format");
        printf("{\"kind\":\"%s\",\"index\":%u,\"client\":%u,\"start_ns\":%" PRIu64
            ",\"end_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"source\":\"%s\",\"request_hex\":\"",
            kind, index, client, start, received, received - start, source_text);
        hex(request, size); printf("\",\"hex\":\"");
        hex(reply, length); puts("\"}"); fflush(stdout);
        size_t amount;
        const unsigned char *topstatus = option(reply + 4, length - 4, 13, &amount);
        require(!topstatus || (amount >= 2 && be16(topstatus) == 0), "DHCP top-level failure");
        const unsigned char *ia = option(reply + 4, length - 4, ia_kind, &amount);
        require(ia && amount >= 12 && ia[0] == 0 && ia[1] == 0 && ia[2] == 0 && ia[3] == client + 1,
            "reply omitted or mismatched IA");
        size_t sub_size;
        const unsigned char *status = option(ia + 12, amount - 12, 13, &sub_size);
        require(!status || (sub_size >= 2 && be16(status) == 0), "DHCP IA failure status");
        const unsigned char *address = option(ia + 12, amount - 12, ia_kind == 3 ? 5 : 26, &sub_size);
        require(address && sub_size == (ia_kind == 3 ? 24u : 25u), "reply has no address/prefix");
        size_t valid_offset = ia_kind == 3 ? 20 : 4;
        require(memcmp(address + valid_offset, "\0\0\0\0", 4), "reply lifetime is zero");
        return length;
    }
}
static void bind_client(int fd, unsigned client, unsigned index, unsigned ia_kind) {
    unsigned char request[CAPACITY] = {1, 0x12, 0x30, 0}, reply[CAPACITY];
    unsigned char duid[10] = {0, 3, 0, 1, 2, 0, 0, 0, 0, 0};
    unsigned char ia[12] = {0};
    duid[9] = (unsigned char)(client + 2); ia[3] = (unsigned char)(client + 1);
    request[3] = (unsigned char)index;
    request[1] = (unsigned char)(ia_kind == 25 ? 0x13 : 0x12);
    const unsigned char oro[] = {0, 23, 0, 24, 0, 41, 0, 42};
    unsigned char fqdn[] = {0, 8, 'f','i','x','t','u','r','e','0', 0};
    fqdn[9] = (unsigned char)('0' + client);
    size_t length = add_option(request, 4, 1, duid, sizeof(duid));
    length = add_option(request, length, 6, oro, sizeof(oro));
    length = add_option(request, length, ia_kind, ia, sizeof(ia));
    if (ia_kind == 3) length = add_option(request, length, 39, fqdn, sizeof(fqdn));
    size_t response = exchange(fd, request, length, 2, client, index, ia_kind,
        ia_kind == 3 ? "solicit" : "pd_solicit", reply);
    size_t server_length, ia_length;
    const unsigned char *server = option(reply + 4, response - 4, 2, &server_length);
    const unsigned char *offered = option(reply + 4, response - 4, ia_kind, &ia_length);
    require(server && server_length >= 2 && offered && ia_length >= 12, "invalid Advertise identity");
    request[0] = 3; request[2] = 0x40;
    length = add_option(request, 4, 1, duid, sizeof(duid));
    length = add_option(request, length, 2, server, server_length);
    length = add_option(request, length, 6, oro, sizeof(oro));
    length = add_option(request, length, ia_kind, offered, ia_length);
    if (ia_kind == 3) length = add_option(request, length, 39, fqdn, sizeof(fqdn));
    exchange(fd, request, length, 7, client, index, ia_kind,
        ia_kind == 3 ? "request" : "pd_request", reply);
    if (ia_kind == 3) {
        request[0] = 5; request[2] = 0x50;
        exchange(fd, request, length, 7, client, index, ia_kind, "renew", reply);
    }
}
static void memory(const char *stage) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)daemon_pid);
    FILE *file = fopen(path, "r");
    if (!file) die("daemon status");
    unsigned rss = 0, anon = 0; int have_anon = 0;
    while (fgets(line, sizeof(line), file)) {
        unsigned value;
        if (sscanf(line, "VmRSS: %u kB", &value) == 1) rss = value;
        if (sscanf(line, "RssAnon: %u kB", &value) == 1) { anon = value; have_anon = 1; }
    }
    fclose(file);
    require(rss != 0 && have_anon && kill(daemon_pid, 0) == 0, "daemon memory fields unavailable");
    same_process();
    printf("{\"kind\":\"memory\",\"stage\":\"%s\",\"pid\":%ld,\"rss_kib\":%u,\"rss_anon_kib\":%u}\n", stage, (long)daemon_pid, rss, anon);
}

static int matches_dns(const unsigned char *packet, size_t size, const struct in6_addr *dns) {
    if (size < 16 || packet[0] != 134 || packet[1] != 0) return 0;
    for (size_t at = 16; at < size;) {
        if (size - at < 8 || packet[at + 1] == 0) return 0;
        size_t length = (size_t)packet[at + 1] * 8;
        if (length > size - at) return 0;
        if (packet[at] == 25) {
            for (size_t address = at + 8; address + 16 <= at + length; address += 16)
                if (!memcmp(packet + address, dns, 16)) return 1;
        }
        at += length;
    }
    return 0;
}

static void change_provider(const char *command, unsigned sequence) {
    char argument[16], path[64];
    snprintf(argument, sizeof(argument), "%u", sequence);
    snprintf(path, sizeof(path), "update-%u.log", sequence);
    helper_pid = fork();
    if (helper_pid < 0) die("fork provider command");
    if (helper_pid == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() == 1) _exit(125);
        int log = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0) _exit(125);
        close(log);
        execl(command, command, argument, (char *)NULL);
        _exit(125);
    }
    int status;
    pid_t waited;
    do { waited = waitpid(helper_pid, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == helper_pid, "provider command wait failed");
    helper_pid = -1;
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "provider command failed");
}

static void update(int capture, const char *command, unsigned index) {
    char dns_text[64];
    snprintf(dns_text, sizeof(dns_text), "2001:db8:53::%u", index + 1);
    struct in6_addr dns;
    require(inet_pton(AF_INET6, dns_text, &dns) == 1, "update DNS parsing");
    (void)drain_capture(capture);
    same_process();
    uint64_t before = cpu(), start = now();
    change_provider(command, index + 1);
    unsigned char packet[CAPACITY];
    uint64_t received = 0, deadline = start + UINT64_C(5000000000);
    int length = 0;
    while (readable(capture, deadline)) {
        length = captured_ra(capture, packet, &received);
        if (length > 0 && matches_dns(packet, (size_t)length, &dns)) break;
        length = 0;
    }
    require(length > 0, "no RA containing new provider DNS");
    pause_ns(UINT64_C(1000000));
    uint64_t end = now(), after = cpu();
    require(after >= before && end >= received + UINT64_C(1000000), "invalid update clocks");
    same_process();
    char source_text[INET6_ADDRSTRLEN];
    require(inet_ntop(AF_INET6, &last_reply_source, source_text, sizeof(source_text)) != NULL, "RA source format");
    printf("{\"kind\":\"update\",\"index\":%u,\"start_ns\":%" PRIu64
        ",\"end_ns\":%" PRIu64 ",\"ra_received_ns\":%" PRIu64
        ",\"cpu_before_ns\":%" PRIu64 ",\"cpu_after_ns\":%" PRIu64
        ",\"elapsed_ns\":%" PRIu64 ",\"cpu_ns\":%" PRIu64
        ",\"drain_ns\":1000000,\"dns\":\"%s\",\"source\":\"%s\",\"hex\":\"",
        index, start, end, received, before, after, end - start, after - before, dns_text, source_text);
    hex(packet, (size_t)length); puts("\"}"); fflush(stdout);
}

static void idle(int capture) {
    (void)drain_capture(capture);
    same_process();
    uint64_t before = cpu(), start = now();
    pause_ns(UINT64_C(3000000000));
    uint64_t end = now(), after = cpu();
    unsigned adverts = drain_capture(capture);
    require(after >= before && end - start >= UINT64_C(3000000000), "invalid idle clocks");
    same_process();
    printf("{\"kind\":\"idle\",\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64
        ",\"cpu_before_ns\":%" PRIu64 ",\"cpu_after_ns\":%" PRIu64
        ",\"solicited_count\":0,\"periodic_ra_count\":%u}\n", start, end, before, after, adverts);
    fflush(stdout);
}

static void run(pid_t pid, const char *command, int idle_renew) {
    daemon_pid = pid;
    initial_identity = identity();
    int error = clock_getcpuclockid(daemon_pid, &daemon_clock);
    if (error) { errno = error; die("clock_getcpuclockid"); }
    struct timespec wall_resolution, cpu_resolution;
    if (clock_getres(CLOCK_MONOTONIC, &wall_resolution) || clock_getres(daemon_clock, &cpu_resolution)) die("clock resolution");
    long page_size = sysconf(_SC_PAGESIZE);
    require(page_size > 0, "page size unavailable");
    int capture = capture_socket(), raw = idle_renew ? -1 : client_socket(IPPROTO_ICMPV6);
    int udp = client_socket(IPPROTO_UDP);
    const char *profile_json = idle_renew ? ",\"profile\":\"idle-renew\"" : "";
    printf("{\"kind\":\"instrument\",\"schema_version\":1,\"pid\":%ld,\"start_ticks\":%" PRIu64
        ",\"exe_dev\":%" PRIu64 ",\"exe_ino\":%" PRIu64
        ",\"clock_quantum_ns\":%" PRIu64 ",\"cpu_clock_quantum_ns\":%" PRIu64
        ",\"cpu_clock_kind\":\"process\",\"page_size_bytes\":%ld,\"path\":\"empty_bridge_local_client\"%s}\n",
        (long)pid, initial_identity.start_ticks, initial_identity.exe_dev, initial_identity.exe_ino,
        nanoseconds(wall_resolution), nanoseconds(cpu_resolution), page_size, profile_json);
    fflush(stdout);
    pause_ns(UINT64_C(2000000000));
    idle(capture);
    if (!idle_renew) {
        memory("empty");
        for (unsigned index = 0; index < 16; index++) rs_reply(raw, index);
    }
    for (unsigned index = 0; index < 16; index++) bind_client(udp, index % 3, index, 3);
    // This empty-bridge topology cannot install a PD route through a local
    // client address. Memory population is the actual router's three NA
    // bindings; PD is covered by the separate real-veth functional evidence.
    /* Same one-millisecond post-reply drain on each side, outside latency. */
    pause_ns(UINT64_C(1000000));
    if (!idle_renew) {
        memory("populated");
        for (unsigned index = 0; index < 8; index++) update(capture, command, index);
    }
    same_process();
    printf("{\"kind\":\"complete\",\"schema_version\":1,\"pid\":%ld,\"start_ticks\":%" PRIu64
        ",\"exe_dev\":%" PRIu64 ",\"exe_ino\":%" PRIu64
        ",\"rs_count\":%u,\"dhcp_count_each\":16,\"updates\":%u,\"na_count\":3,\"pd_count\":0%s}\n",
        (long)pid, initial_identity.start_ticks, initial_identity.exe_dev, initial_identity.exe_ino,
        idle_renew ? 0u : 16u, idle_renew ? 0u : 8u, profile_json);
    fflush(stdout);
    close(capture); if (raw >= 0) close(raw); close(udp);
}

static void floor_measurement(void) {
    struct timespec resolution;
    if (clock_getres(CLOCK_MONOTONIC, &resolution)) die("clock resolution");
    for (unsigned index = 0; index < 16; index++) {
        uint64_t start = now(), end = now();
        printf("{\"kind\":\"floor_clock\",\"index\":%u,\"clock_quantum_ns\":%" PRIu64
            ",\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 "}\n",
            index, nanoseconds(resolution), start, end, end - start);
    }
    fflush(stdout);
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) die("echo ready pipe");
    helper_pid = fork();
    if (helper_pid < 0) die("fork echo");
    if (helper_pid == 0) {
        close(ready[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() == 1) _exit(125);
        int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        if (fd < 0) die("echo socket");
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "br-lan", 7)) die("echo bind device");
        struct sockaddr_in6 address = endpoint("::", 15467);
        if (bind(fd, (struct sockaddr *)&address, sizeof(address))) die("echo bind");
        struct ipv6_mreq membership = {.ipv6mr_interface = index_number};
        require(inet_pton(AF_INET6, "ff02::1:2", &membership.ipv6mr_multiaddr) == 1, "echo group");
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &membership, sizeof(membership))) die("echo join");
        if (write(ready[1], "1", 1) != 1) _exit(125);
        close(ready[1]);
        for (unsigned index = 0; index < 16; index++) {
            unsigned char packet[64];
            struct sockaddr_in6 peer; socklen_t peer_size = sizeof(peer);
            ssize_t length;
            do { length = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &peer_size); }
            while (length < 0 && errno == EINTR);
            if (length != sizeof(packet) || sendto(fd, packet, sizeof(packet), 0,
                (struct sockaddr *)&peer, peer_size) != sizeof(packet)) _exit(125);
        }
        close(fd); _exit(0);
    }
    close(ready[1]); char marker;
    require(read(ready[0], &marker, 1) == 1 && marker == '1', "echo ready failed"); close(ready[0]);
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    if (fd < 0) die("echo client socket");
    set_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (int)index_number);
    set_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1);
    struct sockaddr_in6 source = endpoint("fe80::2", 15466);
    if (bind(fd, (struct sockaddr *)&source, sizeof(source))) die("echo client bind");
    for (unsigned index = 0; index < 16; index++) {
        unsigned char sent[64], reply[64];
        memset(sent, (int)index, sizeof(sent));
        uint64_t start = now();
        send6(fd, sent, sizeof(sent), endpoint("ff02::1:2", 15467));
        require(readable(fd, start + UINT64_C(3000000000)), "echo timeout");
        struct sockaddr_in6 peer; socklen_t peer_size = sizeof(peer);
        ssize_t length = recvfrom(fd, reply, sizeof(reply), 0, (struct sockaddr *)&peer, &peer_size);
        uint64_t end = now();
        require(length == sizeof(reply) && !memcmp(sent, reply, sizeof(reply))
            && peer.sin6_port == htons(15467) && private_linklocal(&peer.sin6_addr), "echo payload/peer mismatch");
        char source_text[INET6_ADDRSTRLEN];
        require(inet_ntop(AF_INET6, &peer.sin6_addr, source_text, sizeof(source_text)) != NULL, "echo source format");
        printf("{\"kind\":\"floor_echo\",\"index\":%u,\"start_ns\":%" PRIu64
            ",\"end_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"bytes\":64,\"payload_matches\":true,\"source\":\"%s\",\"request_hex\":\"",
            index, start, end, end - start, source_text);
        hex(sent, sizeof(sent)); printf("\",\"hex\":\""); hex(reply, sizeof(reply)); puts("\"}");
    }
    close(fd);
    int status; pid_t waited;
    do { waited = waitpid(helper_pid, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == helper_pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "echo child failed");
    helper_pid = -1;
    puts("{\"kind\":\"floor_complete\",\"clock_count\":16,\"echo_count\":16}"); fflush(stdout);
}

int main(int argc, char **argv) {
    require(getenv("OWRT_BENCH_NAMESPACE") && !strcmp(getenv("OWRT_BENCH_NAMESPACE"), "1"), "private namespace required");
    require(geteuid() == 0, "root is required inside the private namespace");
    atexit(cleanup); alarm(45);
    index_number = if_nametoindex("br-lan");
    require(index_number != 0, "private bridge missing");
    require(inet_pton(AF_INET6, "fe80::2", &client_address) == 1
        && inet_pton(AF_INET6, "fe80::1", &server_address) == 1, "address parsing");
    if (argc == 2 && !strcmp(argv[1], "floor")) {
        floor_measurement();
    } else if ((argc == 4 && !strcmp(argv[1], "run"))
               || (argc == 3 && !strcmp(argv[1], "run-idle-renew"))) {
        char *end; long pid = strtol(argv[2], &end, 10);
        require(*argv[2] && !*end && pid > 1 && pid <= INT32_MAX, "invalid target PID");
        run((pid_t)pid, argc == 4 ? argv[3] : NULL, argc == 3);
    } else {
        require(0, "usage: odhcpd-device-probe floor | run PID UPDATE_COMMAND | run-idle-renew PID");
    }
    return 0;
}
