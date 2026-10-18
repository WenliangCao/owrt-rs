/* Read-only, bounded RA/DHCPv6 evidence capture. No transmit socket,
 * promiscuous membership, interface configuration or daemon interaction.
 * Ethernet + direct IPv6 headers only; extension/VLAN headers are excluded.
 * Build on Linux: cc -O2 -static -Wall -Wextra -Werror -o CAPTURE this-file.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SNAPLEN 16384
#define BYTE_LIMIT (4u * 1024u * 1024u)
static volatile sig_atomic_t stopped;
static void stop(int number) { stopped = number; }
static void fail(const char *message) { perror(message); exit(1); }
static uint64_t stamp(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) fail("clock_gettime");
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void hex(const unsigned char *p, size_t length) {
    for (size_t i = 0; i < length; i++) printf("%02x", p[i]);
}
static void duid(const unsigned char *packet, size_t length, unsigned code) {
    size_t at = 4;
    while (at + 4 <= length) {
        unsigned type = be16(packet + at), amount = be16(packet + at + 2);
        at += 4;
        if (amount > length - at) break;
        if (type == code) { hex(packet + at, amount); return; }
        at += amount;
    }
}

/* EtherType IPv6; next header ICMPv6/type RA, or UDP 546->547 / 547->546.
 * AF_PACKET ETH_P_ALL is needed to include outgoing reply frames. Filtering
 * is attached before bind; unrelated client data never enters the file. */
static struct sock_filter filter[] = {
    {0x28, 0, 0, 12}, {0x15, 0, 13, ETH_P_IPV6},
    {0x30, 0, 0, 20}, {0x15, 3, 0, 17}, {0x15, 0, 10, 58},
    {0x30, 0, 0, 54}, {0x15, 7, 8, 134},
    {0x28, 0, 0, 54}, {0x15, 0, 2, 546}, {0x28, 0, 0, 56},
    {0x15, 3, 4, 547}, {0x15, 0, 3, 547}, {0x28, 0, 0, 56},
    {0x15, 0, 1, 546}, {0x06, 0, 0, SNAPLEN}, {0x06, 0, 0, 0}
};

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s INTERFACE SECONDS(1..1800) NEW_OUTPUT.pcap\n", argv[0]);
        return 2;
    }
    char *end;
    unsigned long duration = strtoul(argv[2], &end, 10);
    if (!*argv[2] || *end || duration < 1 || duration > 1800 || strlen(argv[1]) >= IF_NAMESIZE) return 2;
    unsigned index = if_nametoindex(argv[1]);
    if (!index) fail("interface index");
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) fail("AF_PACKET");
    struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program))) fail("packet filter");
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled))) fail("packet timestamp");
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = (int)index};
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) fail("packet bind");
    int output = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) fail("create PCAP");
    FILE *pcap = fdopen(output, "wb");
    if (!pcap) fail("PCAP stream");
    const struct { uint32_t magic; uint16_t major, minor; uint32_t zone, sigfigs, snaplen, linktype; }
        header = {0xa1b2c3d4, 2, 4, 0, 0, SNAPLEN, 1};
    if (fwrite(&header, sizeof(header), 1, pcap) != 1 || fflush(pcap)) fail("PCAP header");
    struct sigaction action = {.sa_handler = stop};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) || sigaction(SIGALRM, &action, NULL)) fail("signals");
    uint64_t started = stamp(CLOCK_MONOTONIC), deadline = started + duration * UINT64_C(1000000000);
    alarm((unsigned)duration);
    unsigned count = 0, written = sizeof(header), truncated = 0;
    int quota = 0;
    printf("{\"kind\":\"capture_start\",\"schema\":1,\"pid\":%ld,\"ifindex\":%u,\"duration_seconds\":%lu,\"monotonic_ns\":%" PRIu64
           ",\"realtime_ns\":%" PRIu64 ",\"promiscuous\":false,\"filter\":\"Ethernet direct IPv6 RA or UDP 546-547\"}\n",
           (long)getpid(), index, duration, started, stamp(CLOCK_REALTIME));
    fflush(stdout);
    while (!stopped && stamp(CLOCK_MONOTONIC) < deadline) {
        uint64_t current = stamp(CLOCK_MONOTONIC);
        if (current >= deadline) break;
        int timeout = (int)((deadline - current + 999999) / 1000000);
        if (timeout > 1000) timeout = 1000;
        struct pollfd p = {fd, POLLIN, 0};
        int ready = poll(&p, 1, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || p.revents & (POLLERR | POLLHUP | POLLNVAL)) fail("capture poll");
        if (!(p.revents & POLLIN)) continue;
        for (unsigned burst = 0; burst < 64 && !stopped; burst++) {
            unsigned char frame[SNAPLEN];
            union { struct cmsghdr alignment; unsigned char data[128]; } control;
            struct sockaddr_ll peer;
            struct iovec iov = {frame, sizeof(frame)};
            struct msghdr message = {.msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = control.data, .msg_controllen = sizeof(control.data)};
            ssize_t received = recvmsg(fd, &message, MSG_TRUNC);
            uint64_t mono = stamp(CLOCK_MONOTONIC), wall = stamp(CLOCK_REALTIME), kernel_wall = 0;
            if (received < 0 && (errno == EAGAIN || errno == EINTR)) break;
            if (received < 0) fail("packet receive");
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMPNS && c->cmsg_len == CMSG_LEN(sizeof(struct timespec))) {
                    struct timespec value; memcpy(&value, CMSG_DATA(c), sizeof(value));
                    kernel_wall = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
                }
            }
            if (!kernel_wall || message.msg_flags & MSG_CTRUNC) { errno = EIO; fail("missing packet timestamp"); }
            size_t size = (size_t)received < sizeof(frame) ? (size_t)received : sizeof(frame);
            if (size < 55 || peer.sll_ifindex != (int)index || be16(frame + 12) != ETH_P_IPV6 || frame[14] >> 4 != 6) continue;
            int ra = frame[20] == 58 && frame[54] == 134;
            int dhcp = frame[20] == 17 && size >= 66
                && ((be16(frame + 54) == 546 && be16(frame + 56) == 547)
                    || (be16(frame + 54) == 547 && be16(frame + 56) == 546));
            if (!ra && !dhcp) continue;
            if (count >= 4096 || written + 16 + size > BYTE_LIMIT) { quota = 1; break; }
            int cut = (size_t)received != size || size < 54u + be16(frame + 18);
            truncated += cut;
            uint32_t record[] = {(uint32_t)(kernel_wall / UINT64_C(1000000000)), (uint32_t)(kernel_wall % UINT64_C(1000000000) / 1000), (uint32_t)size, (uint32_t)received};
            if (fwrite(record, sizeof(record), 1, pcap) != 1 || fwrite(frame, size, 1, pcap) != 1 || fflush(pcap)) fail("PCAP record");
            written += 16 + (unsigned)size; count++;
            char source[INET6_ADDRSTRLEN], destination[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, frame + 22, source, sizeof(source)) || !inet_ntop(AF_INET6, frame + 38, destination, sizeof(destination))) fail("IPv6 text");
            printf("{\"kind\":\"%s\",\"number\":%u,\"monotonic_ns\":%" PRIu64 ",\"realtime_ns\":%" PRIu64
                ",\"packet_realtime_ns\":%" PRIu64 ",\"ifindex\":%d,\"packet_type\":%u,\"source\":\"%s\",\"destination\":\"%s\",\"hop_limit\":%u,\"original_bytes\":%zd,\"captured_bytes\":%zu,\"truncated\":%s",
                ra ? "ra" : "dhcpv6", count, mono, wall, kernel_wall, peer.sll_ifindex, peer.sll_pkttype,
                source, destination, frame[21], received, size, cut ? "true" : "false");
            if (dhcp) {
                size_t length = be16(frame + 58);
                length = length >= 8 ? length - 8 : 0;
                if (length > size - 62) length = size - 62;
                printf(",\"source_port\":%u,\"destination_port\":%u,\"message_type\":%u,\"xid\":\"", be16(frame + 54), be16(frame + 56), frame[62]);
                hex(frame + 63, 3); printf("\",\"client_duid\":\""); duid(frame + 62, length, 1);
                printf("\",\"server_duid\":\""); duid(frame + 62, length, 2); putchar('"');
            }
            printf(",\"frame_hex\":\""); hex(frame, size); puts("\"}"); fflush(stdout);
        }
        if (quota) break;
    }
    struct tpacket_stats stats = {0}; socklen_t stats_size = sizeof(stats);
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &stats_size)) fail("packet stats");
    if (fflush(pcap) || fsync(fileno(pcap)) || fclose(pcap)) fail("finish PCAP");
    close(fd);
    printf("{\"kind\":\"capture_stop\",\"monotonic_ns\":%" PRIu64 ",\"realtime_ns\":%" PRIu64
        ",\"packets\":%u,\"truncated\":%u,\"socket_received\":%u,\"socket_dropped\":%u,\"quota_reached\":%s,\"signal\":%d}\n",
        stamp(CLOCK_MONOTONIC), stamp(CLOCK_REALTIME), count, truncated, stats.tp_packets, stats.tp_drops,
        quota ? "true" : "false", (int)stopped);
    return quota || truncated || stats.tp_drops ? 1 : 0;
}
