/* Bounded, router-local DNS and DHCP health check. No files are written.
 * Run as root. DHCP uses one reserved synthetic MAC and releases its lease.
 * This exercises the daemon on its LAN interface; external client reachability
 * (Wi-Fi, firewall, routing) still needs the runbook's separate client checks.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

static const unsigned char hardware[6] = {0x02, 0x64, 0x6e, 0x73, 0x70, 0x01};
static const unsigned char cookie[4] = {0x63, 0x82, 0x53, 0x63};

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        exit(1);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static unsigned u16(const unsigned char *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

static void put16(unsigned char *p, unsigned value)
{
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static int readable(int fd, int64_t deadline)
{
    for (;;) {
        int64_t remaining = deadline - milliseconds();
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (remaining <= 0)
            return 0;
        int result = poll(&pfd, 1, (int)remaining);
        if (result < 0 && errno == EINTR)
            continue;
        return result > 0 && (pfd.revents & POLLIN);
    }
}

static int udp_socket(void)
{
    return socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
}

static int dns_skip_name(const unsigned char *packet, size_t size, size_t *offset)
{
    while (*offset < size) {
        unsigned length = packet[(*offset)++];
        if (!length)
            return 1;
        if ((length & 0xc0) == 0xc0) {
            if (*offset >= size)
                return 0;
            unsigned target = ((length & 0x3f) << 8) | packet[(*offset)++];
            return target < size;
        }
        if (length > 63 || length > size - *offset)
            return 0;
        *offset += length;
    }
    return 0;
}

static int dns_probe(struct in_addr server, const char *name, struct in_addr expected)
{
    unsigned char query[512] = {0}, reply[4096];
    size_t size = 12;
    unsigned id = (unsigned)milliseconds() ^ (unsigned)getpid();
    put16(query, id);
    query[2] = 1; /* recursion desired; a local positive record needs no upstream */
    query[5] = 1;
    const char *label = name;
    if (!*label || strlen(name) > 253)
        return 0;
    while (*label) {
        const char *end = strchr(label, '.');
        size_t length = end ? (size_t)(end - label) : strlen(label);
        if (!length || length > 63)
            return 0;
        query[size++] = (unsigned char)length;
        memcpy(query + size, label, length);
        size += length;
        if (!end)
            break;
        label = end + 1;
    }
    query[size++] = 0;
    put16(query + size, 1); size += 2;
    put16(query + size, 1); size += 2;
    int fd = udp_socket(), success = 0;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(53), .sin_addr = server};
    if (fd < 0)
        return 0;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        send(fd, query, size, 0) != (ssize_t)size)
        goto done;
    int64_t deadline = milliseconds() + 2000;
    while (readable(fd, deadline)) {
        ssize_t count = recv(fd, reply, sizeof(reply), 0);
        if (count < (ssize_t)size || memcmp(query, reply, 2) ||
            (u16(reply + 2) & 0xfa0f) != 0x8000 || u16(reply + 4) != 1 ||
            memcmp(query + 12, reply + 12, size - 12))
            continue;
        size_t offset = size;
        for (unsigned i = 0; i < u16(reply + 6); ++i) {
            if (!dns_skip_name(reply, (size_t)count, &offset) || (size_t)count - offset < 10)
                break;
            unsigned type = u16(reply + offset), cls = u16(reply + offset + 2);
            unsigned length = u16(reply + offset + 8);
            offset += 10;
            if (length > (size_t)count - offset)
                break;
            if (type == 1 && cls == 1 && length == 4 &&
                !memcmp(reply + offset, &expected.s_addr, 4)) {
                success = 1;
                goto done;
            }
            offset += length;
        }
    }
done:
    close(fd);
    return success;
}

static size_t dhcp_packet(unsigned char *packet, unsigned kind, uint32_t xid,
                          struct in_addr offered, struct in_addr server)
{
    memset(packet, 0, 300);
    packet[0] = 1; packet[1] = 1; packet[2] = 6;
    memcpy(packet + 4, &xid, 4);
    packet[10] = kind == 7 ? 0 : 0x80; /* broadcast OFFER/ACK */
    memcpy(packet + 28, hardware, sizeof(hardware));
    memcpy(packet + 236, cookie, sizeof(cookie));
    size_t n = 240;
    packet[n++] = 53; packet[n++] = 1; packet[n++] = (unsigned char)kind;
    if (kind == 7) {
        memcpy(packet + 12, &offered.s_addr, 4); /* RELEASE ciaddr */
    } else {
        packet[n++] = 55; packet[n++] = 3;
        packet[n++] = 1; packet[n++] = 6; packet[n++] = 51;
    }
    if (kind == 3) {
        packet[n++] = 50; packet[n++] = 4;
        memcpy(packet + n, &offered.s_addr, 4); n += 4;
    }
    if (kind == 3 || kind == 7) {
        packet[n++] = 54; packet[n++] = 4;
        memcpy(packet + n, &server.s_addr, 4); n += 4;
    }
    packet[n] = 255;
    return 300; /* BOOTP minimum packet size, including padding */
}

static int dhcp_reply(int fd, unsigned kind, uint32_t xid, struct in_addr server,
                      struct in_addr *offered)
{
    int64_t deadline = milliseconds() + 4000;
    while (readable(fd, deadline)) {
        unsigned char packet[1500];
        struct sockaddr_in peer;
        socklen_t peer_size = sizeof(peer);
        ssize_t size = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &peer_size);
        if (size < 240 || peer.sin_family != AF_INET || peer.sin_port != htons(67) ||
            peer.sin_addr.s_addr != server.s_addr || packet[0] != 2 ||
            packet[1] != 1 || packet[2] != 6 || memcmp(packet + 4, &xid, 4) ||
            memcmp(packet + 28, hardware, sizeof(hardware)) ||
            memcmp(packet + 236, cookie, sizeof(cookie)))
            continue;
        unsigned type = 0;
        int server_seen = 0, lease_seen = 0, end_seen = 0, malformed = 0;
        for (size_t offset = 240; offset < (size_t)size;) {
            unsigned code = packet[offset++];
            if (code == 255) { end_seen = 1; break; }
            if (!code)
                continue;
            if (offset >= (size_t)size) { malformed = 1; break; }
            unsigned length = packet[offset++];
            if (length > (size_t)size - offset) { malformed = 1; break; }
            if (code == 53) {
                if (length != 1 || type) { malformed = 1; break; }
                type = packet[offset];
            } else if (code == 54) {
                if (length != 4 || server_seen || memcmp(packet + offset, &server.s_addr, 4)) {
                    malformed = 1; break;
                }
                server_seen = 1;
            } else if (code == 51) {
                if (length != 4 || lease_seen ||
                    !(packet[offset] | packet[offset+1] | packet[offset+2] | packet[offset+3])) {
                    malformed = 1; break;
                }
                lease_seen = 1;
            }
            offset += length;
        }
        struct in_addr address;
        memcpy(&address.s_addr, packet + 16, 4);
        uint32_t host = ntohl(address.s_addr);
        if (malformed || !end_seen || type != kind || !server_seen || !lease_seen ||
            !host || (host >> 24) == 127 || (host >> 24) >= 224 ||
            address.s_addr == server.s_addr ||
            (kind == 5 && address.s_addr != offered->s_addr))
            continue;
        *offered = address;
        return 1;
    }
    return 0;
}

static int dhcp_probe(const char *interface, struct in_addr server)
{
    int fd = udp_socket(), one = 1, success = 0;
    unsigned char packet[300];
    struct in_addr offered = {0};
    uint32_t xid = (uint32_t)milliseconds() ^ ((uint32_t)getpid() << 16);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(68)};
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(67), .sin_addr = server};
    if (fd < 0)
        return 0;
    /* Exclusive :68 binding: never steal replies from an existing LAN client. */
    if (strlen(interface) >= IFNAMSIZ ||
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0 ||
        bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
        goto done;
    size_t size = dhcp_packet(packet, 1, xid, offered, server);
    if (sendto(fd, packet, size, 0, (struct sockaddr *)&remote, sizeof(remote)) != (ssize_t)size ||
        !dhcp_reply(fd, 2, xid, server, &offered))
        goto done;
    size = dhcp_packet(packet, 3, xid, offered, server);
    if (sendto(fd, packet, size, 0, (struct sockaddr *)&remote, sizeof(remote)) == (ssize_t)size)
        success = dhcp_reply(fd, 5, xid, server, &offered);
    /* Also release after an ACK timeout: the server may have committed a lease
     * whose response was lost. The fixed MAC bounds any missed cleanup to one. */
    size = dhcp_packet(packet, 7, xid, offered, server);
    if (sendto(fd, packet, size, 0, (struct sockaddr *)&remote, sizeof(remote)) != (ssize_t)size)
        success = 0;
    if (success)
        printf("dhcp=ok address=%s mac=02:64:6e:73:70:01 released=sent\n", inet_ntoa(offered));
done:
    close(fd);
    return success;
}

int main(int argc, char **argv)
{
    struct in_addr dns, expected, dhcp;
    if (argc != 6 || inet_pton(AF_INET, argv[1], &dns) != 1 ||
        inet_pton(AF_INET, argv[3], &expected) != 1 || inet_pton(AF_INET, argv[5], &dhcp) != 1) {
        fprintf(stderr, "usage: %s DNS_SERVER DNS_NAME EXPECTED_A DHCP_INTERFACE DHCP_SERVER\n", argv[0]);
        return 2;
    }
    alarm(12); /* Absolute last resort, including unexpected system call stalls. */
    if (!dns_probe(dns, argv[2], expected)) {
        fputs("dns=failed\n", stderr);
        return 1;
    }
    puts("dns=ok");
    if (!dhcp_probe(argv[4], dhcp)) {
        fputs("dhcp=failed\n", stderr);
        return 1;
    }
    return 0;
}
