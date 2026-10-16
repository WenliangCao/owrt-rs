/* Passive LAN UDP DNS shape counts. Never prints/stores addresses or names.
 * Build: cc -O2 -Wall -Wextra query_shape_stats.c -o query-shape-stats
 * Tests (also on non-Linux): cc -DQUERY_SHAPE_TEST ... && ./query-shape-stats
 * Run on Linux: query-shape-stats <LAN-interface> <seconds, 1..3600>
 * TCP is counted as segments only; no TCP query/share claim is made.
 * Frame/socket totals are after the kernel's DNS/fragment/extension filter.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct counts {
    uint64_t queries, excluded_health_name, malformed, ad, cd, ad_cd, opt, empty_opt, do_bit;
    uint64_t opt_options, opt_nonzero_version, a, aaaa, https, other_type;
    uint64_t address_queries, j_shape, reserve_shape, reserve_extra;
};

static uint16_t be16(const unsigned char *p) { return (p[0] << 8) | p[1]; }

/* The external health probe uses this public fixed name. Conservatively
 * exclude real client requests for the same name as well. Compressed names
 * remain in the sample; no other name is decoded, retained or printed. */
static int is_health_query(const unsigned char *p, size_t n) {
    static const unsigned char name[] = "\003www\012cloudflare\003com";
    if (be16(p + 4) != 1 || n < 12 + sizeof(name) + 4) return 0;
    for (size_t i = 0; i < sizeof(name); i++) {
        unsigned char b = p[12 + i];
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (b != name[i]) return 0;
    }
    return 1;
}

/* Validate compression chains without retaining decoded labels. */
static int name_end(const unsigned char *p, size_t n, size_t start,
                    size_t *end, int *plain) {
    size_t pos = start, expanded = 0, steps = 0;
    int jumped = 0;
    *plain = 1;
    while (pos < n && ++steps <= n) {
        unsigned len = p[pos++];
        if ((len & 0xc0) == 0xc0) {
            if (pos >= n) return 0;
            size_t target = ((len & 63) << 8) | p[pos++];
            if (!jumped) *end = pos;
            *plain = 0;
            jumped = 1;
            /* Prior-name pointers only, including no self/cyclic references. */
            if (target >= pos - 2) return 0;
            pos = target;
        } else {
            if (len > 63 || pos + len > n || (expanded += len + 1) > 255) return 0;
            if (!len) {
                if (!jumped) *end = pos;
                return 1;
            }
            pos += len;
        }
    }
    return 0;
}

/* Counts query headers even if the body is malformed; shape counts require
 * a fully bounded message. They are upper bounds, not observed cache hits. */
static void dns_count(struct counts *c, const unsigned char *p, size_t n) {
    if (n < 12) { c->malformed++; return; }
    unsigned flags = be16(p + 2);
    if (flags & 0x8000) return;
    if (is_health_query(p, n)) { c->excluded_health_name++; return; }
    c->queries++;
    c->ad += !!(flags & 0x20);
    c->cd += !!(flags & 0x10);
    c->ad_cd += !!(flags & 0x30);
    unsigned qd = be16(p + 4), an = be16(p + 6), ns = be16(p + 8), ar = be16(p + 10);
    size_t pos = 12, qend = 0;
    unsigned qtype = 0, qclass = 0;
    int qplain = 0, has_opt = 0, empty = 0, has_do = 0, options = 0, version = 0;
    int literal_empty_opt = 0;
    for (unsigned i = 0; i < qd; i++) {
        int plain;
        if (!name_end(p, n, pos, &pos, &plain) || n - pos < 4) goto malformed;
        if (!i) { qtype = be16(p + pos); qclass = be16(p + pos + 2); qplain = plain; }
        pos += 4;
        if (!i) qend = pos;
    }
    for (unsigned i = 0; i < an + ns + ar; i++) {
        size_t start = pos;
        int plain;
        if (!name_end(p, n, pos, &pos, &plain) || n - pos < 10) goto malformed;
        unsigned type = be16(p + pos), size = be16(p + pos + 8);
        if (n - pos - 10 < size) goto malformed;
        if (i >= an + ns && type == 41) {
            has_opt = 1;
            empty |= size == 0;
            options |= size != 0;
            has_do |= !!(p[pos + 6] & 0x80);
            version |= p[pos + 5] != 0;
            literal_empty_opt = plain && pos == start + 1 && p[start] == 0 && size == 0
                && p[pos + 4] == 0 && p[pos + 5] == 0
                && p[pos + 6] == 0 && p[pos + 7] == 0;
        }
        pos += 10 + size;
    }
    if (pos != n) goto malformed;
    c->opt += has_opt;
    c->empty_opt += empty;
    c->do_bit += has_do;
    c->opt_options += options;
    c->opt_nonzero_version += version;
    if (qd == 1) {
        c->a += qtype == 1;
        c->aaaa += qtype == 28;
        c->https += qtype == 65;
        c->other_type += qtype != 1 && qtype != 28 && qtype != 65;
    }
    int address = qd == 1 && qclass == 1 && (qtype == 1 || qtype == 28);
    c->address_queries += address;
    int common = address && qplain && an == 0 && ns == 0;
    int j = common && flags == 0x0100 && ar == 0 && qend == n;
    int reserve = common && (flags & ~0x0030) == 0x0100
        && ((ar == 0 && qend == n) || (ar == 1 && literal_empty_opt && qend + 11 == n));
    c->j_shape += j;
    c->reserve_shape += reserve;
    c->reserve_extra += reserve && !j;
    return;
malformed:
    c->malformed++;
}

#define FIELDS(X) X(queries) X(excluded_health_name) X(malformed) X(ad) X(cd) X(ad_cd) X(opt) X(empty_opt) \
    X(do_bit) X(opt_options) X(opt_nonzero_version) X(a) X(aaaa) X(https) X(other_type) \
    X(address_queries) X(j_shape) X(reserve_shape) X(reserve_extra)
static void print_counts(const struct counts *c) {
    int comma = 0;
    putchar('{');
#define PRINT(field) printf("%s\"" #field "\":%llu", comma++ ? "," : "", (unsigned long long)c->field);
    FIELDS(PRINT)
#undef PRINT
    putchar('}');
}

#ifdef QUERY_SHAPE_TEST
#include <assert.h>

static void check_shape_boundaries(void) {
    unsigned char q[512] = {0,1,1,0,0,1,0,0,0,0,0,0,1,'x',0,0,1,0,1};
    const unsigned char opt[11] = {0,0,41,4,208,0,0,0,0,0,0};
    /* Exact-size allocations make every truncated DNS prefix an ASan check. */
    q[11] = 1;
    memcpy(q + 19, opt, sizeof(opt));
    for (size_t n = 0; n < 30; n++) {
        unsigned char *short_q = malloc(n ? n : 1);
        assert(short_q);
        memcpy(short_q, q, n);
        struct counts c = {0};
        dns_count(&c, short_q, n);
        assert(c.malformed == 1 && !c.j_shape && !c.reserve_shape);
        free(short_q);
    }
    /* Every flag combination must agree with the two exact source guards. */
    for (unsigned flags = 0; flags <= UINT16_MAX; flags++) {
        q[2] = flags >> 8; q[3] = flags;
        for (unsigned with_opt = 0; with_opt <= 1; with_opt++) {
            q[11] = with_opt;
            struct counts c = {0};
            dns_count(&c, q, with_opt ? 30 : 19);
            assert(c.queries == !(flags & 0x8000));
            assert(c.j_shape == (flags == 0x0100 && !with_opt));
            assert(c.reserve_shape == ((flags & ~0x0030) == 0x0100));
            assert(c.reserve_extra == c.reserve_shape - c.j_shape);
        }
    }
    q[2] = 1; q[3] = 0; q[11] = 2;
    memcpy(q + 30, opt, sizeof(opt));
    q[37] = 0x80;
    struct counts c = {0};
    dns_count(&c, q, 41);
    assert(c.opt == 1 && c.empty_opt == 1 && c.do_bit == 1 && !c.reserve_shape);
    /* The additional OPT must own the literal root, not a compressed root. */
    q[11] = 1; q[19] = 0xc0; q[20] = 0;
    memcpy(q + 21, opt + 1, sizeof(opt) - 1);
    memset(&c, 0, sizeof(c));
    dns_count(&c, q, 31);
    assert(c.opt == 1 && c.empty_opt == 1 && !c.reserve_shape);
    /* An expanded DNS name is valid at 255 bytes and rejected at 256. */
    for (unsigned last = 61; last <= 62; last++) {
        memset(q, 0, sizeof(q)); q[2] = 1; q[5] = 1;
        size_t pos = 12;
        for (unsigned label = 0; label < 4; label++) {
            unsigned size = label == 3 ? last : 63;
            q[pos++] = size; memset(q + pos, 'x', size); pos += size;
        }
        q[pos++] = 0; q[pos++] = 0; q[pos++] = 1; q[pos++] = 0; q[pos++] = 1;
        memset(&c, 0, sizeof(c));
        dns_count(&c, q, pos);
        assert(c.j_shape == (last == 61) && c.malformed == (last == 62));
    }
}

static void check_health_exclusion(void) {
    unsigned char q[80] = {0,1,1,0x30,0,1,0,0,0,0,0,0};
    const unsigned char name[] = "\003www\012cloudflare\003com";
    memcpy(q + 12, name, sizeof(name));
    q[33] = 1; q[35] = 1;
    struct counts c = {0};
    dns_count(&c, q, 36);
    assert(c.excluded_health_name == 1 && !c.queries && !c.ad && !c.cd && !c.reserve_shape);
    for (size_t i = 12; i < 32; i++) {
        if (q[i] >= 'a' && q[i] <= 'z') q[i] -= 'a' - 'A';
    }
    q[11] = 1;
    const unsigned char opt[11] = {0,0,41,4,208,0,0,0,0,0,0};
    memcpy(q + 36, opt, sizeof(opt));
    dns_count(&c, q, 47);
    assert(c.excluded_health_name == 2 && !c.queries && !c.opt);
    q[11] = 0;
    memcpy(q + 28, "net", 3);
    dns_count(&c, q, 36);
    assert(c.excluded_health_name == 2 && c.queries == 1 && c.reserve_shape == 1);
    /* A same-name compression pointer remains in the conservative sample. */
    memcpy(q + 12, name, sizeof(name));
    q[31] = 0xc0; q[32] = 0; q[33] = 0; q[34] = 1; q[35] = 0; q[36] = 1;
    dns_count(&c, q, 37);
    assert(c.excluded_health_name == 2 && c.queries == 2 && c.address_queries == 2
        && c.reserve_shape == 1 && !c.malformed);
    /* A longer suffix must not match the fixed name's terminal root byte. */
    q[31] = 1; q[32] = 'x'; q[33] = 0; q[34] = 0; q[35] = 1; q[36] = 0; q[37] = 1;
    dns_count(&c, q, 38);
    assert(c.excluded_health_name == 2 && c.queries == 3 && c.reserve_shape == 2);
}

int main(void) {
    unsigned char q[80] = {0,1,1,0,0,1,0,0,0,0,0,0,1,'x',0,0,1,0,1};
    struct counts c = {0};
    dns_count(&c, q, 19);
    assert(c.queries == 1 && c.j_shape == 1 && c.reserve_shape == 1 && c.a == 1);
    q[3] = 0x30;
    dns_count(&c, q, 19);
    assert(c.ad == 1 && c.cd == 1 && c.ad_cd == 1 && c.reserve_extra == 1);
    q[11] = 1;
    unsigned char opt[11] = {0,0,41,4,208,0,0,0,0,0,0};
    memcpy(q + 19, opt, 11);
    dns_count(&c, q, 30);
    assert(c.opt == 1 && c.empty_opt == 1 && c.reserve_extra == 2);
    q[26] = 0x80;
    dns_count(&c, q, 30);
    assert(c.do_bit == 1 && c.reserve_extra == 2);
    q[26] = 0; q[25] = 1;
    dns_count(&c, q, 30);
    assert(c.opt_nonzero_version == 1 && c.reserve_extra == 2);
    q[25] = 0; q[29] = 4;
    memset(q + 30, 0, 4);
    dns_count(&c, q, 34);
    assert(c.opt_options == 1 && c.reserve_extra == 2);
    dns_count(&c, q, 33);
    assert(c.malformed == 1);
    q[11] = 0; q[3] = 0; q[16] = 28;
    dns_count(&c, q, 19);
    assert(c.aaaa == 1 && c.j_shape == 2);
    q[16] = 65;
    dns_count(&c, q, 19);
    assert(c.https == 1 && c.j_shape == 2);
    q[12] = 0xc0; q[13] = 12;
    dns_count(&c, q, 19);
    assert(c.malformed == 2);
    print_counts(&c); putchar('\n');
    check_shape_boundaries();
    check_health_exclusion();
    puts("query-shape parser checks passed");
    return 0;
}
#else
#ifdef __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static void stop_capture(int sig) { (void)sig; stopped = 1; }
static double monotime(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock"); exit(1); }
    return t.tv_sec + t.tv_nsec / 1e9;
}
static int local_destination(const struct ifaddrs *addresses, const char *iface,
                             int family, const unsigned char *dest) {
    for (const struct ifaddrs *a = addresses; a; a = a->ifa_next) {
        if (!a->ifa_addr || strcmp(a->ifa_name, iface) || a->ifa_addr->sa_family != family) continue;
        const void *candidate = family == AF_INET
            ? (void *)&((struct sockaddr_in *)a->ifa_addr)->sin_addr
            : (void *)&((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr;
        if (!memcmp(candidate, dest, family == AF_INET ? 4 : 16)) return 1;
    }
    return 0;
}

static int attach_dns_filter(int fd) {
    /* SOCK_DGRAM starts at the IP header. Reject ordinary non-DNS traffic in
     * the kernel; pass fragments and supported IPv6 extensions to the bounded
     * parser below. Jump destinations are shown to keep this table auditable. */
    static struct sock_filter filter[] = {
        /*  0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PROTOCOL),
        /*  1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 8), /* 2 / 10 */
        /*  2 */ BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
        /*  3 */ BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 17, 0), /* 21 / 4 */
        /*  4 */ BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
        /*  5 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 1, 0), /* 7 / 6 */
        /*  6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 15), /* 7 / 22 */
        /*  7 */ BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
        /*  8 */ BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),
        /*  9 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53, 11, 12), /* 21 / 22 */
        /* 10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 11), /* 11 / 22 */
        /* 11 */ BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6),
        /* 12 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 6, 0), /* 19 / 13 */
        /* 13 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 5, 0), /* 19 / 14 */
        /* 14 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 6, 0), /* 21 / 15 */
        /* 15 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 43, 5, 0), /* 21 / 16 */
        /* 16 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 60, 4, 0), /* 21 / 17 */
        /* 17 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 51, 3, 0), /* 21 / 18 */
        /* 18 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 44, 2, 3), /* 21 / 22 */
        /* 19 */ BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 42),
        /* 20 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53, 0, 1), /* 21 / 22 */
        /* 21 */ BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
        /* 22 */ BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program));
}

int main(int argc, char **argv) {
    char *end = NULL;
    long duration = argc == 3 ? strtol(argv[2], &end, 10) : 0;
    if (argc != 3 || !end || *end || duration < 1 || duration > 3600) {
        fprintf(stderr, "usage: query-shape-stats LAN-interface seconds(1..3600)\n"); return 2;
    }
    unsigned index = if_nametoindex(argv[1]);
    struct ifaddrs *addresses = NULL;
    if (!index || getifaddrs(&addresses)) { perror("interface addresses"); return 1; }
    /* Protocol zero receives nothing until the filtered socket is bound. */
    int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("packet socket"); return 1; }
    if (attach_dns_filter(fd)) { perror("packet filter"); close(fd); freeifaddrs(addresses); return 1; }
    struct sockaddr_ll bindto = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = index};
    if (bind(fd, (void *)&bindto, sizeof(bindto))) { perror("bind"); return 1; }
    /* No promiscuous membership, firewall change, payload log or packet send. */
    signal(SIGTERM, stop_capture); signal(SIGINT, stop_capture);
    struct counts total = {0}, bins[60] = {{0}};
    uint64_t frames = 0, outgoing = 0, fragments = 0, truncated = 0;
    uint64_t udp4 = 0, udp6 = 0, tcp_segments = 0, tcp_data_segments = 0, receive_errors = 0;
    unsigned char packet[65536];
    double start = monotime(), deadline = start + duration;
    while (!stopped) {
        double now = monotime();
        if (now >= deadline) break;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, (int)((deadline - now) * 1000) + 1);
        if (ready < 0) { if (errno == EINTR) continue; receive_errors++; break; }
        if (!ready) break;
        struct sockaddr_ll sender;
        socklen_t slen = sizeof(sender);
        ssize_t received = recvfrom(fd, packet, sizeof(packet), MSG_TRUNC, (void *)&sender, &slen);
        if (received < 0) { if (errno == EINTR) continue; receive_errors++; break; }
        frames++;
        if (sender.sll_pkttype == PACKET_OUTGOING) { outgoing++; continue; }
        if ((size_t)received > sizeof(packet)) { truncated++; continue; }
        size_t n = received, pos;
        unsigned proto;
        int family;
        if (sender.sll_protocol == htons(ETH_P_IP) && n >= 20 && packet[0] >> 4 == 4) {
            family = AF_INET; pos = (packet[0] & 15) * 4; proto = packet[9];
            size_t length = be16(packet + 2);
            if (pos < 20 || length < pos || length > n) { truncated++; continue; }
            n = length;
            if (!local_destination(addresses, argv[1], family, packet + 16)) continue;
            if (be16(packet + 6) & 0x3fff) { fragments++; continue; }
        } else if (sender.sll_protocol == htons(ETH_P_IPV6) && n >= 40 && packet[0] >> 4 == 6) {
            family = AF_INET6; pos = 40; proto = packet[6];
            size_t length = 40 + be16(packet + 4);
            if (length > n) { truncated++; continue; }
            n = length;
            if (!local_destination(addresses, argv[1], family, packet + 24)) continue;
            while (proto == 0 || proto == 43 || proto == 60 || proto == 51) {
                if (n - pos < 2) break;
                size_t extlen = proto == 51 ? (packet[pos + 1] + 2) * 4 : (packet[pos + 1] + 1) * 8;
                if (extlen > n - pos) break;
                proto = packet[pos]; pos += extlen;
            }
            if (proto == 44) { fragments++; continue; }
        } else continue;
        if ((proto != 6 && proto != 17) || n - pos < 8 || be16(packet + pos + 2) != 53) continue;
        if (proto == 6) {
            tcp_segments++;
            if (n - pos >= 20) {
                size_t hlen = (packet[pos + 12] >> 4) * 4;
                tcp_data_segments += hlen >= 20 && n - pos > hlen;
            }
            continue;
        }
        size_t length = be16(packet + pos + 4);
        if (length < 8 || length > n - pos) { truncated++; continue; }
        if (family == AF_INET) udp4++; else udp6++;
        double elapsed = monotime() - start;
        unsigned bin = (unsigned)(elapsed / 60);
        if (bin > 59) bin = 59;
        dns_count(&total, packet + pos + 8, length - 8);
        dns_count(&bins[bin], packet + pos + 8, length - 8);
    }
    double elapsed = monotime() - start;
    struct tpacket_stats stats = {0};
    socklen_t statlen = sizeof(stats);
    int stats_ok = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &statlen) == 0;
    close(fd); freeifaddrs(addresses);
    printf("{\"schema\":1,\"duration_seconds\":%ld,\"elapsed_seconds\":%.3f,\"interrupted\":%s,"
           "\"frames\":%llu,\"outgoing_skipped\":%llu,\"fragment_packets_skipped\":%llu,\"truncated\":%llu,"
           "\"udp4_datagrams\":%llu,\"udp6_datagrams\":%llu,\"tcp_segments\":%llu,\"tcp_data_segments\":%llu,"
           "\"receive_errors\":%llu,\"socket_stats_available\":%s,\"socket_packets\":%u,\"socket_drops\":%u,\"udp_dns\":",
           duration, elapsed, stopped ? "true" : "false", (unsigned long long)frames,
           (unsigned long long)outgoing, (unsigned long long)fragments, (unsigned long long)truncated,
           (unsigned long long)udp4, (unsigned long long)udp6, (unsigned long long)tcp_segments,
           (unsigned long long)tcp_data_segments, (unsigned long long)receive_errors,
           stats_ok ? "true" : "false", stats.tp_packets, stats.tp_drops);
    print_counts(&total);
    printf(",\"minute_bins\":[");
    unsigned count = (unsigned)(elapsed / 60) + 1;
    if (count > 60) count = 60;
    for (unsigned i = 0; i < count; i++) { if (i) putchar(','); print_counts(&bins[i]); }
    puts("]}");
    return receive_errors || !stats_ok || stopped ? 1 : 0;
}
#else
#error "Capture requires Linux; use -DQUERY_SHAPE_TEST for portable parser checks."
#endif
#endif
