// Standalone Linux evidence helper, independent of the replacement daemons.
// Records route-netlink datagrams and filtered WAN packets, without changing
// links, routes, promiscuity or configuration. Data files are append-only.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
static double seconds(clockid_t clock) {
    struct timespec ts;
    if (clock_gettime(clock, &ts)) { perror("clock_gettime"); exit(1); }
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int bounded(int argc, char **argv, int limit_output) {
    if (argc < 4) return 2;
    char *end;
    long duration = strtol(argv[2], &end, 10);
    if (*end || duration < 1 || duration > 120) return 2;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        if (setsid() < 0) _exit(126);
        // Each capture uses a fresh file; also limits faulty command output.
        if (limit_output) {
            struct rlimit limit = {65536, 65536};
            if (setrlimit(RLIMIT_FSIZE, &limit)) _exit(126);
        }
        execvp(argv[3], argv + 3);
        _exit(127);
    }
    double deadline = seconds(CLOCK_MONOTONIC) + duration;
    int status = 0;
    for (;;) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) break;
        if (got < 0 && errno != EINTR) return 1;
        if (stopping || seconds(CLOCK_MONOTONIC) >= deadline) {
            // Kill the private command group, including a stuck ubus client.
            kill(-child, SIGKILL);
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            return stopping ? 143 : 124;
        }
        struct timespec pause = {0, 50000000};
        nanosleep(&pause, NULL);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

// Generated offline with tcpdump -ddd, Ethernet link type and snaplen 1536:
// arp or (udp and (port 67 or port 68 or port 546 or port 547)) or
// (icmp6 and ip6[40] >= 133 and ip6[40] <= 136).
static struct sock_filter packet_filter[] = {
    {40,0,0,12}, {21,33,0,2054}, {21,0,16,34525}, {48,0,0,20},
    {21,0,7,17}, {40,0,0,54}, {21,28,0,67}, {21,27,0,68},
    {21,26,0,546}, {21,25,0,547}, {40,0,0,56}, {21,23,20,67},
    {21,0,2,44}, {48,0,0,54}, {21,21,0,17}, {21,0,20,58},
    {48,0,0,54}, {53,0,18,133}, {37,17,16,136}, {21,0,16,2048},
    {48,0,0,23}, {21,0,14,17}, {40,0,0,20}, {69,12,0,8191},
    {177,0,0,14}, {72,0,0,14}, {21,8,0,67}, {21,7,0,68},
    {21,6,0,546}, {21,5,0,547}, {72,0,0,16}, {21,3,0,67},
    {21,2,0,68}, {21,1,0,546}, {21,0,1,547}, {6,0,0,1536}, {6,0,0,0}
};

static int packet_socket(unsigned index, const char *interface, unsigned char mac[6]) {
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq request = {0};
    if (strlen(interface) >= sizeof(request.ifr_name)) { close(fd); errno = EINVAL; return -1; }
    memcpy(request.ifr_name, interface, strlen(interface) + 1);
    if (ioctl(fd, SIOCGIFHWADDR, &request)) { int error = errno; close(fd); errno = error; return -1; }
    memcpy(mac, request.ifr_hwaddr.sa_data, 6);
    struct sock_fprog filter = {sizeof(packet_filter) / sizeof(packet_filter[0]), packet_filter};
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
                                 .sll_ifindex = (int)index};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) ||
        bind(fd, (void *)&address, sizeof(address))) {
        int error = errno; close(fd); errno = error; return -1;
    }
    return fd;
}

static FILE *append_file(const char *directory, const char *name) {
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path)) return NULL;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    FILE *file = fdopen(fd, "ab");
    if (!file) close(fd);
    if (file && fseeko(file, 0, SEEK_END)) { fclose(file); return NULL; }
    return file;
}

static long file_size(FILE *file) {
    return ftello(file);
}

static void flush(FILE *file) {
    if (fflush(file) || fsync(fileno(file))) stopping = 1;
}

static int events(const char *directory, const char *interface, unsigned duration) {
    char lockpath[1024];
    if (snprintf(lockpath, sizeof(lockpath), "%s/events.lock", directory) >= (int)sizeof(lockpath)) return 2;
    int lock = open(lockpath, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) return 1;
    FILE *meta = append_file(directory, "events.log");
    FILE *netlink = append_file(directory, "netlink.hex");
    FILE *packets = append_file(directory, "wan.pcap");
    if (!meta || !netlink || !packets) return 1;
    setvbuf(meta, NULL, _IOLBF, 0);
    if (!file_size(packets)) {
        const struct { uint32_t magic; uint16_t major, minor; uint32_t zone, sig, snaplen, link; }
            header = {0xa1b2c3d4, 2, 4, 0, 0, 1536, 1};
        if (fwrite(&header, sizeof(header), 1, packets) != 1) return 1;
        flush(packets);
    }
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct sockaddr_nl address = {.nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                     RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE};
    if (nl < 0 || bind(nl, (void *)&address, sizeof(address))) { perror("netlink"); return 1; }
    int receive_buffer = 262144;
    if (setsockopt(nl, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer))) return 1;
    double started = seconds(CLOCK_BOOTTIME), synced = started, checked = 0, heartbeat = 0;
    unsigned bound_index = 0, packet_count = 0, omitted_netlink = 0, omitted_packets = 0, foreign_arp = 0;
    unsigned char wan_mac[6] = {0};
    int packet = -1;
    unsigned char data[16384];
    fprintf(meta, "start boot_seconds=%.3f wall_seconds=%.3f interface=%s pid=%ld\n",
            started, seconds(CLOCK_REALTIME), interface, (long)getpid());
    flush(meta);
    while (!stopping && (!duration || seconds(CLOCK_BOOTTIME) - started < duration)) {
        double now = seconds(CLOCK_BOOTTIME);
        if (now - checked >= 1) {
            checked = now;
            struct statvfs storage;
            if (statvfs(directory, &storage) || (uint64_t)storage.f_bavail * storage.f_frsize < 8 * 1024 * 1024) {
                fprintf(meta, "storage_reserve_reached boot_seconds=%.3f\n", now); break;
            }
            unsigned index = if_nametoindex(interface);
            if (index != bound_index || (index && packet < 0)) {
                if (packet >= 0) close(packet);
                packet = index ? packet_socket(index, interface, wan_mac) : -1;
                bound_index = index;
                fprintf(meta, "wan_binding boot_seconds=%.3f index=%u capture_fd=%d errno=%d\n",
                        now, index, packet, packet < 0 && index ? errno : 0);
                flush(meta);
            }
            if (now - heartbeat >= 30) {
                heartbeat = now;
                fprintf(meta, "heartbeat boot_seconds=%.3f wall_seconds=%.3f packets=%u quota_omitted_netlink=%u quota_omitted_packets=%u foreign_arp_filtered=%u\n",
                        now, seconds(CLOCK_REALTIME), packet_count, omitted_netlink, omitted_packets, foreign_arp);
            }
        }
        struct pollfd fds[] = {{nl, POLLIN, 0}, {packet, POLLIN, 0}};
        if (poll(fds, 2, 250) < 0 && errno != EINTR) break;
        for (int which = 0; which < 2; which++) {
            if (!(fds[which].revents & POLLIN)) continue;
            // Bound a burst so packet traffic cannot starve flushing or signals.
            for (unsigned burst = 0; burst < 64; burst++) {
                ssize_t length = recv(fds[which].fd, data, sizeof(data), MSG_TRUNC);
                if (length < 0) {
                    if (errno != EAGAIN && errno != EINTR)
                        fprintf(meta, "receive_error boot_seconds=%.3f source=%d errno=%d\n", now, which, errno);
                    break;
                }
                if (!length) break;
                double wall = seconds(CLOCK_REALTIME), mono = seconds(CLOCK_BOOTTIME);
                size_t saved = (size_t)length < sizeof(data) ? (size_t)length : sizeof(data);
                // Shared upstream LANs can carry many unrelated ARP broadcasts.
                // Retain requests/replies involving our Ethernet address only.
                if (which && saved >= 14 && data[12] == 8 && data[13] == 6 &&
                    memcmp(data, wan_mac, 6) && memcmp(data + 6, wan_mac, 6)) {
                    foreign_arp++;
                    continue;
                }
                if (!which && file_size(netlink) < 512 * 1024) {
                    fprintf(netlink, "boot_seconds=%.6f wall_seconds=%.6f original=%zd captured=%zu hex=", mono, wall, length, saved);
                    for (size_t i = 0; i < saved; i++) fprintf(netlink, "%02x", data[i]);
                    fputc('\n', netlink);
                } else if (!which) {
                    if (!omitted_netlink++) fprintf(meta, "netlink_file_limit boot_seconds=%.3f\n", mono);
                }
                if (which && file_size(packets) < 512 * 1024) {
                    if (saved > 1536) saved = 1536;
                    uint32_t record[] = {(uint32_t)wall, (uint32_t)((wall - (uint32_t)wall) * 1e6),
                                         (uint32_t)saved, (uint32_t)length};
                    fwrite(record, sizeof(record), 1, packets);
                    fwrite(data, saved, 1, packets);
                    packet_count++;
                    if (packet_count % 32 == 1)
                        fprintf(meta, "packet_checkpoint boot_seconds=%.6f wall_seconds=%.6f number=%u bytes=%zu\n",
                                mono, wall, packet_count, saved);
                } else if (which) {
                    if (!omitted_packets++) fprintf(meta, "packet_file_limit boot_seconds=%.3f\n", mono);
                }
            }
        }
        if (now - synced >= 2) {
            synced = now; flush(meta); flush(netlink); flush(packets);
        }
        if (file_size(meta) >= 256 * 1024) break;
    }
    if (packet >= 0) {
        struct tpacket_stats stats;
        socklen_t length = sizeof(stats);
        if (!getsockopt(packet, SOL_PACKET, PACKET_STATISTICS, &stats, &length))
            fprintf(meta, "packet_socket_stats received=%u dropped=%u\n", stats.tp_packets, stats.tp_drops);
        close(packet);
    }
    fprintf(meta, "stop boot_seconds=%.3f signal=%d\n", seconds(CLOCK_BOOTTIME), (int)stopping);
    flush(meta); flush(netlink); flush(packets);
    fclose(meta); fclose(netlink); fclose(packets); close(nl); close(lock);
    return 0;
}

int main(int argc, char **argv) {
    struct sigaction action = {.sa_handler = stop};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 1;
    if (argc >= 2 && !strcmp(argv[1], "bounded")) return bounded(argc, argv, 1);
    // Deployment-only commands must copy verified images/configuration into
    // RAM. Retain the timeout/process-group boundary without a 64 KiB cap.
    if (argc >= 2 && !strcmp(argv[1], "bounded-no-file-limit")) return bounded(argc, argv, 0);
    if (argc == 5 && !strcmp(argv[1], "events")) {
        char *end;
        unsigned long duration = strtoul(argv[4], &end, 10);
        if (*end || duration > 86400) return 2;
        return events(argv[2], argv[3], (unsigned)duration);
    }
    fprintf(stderr, "usage: power-recorder bounded|bounded-no-file-limit SECONDS COMMAND... | events DIRECTORY INTERFACE SECONDS_OR_0\n");
    return 2;
}
