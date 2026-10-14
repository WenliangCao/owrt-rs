/* Test-only AArch64 launcher; never link this into either dnsmasq binary.
 *
 * Both implementations bind DHCP to INADDR_ANY even with listen-address=lo.
 * Rewrite startup binds for DHCP 15467 and ephemeral control sockets to
 * 127.0.0.1, then detach before measurement. DNS must bind 127/8:15353.
 * Refuse other IPv4/IPv6 addresses, ports 53/67, unexpected wildcard ports,
 * and forks before the DHCP + DNS UDP/TCP listeners have been observed.
 * This is a startup guard, not a sandbox after detach. The controller must
 * inspect all final sockets and TracerPid before issuing any test traffic.
 *
 * Usage: launcher /tmp/owned/child.pid /tmp/owned/bind.jsonl -- ELF ARGS...
 * Compile natively on AArch64 Linux, or with the matching OpenWrt SDK.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(__linux__)
#error This launcher requires native AArch64 Linux ptrace registers.
#endif

enum { NR_CLOSE = 57, NR_SOCKET = 198, NR_BIND = 200,
       NR_CLONE = 220, NR_CLONE3 = 435, DNS_PORT = 15353, DHCP_PORT = 15467 };
struct registers { uint64_t x[31], sp, pc, pstate; };
static pid_t child = -1;
static FILE *report;
static int types[4096];

static void stop_child(int signal_number)
{
    (void)signal_number;
    if (child > 0) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
    }
    _exit(125);
}

static void fail(const char *message)
{
    int saved = errno;
    fprintf(stderr, "loopback-bind: %s (%s)\n", message, strerror(saved));
    if (report) {
        fprintf(report, "{\"event\":\"failed\",\"reason\":\"%s\",\"errno\":%d}\n", message, saved);
        fflush(report);
    }
    if (child > 0) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    exit(1);
}

static void read_memory(uint64_t address, void *destination, size_t length)
{
    unsigned char *output = destination;
    for (size_t offset = 0; offset < length; offset += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *)(address + offset), 0);
        if (errno) fail("cannot read bind sockaddr");
        size_t amount = length - offset;
        if (amount > sizeof(word)) amount = sizeof(word);
        memcpy(output + offset, &word, amount);
    }
}

static void write_word(uint64_t address, long word)
{
    if (ptrace(PTRACE_POKEDATA, child, (void *)address, (void *)word) < 0)
        fail("cannot write bind sockaddr");
}

int main(int argc, char **argv)
{
    if (argc < 5 || strcmp(argv[3], "--") ||
        strncmp(argv[1], "/tmp/", 5) || strncmp(argv[2], "/tmp/", 5)) {
        fprintf(stderr, "usage: %s /tmp/.../child.pid /tmp/.../bind.jsonl -- ELF ARGS...\n", argv[0]);
        return 2;
    }
    report = fopen(argv[2], "wx");
    if (!report) fail("cannot create fresh report");
    setvbuf(report, NULL, _IOLBF, 0);
    signal(SIGALRM, stop_child);
    signal(SIGTERM, stop_child);
    signal(SIGINT, stop_child);
    alarm(15);
    child = fork();
    if (child < 0) fail("fork failed");
    if (!child) {
        fclose(report);
        if (setpgid(0, 0) < 0 || ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            _exit(126);
        raise(SIGSTOP);
        execvp(argv[4], &argv[4]);
        _exit(127);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status))
        fail("child did not stop before exec");
    FILE *pidfile = fopen(argv[1], "wx");
    if (!pidfile) fail("cannot create fresh pid file");
    if (fprintf(pidfile, "%ld\n", (long)child) < 0 || fclose(pidfile))
        fail("cannot write pid file");
    fprintf(report, "{\"event\":\"started\",\"pid\":%ld}\n", (long)child);
    if (ptrace(PTRACE_SETOPTIONS, child, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL) < 0)
        fail("cannot set ptrace options");

    int entering = 1, active_bind = 0, rewritten = 0, dhcp = 0, udp = 0, tcp = 0;
    int fd = -1, socket_type = 0, port = 0, family = 0;
    uint64_t syscall_number = 0, address = 0;
    long original_word = 0;
    int deliver_signal = 0;
    char bound_address[INET6_ADDRSTRLEN] = "";
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, child, 0, deliver_signal) < 0)
            fail("cannot resume child");
        deliver_signal = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFSTOPPED(status)) {
            errno = ECHILD;
            fail("child exited before all listeners were bound");
        }
        int stopped = WSTOPSIG(status);
        if (stopped == SIGTRAP && (status >> 16) == PTRACE_EVENT_EXEC)
            continue;
        if (stopped != (SIGTRAP | 0x80)) {
            deliver_signal = stopped;
            continue;
        }
        struct registers regs;
        struct iovec iov = { &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &iov) < 0 ||
            iov.iov_len != sizeof(regs))
            fail("cannot read AArch64 registers");
        if (entering) {
            syscall_number = regs.x[8];
            active_bind = rewritten = 0;
            if (syscall_number == NR_CLONE || syscall_number == NR_CLONE3) {
                errno = EPERM;
                fail("fork before listener guard detached");
            }
            if (syscall_number == NR_SOCKET) socket_type = (int)regs.x[1] & 15;
            if (syscall_number == NR_CLOSE) {
                if (regs.x[0] < sizeof(types) / sizeof(types[0])) types[regs.x[0]] = 0;
            }
            if (syscall_number == NR_BIND) {
                unsigned short sockaddr_family;
                address = regs.x[1];
                fd = (int)regs.x[0];
                if (regs.x[2] < sizeof(sockaddr_family)) fail("short sockaddr");
                read_memory(address, &sockaddr_family, sizeof(sockaddr_family));
                family = sockaddr_family;
                if (family == AF_INET || family == AF_INET6) {
                    struct sockaddr_storage storage;
                    size_t length = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                    if (regs.x[2] < length) fail("short Internet sockaddr");
                    read_memory(address, &storage, length);
                    struct sockaddr_in *v4 = (struct sockaddr_in *)&storage;
                    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
                    port = ntohs(v4->sin_port);
                    if (port == 53 || port == 67) {
                        errno = EPERM;
                        fail("standard service port rejected");
                    }
                    if (family == AF_INET && v4->sin_addr.s_addr == htonl(INADDR_ANY)) {
                        if (port != DHCP_PORT && port != 0) {
                            errno = EPERM;
                            fail("unexpected wildcard port rejected");
                        }
                        read_memory(address, &original_word, sizeof(original_word));
                        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        long replacement;
                        memcpy(&replacement, &storage, sizeof(replacement));
                        write_word(address, replacement);
                        rewritten = 1;
                    } else if ((family == AF_INET && (ntohl(v4->sin_addr.s_addr) >> 24) != 127) ||
                               (family == AF_INET6 && !IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr))) {
                        errno = EPERM;
                        fail("non-loopback bind rejected");
                    }
                    if (!inet_ntop(family, family == AF_INET ? (void *)&v4->sin_addr : (void *)&v6->sin6_addr,
                                   bound_address, sizeof(bound_address))) fail("cannot format bind address");
                    active_bind = 1;
                }
            }
        } else {
            int64_t result = (int64_t)regs.x[0];
            if (syscall_number == NR_SOCKET && result >= 0 &&
                (uint64_t)result < sizeof(types) / sizeof(types[0]))
                types[result] = socket_type;
            if (active_bind) {
                if (rewritten) write_word(address, original_word);
                int type = fd >= 0 && (size_t)fd < sizeof(types) / sizeof(types[0]) ? types[fd] : 0;
                fprintf(report, "{\"event\":\"bind\",\"pid\":%ld,\"fd\":%d,\"family\":%d,\"type\":%d,\"port\":%d,\"effective_address\":\"%s\",\"rewritten\":%s,\"result\":%lld}\n",
                        (long)child, fd, family, type, port, bound_address, rewritten ? "true" : "false", (long long)result);
                if (result < 0) {
                    errno = (int)-result;
                    fail("guarded bind failed");
                }
                if (port == DHCP_PORT && type == SOCK_DGRAM) dhcp = 1;
                if (port == DNS_PORT && type == SOCK_DGRAM) udp = 1;
                if (port == DNS_PORT && type == SOCK_STREAM) tcp = 1;
                if (dhcp && udp && tcp) {
                    if (ptrace(PTRACE_DETACH, child, 0, 0) < 0) fail("cannot detach");
                    alarm(0);
                    fprintf(report, "{\"event\":\"detached\",\"pid\":%ld,\"dhcp\":true,\"dns_udp\":true,\"dns_tcp\":true}\n", (long)child);
                    int close_result = fclose(report);
                    report = NULL;
                    if (close_result) fail("cannot close report");
                    printf("%ld\n", (long)child);
                    return 0;
                }
            }
        }
        entering = !entering;
    }
}
