/* Standalone Linux mechanism probe: counts only, never a daemon benchmark.
 * Both methods use the same loopback socket, IP_PKTINFO and 65535-byte scratch.
 * mode recvmsg drains with the existing 16 packet budget; recvmmsg returns a
 * bounded batch; checked additionally consumes SO_ERROR after a partial batch.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int batched = strcmp(argv[1], "recvmsg") != 0;
    int checked = strcmp(argv[1], "checked") == 0;
    unsigned iterations = strtoul(argv[2], NULL, 10);
    unsigned burst = strtoul(argv[3], NULL, 10);
    if (!iterations || !burst || burst > 16) return 2;
    int receiver = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(receiver >= 0 && sender >= 0);
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(receiver, (struct sockaddr *)&destination, sizeof destination) == 0);
    socklen_t address_len = sizeof destination;
    assert(getsockname(receiver, (struct sockaddr *)&destination, &address_len) == 0);
    int enabled = 1;
    assert(setsockopt(receiver, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof enabled) == 0);
    unsigned char bytes[65535], query[28] = {0};
    struct sockaddr_storage peers[16];
    union { struct cmsghdr alignment; unsigned char bytes[64]; } control[16];
    struct iovec vectors[16];
    struct mmsghdr messages[16];
    memset(messages, 0, sizeof messages);
    for (unsigned i = 0; i < 16; ++i) {
        vectors[i] = (struct iovec){bytes + i * 1233, 1233};
        messages[i].msg_hdr = (struct msghdr){
            .msg_name = &peers[i], .msg_namelen = sizeof peers[i],
            .msg_iov = &vectors[i], .msg_iovlen = 1,
            .msg_control = control[i].bytes, .msg_controllen = sizeof control[i].bytes,
        };
    }
    if (strcmp(argv[1], "fault") == 0) {
        // A constructed ABI failure demonstrates that a positive batch count
        // does not identify whether the batch ended with EAGAIN or an error.
        // Production Rust never supplies this invalid pointer; no assertion
        // about a naturally occurring EFAULT rate is made.
        for (unsigned i = 0; i < 2; ++i)
            assert(sendto(sender, query, sizeof query, 0,
                          (struct sockaddr *)&destination, sizeof destination) == sizeof query);
        messages[1].msg_hdr.msg_iov = (struct iovec *)(uintptr_t)1;
        errno = 0;
        int received = recvmmsg(receiver, messages, 16, MSG_DONTWAIT, NULL);
        int returned_errno = errno;
        int deferred = 0;
        socklen_t length = sizeof deferred;
        assert(getsockopt(receiver, SOL_SOCKET, SO_ERROR, &deferred, &length) == 0);
        printf("{\"method\":\"fault\",\"received\":%d,\"returned_errno\":%d,\"deferred_socket_error\":%d}\n",
               received, returned_errno, deferred);
        close(sender);
        close(receiver);
        return received == 1 && deferred == EFAULT ? 0 : 1;
    }
    uint64_t calls = 0, packets = 0, would_block = 0;
    for (unsigned iteration = 0; iteration < iterations; ++iteration) {
        for (unsigned i = 0; i < burst; ++i)
            assert(sendto(sender, query, sizeof query, 0,
                          (struct sockaddr *)&destination, sizeof destination) == sizeof query);
        if (batched) {
            for (unsigned i = 0; i < 16; ++i) {
                messages[i].msg_hdr.msg_namelen = sizeof peers[i];
                messages[i].msg_hdr.msg_controllen = sizeof control[i].bytes;
                messages[i].msg_hdr.msg_flags = 0;
            }
            int count = recvmmsg(receiver, messages, 16, MSG_DONTWAIT, NULL);
            ++calls;
            assert(count == (int)burst);
            for (int i = 0; i < count; ++i) {
                assert(messages[i].msg_len == sizeof query);
                assert(messages[i].msg_hdr.msg_controllen != 0);
            }
            packets += count;
            if (checked && count < 16) {
                int error = 0;
                socklen_t length = sizeof error;
                assert(getsockopt(receiver, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
                assert(error == 0);
                ++calls;
            }
        } else {
            for (unsigned i = 0; i < 16; ++i) {
                messages[0].msg_hdr.msg_namelen = sizeof peers[0];
                messages[0].msg_hdr.msg_controllen = sizeof control[0].bytes;
                messages[0].msg_hdr.msg_flags = 0;
                ssize_t count = recvmsg(receiver, &messages[0].msg_hdr, MSG_DONTWAIT);
                ++calls;
                if (count < 0) {
                    assert(errno == EAGAIN || errno == EWOULDBLOCK);
                    ++would_block;
                    break;
                }
                assert(count == sizeof query && messages[0].msg_hdr.msg_controllen != 0);
                ++packets;
            }
        }
    }
    assert(packets == (uint64_t)iterations * burst);
    printf("{\"method\":\"%s\",\"iterations\":%u,\"burst\":%u,\"packets\":%llu,"
           "\"receive_and_error_syscalls\":%llu,\"would_block\":%llu}\n",
           argv[1], iterations, burst, (unsigned long long)packets,
           (unsigned long long)calls, (unsigned long long)would_block);
    close(sender);
    close(receiver);
}
