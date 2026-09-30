/* Compile/run against native headers; compile against the exact SDK too. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

_Static_assert(sizeof(struct iovec) == 16, "iovec size");
_Static_assert(sizeof(struct msghdr) == 56, "msghdr size");
_Static_assert(offsetof(struct msghdr, msg_control) == 32, "control offset");
_Static_assert(sizeof(struct sockaddr_in) == 16, "IPv4 sockaddr size");
_Static_assert(sizeof(struct sockaddr_in6) == 28, "IPv6 sockaddr size");
_Static_assert(CMSG_SPACE(sizeof(struct in_pktinfo)) == 32, "IPv4 control space");
_Static_assert(CMSG_SPACE(sizeof(struct in6_pktinfo)) == 40, "IPv6 control space");
_Static_assert(IP_PKTINFO == 8 && IPV6_RECVPKTINFO == 49 && IPV6_PKTINFO == 50, "pktinfo flags");
_Static_assert(IPV6_V6ONLY == 26 && AF_INET == 2 && AF_INET6 == 10, "family flags");
_Static_assert(SOCK_NONBLOCK == 04000 && SOCK_CLOEXEC == 02000000, "socket flags");
int main(void) {
    puts("{\"linux_64_bit_socket_abi\":\"pass\"}");
    return 0;
}
