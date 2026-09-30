/* Compile/run against native headers; compile against the exact SDK too. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

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
_Static_assert(sizeof(struct ifaddrs) == 56, "ifaddrs size");
_Static_assert(offsetof(struct ifaddrs, ifa_flags) == 16, "ifaddrs flags");
_Static_assert(offsetof(struct ifaddrs, ifa_addr) == 24, "ifaddrs address");
_Static_assert(offsetof(struct ifaddrs, ifa_netmask) == 32, "ifaddrs mask");
_Static_assert(offsetof(struct ifaddrs, ifa_broadaddr) == 40, "ifaddrs broadcast");
_Static_assert(offsetof(struct ifaddrs, ifa_data) == 48, "ifaddrs data");
_Static_assert(IFF_UP == 1 && IFF_BROADCAST == 2 && IFF_LOOPBACK == 8, "interface flags");
_Static_assert(IFNAMSIZ == 16 && sizeof(struct ifreq) == 40, "ifreq size");
_Static_assert(offsetof(struct ifreq, ifr_addr) == 16 && SIOCGIFADDR == 0x8915, "ifreq address");
int main(void) {
    puts("{\"linux_64_bit_socket_abi\":\"pass\"}");
    return 0;
}
