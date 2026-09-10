/* ABI/constants used by the Linux benchmark client's setsockopt call. */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
_Static_assert(IPPROTO_TCP == 6, "IPPROTO_TCP");
_Static_assert(TCP_QUICKACK == 12, "TCP_QUICKACK");
_Static_assert(sizeof(int) == 4, "int");
_Static_assert(sizeof(socklen_t) == 4, "socklen_t");
