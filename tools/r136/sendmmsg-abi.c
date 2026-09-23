/* Compile with the exact OpenWrt SDK's aarch64-openwrt-linux-musl-gcc. */
#define _GNU_SOURCE
#include <stddef.h>
#include <sys/socket.h>

_Static_assert(sizeof(struct msghdr) == 56, "MsgHdr size");
_Static_assert(sizeof(struct mmsghdr) == 64, "MMsgHdr size");
_Static_assert(_Alignof(struct mmsghdr) == 8, "MMsgHdr alignment");
_Static_assert(offsetof(struct mmsghdr, msg_hdr) == 0, "header offset");
_Static_assert(offsetof(struct mmsghdr, msg_len) == 56, "length offset");
_Static_assert(sizeof(((struct mmsghdr *)0)->msg_len) == 4, "length size");

int main(void) { return 0; }
