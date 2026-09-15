/* Every value below is what a #[repr(C)] struct in this repository assumes
 * about the target ABI. Nothing here runs: if it compiles for the device's
 * target, the hand-written FFI declarations match the C library it will call.
 *
 * A layout mismatch is the one class of defect in this code base that fails
 * silently -- the compiler cannot see it and the daemons would simply read and
 * write the wrong offsets -- so it gets a compile-time check rather than a
 * runtime test. Build it with the SDK's cross compiler: `make check-abi`.
 */
#define _GNU_SOURCE
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <dirent.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <poll.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <stddef.h>
#include <errno.h>

#define A(c) _Static_assert((c), #c)

/* The whole file assumes a little-endian LP64 target. Two of the structs below
 * -- msghdr and the ucred/statvfs pairs -- are only laid out this way there. */
A(__BYTE_ORDER == __LITTLE_ENDIAN);
A(sizeof(void *) == 8);
A(sizeof(long) == 8);

/* components/rpcd/src/util.rs: StatVfs */
A(sizeof(struct statvfs) == 112);
A(offsetof(struct statvfs, f_bsize) == 0);
A(offsetof(struct statvfs, f_blocks) == 16);
A(offsetof(struct statvfs, f_bfree) == 24);
A(offsetof(struct statvfs, f_fsid) == 64);
A(offsetof(struct statvfs, f_flag) == 72);
A(offsetof(struct statvfs, f_namemax) == 80);

/* components/rpcd/src/util.rs: machine() reads [u8; 6*65] at 4*65 */
A(sizeof(struct utsname) == 390);
A(offsetof(struct utsname, machine) == 260);

/* components/ubus/src/sys.rs and components/ubusd/src/sys.rs: MsgHdr.
 * iovlen and controllen are `int` plus padding in musl; a usize occupies the
 * same slot only on a little-endian LP64 target, which is asserted above. */
A(sizeof(struct msghdr) == 56);
A(offsetof(struct msghdr, msg_name) == 0);
A(offsetof(struct msghdr, msg_namelen) == 8);
A(offsetof(struct msghdr, msg_iov) == 16);
A(offsetof(struct msghdr, msg_iovlen) == 24);
A(offsetof(struct msghdr, msg_control) == 32);
A(offsetof(struct msghdr, msg_controllen) == 40);
A(offsetof(struct msghdr, msg_flags) == 48);

/* IoVec and PollFd, plus the poll event bits the code hardcodes */
A(sizeof(struct iovec) == 16);
A(offsetof(struct iovec, iov_len) == 8);
A(sizeof(struct pollfd) == 8);
A(offsetof(struct pollfd, events) == 4);
A(offsetof(struct pollfd, revents) == 6);
A(POLLIN == 0x001);
A(POLLOUT == 0x004);
A(POLLERR == 0x008);
A(POLLHUP == 0x010);

/* components/rpcd/src/readiness.rs and its Linux-only CPU diagnostic */
A(sizeof(struct epoll_event) == 16);
A(offsetof(struct epoll_event, data) == 8);
A(EPOLL_CLOEXEC == 0x80000);
A(EPOLL_CTL_ADD == 1);
A(EPOLLIN == 1);
A(CLOCK_THREAD_CPUTIME_ID == 3);
A(sizeof(struct timespec) == 16);
A(offsetof(struct timespec, tv_nsec) == 8);

/* components/uci/src/file.rs: borrowed Linux directory names */
A(sizeof(struct dirent) == 280);
A(offsetof(struct dirent, d_type) == 18);
A(offsetof(struct dirent, d_name) == 19);
A(DT_UNKNOWN == 0);
A(DT_DIR == 4);
A(DT_LNK == 10);

/* the cmsg arithmetic in both sys.rs files */
A(sizeof(struct cmsghdr) == 16);
A(CMSG_SPACE(sizeof(int)) == 24);
A(CMSG_LEN(sizeof(int)) == 20);
A(SOL_SOCKET == 1);
A(SCM_RIGHTS == 1);
A(MSG_DONTWAIT == 0x40);
A(SO_PEERCRED == 17);

/* components/ubusd/src/sys.rs: Ucred */
A(sizeof(struct ucred) == 12);
A(offsetof(struct ucred, pid) == 0);
A(offsetof(struct ucred, uid) == 4);
A(offsetof(struct ucred, gid) == 8);

/* components/rpcd/src/rtnl.rs and iwinfo/sys.rs: SockaddrNl */
A(sizeof(struct sockaddr_nl) == 12);
A(offsetof(struct sockaddr_nl, nl_pid) == 4);
A(offsetof(struct sockaddr_nl, nl_groups) == 8);

/* components/httpd/src/main.rs: SockAddrIn6 */
A(sizeof(struct sockaddr_in6) == 28);
A(offsetof(struct sockaddr_in6, sin6_flowinfo) == 4);
A(offsetof(struct sockaddr_in6, sin6_addr) == 8);
A(offsetof(struct sockaddr_in6, sin6_scope_id) == 24);

/* components/rpcd/src/iwinfo/sys.rs: SockaddrUn, Ifreq, Timeval, FdSet.
 * components/ubusd/src/sys.rs uses the same sockaddr_un layout. */
A(sizeof(struct sockaddr_un) == 110);
A(offsetof(struct sockaddr_un, sun_path) == 2);
A(sizeof(((struct sockaddr_un *)0)->sun_path) == 108);
A(sizeof(struct ifreq) == 40);
A(IFNAMSIZ == 16);
A(sizeof(struct timeval) == 16);
A(offsetof(struct timeval, tv_usec) == 8);
A(sizeof(fd_set) == 128);

/* components/rpcd/src/luci.rs: Tm */
A(sizeof(struct tm) == 56);
A(offsetof(struct tm, tm_sec) == 0);
A(offsetof(struct tm, tm_gmtoff) == 40);
A(offsetof(struct tm, tm_zone) == 48);

/* components/ubusd/src/sys.rs: Stat reads mode/uid/gid, and the mode bits the
 * ACL loader tests */
A(offsetof(struct stat, st_mode) == 16);
A(offsetof(struct stat, st_uid) == 24);
A(offsetof(struct stat, st_gid) == 28);
A(S_IFMT == 0170000);
A(S_IFREG == 0100000);
A(S_IWGRP == 0020);
A(S_IWOTH == 0002);
A(S_IXOTH == 0001);

/* components/ubusd/src/sys.rs: Passwd and Group read only the first member */
A(offsetof(struct passwd, pw_name) == 0);
A(offsetof(struct group, gr_name) == 0);

/* socket() flag values both sys.rs files hardcode */
A(AF_UNIX == 1);
A(SOCK_STREAM == 1);
A(SOCK_CLOEXEC == 02000000);
A(SOCK_NONBLOCK == 04000);

/* components/ubus/src/connect.rs: nonblocking Unix admission and SO_ERROR. */
A(sizeof(socklen_t) == 4);
A(SO_ERROR == 4);
A(EINTR == 4);
A(EAGAIN == 11);
A(EINPROGRESS == 115);
A(EALREADY == 114);
A(EISCONN == 106);

int main(void) { return 0; }
