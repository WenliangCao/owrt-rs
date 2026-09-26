/* Read-only socket-buffer diagnostic for an isolated netifd process.
 * pidfd_getfd duplicates descriptors briefly; no messages are read or sent.
 * Run separately from latency collection. Linux 6.12 pidfd/getsockopt ABI.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *isolated = getenv("OWRT_BENCH_NAMESPACE");
    char *end = NULL;
    if (argc != 2 || !isolated || strcmp(isolated, "1")) {
        fprintf(stderr, "requires isolated harness and one subject PID\n");
        return 2;
    }
    errno = 0;
    long pid = strtol(argv[1], &end, 10);
    if (errno || *end || pid <= 1 || pid > 2147483647L)
        return 2;
    int pidfd = syscall(SYS_pidfd_open, (pid_t)pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open");
        return 1;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd", pid);
    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        close(pidfd);
        return 1;
    }
    int count = 0, failed = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;
        errno = 0;
        long target = strtol(entry->d_name, &end, 10);
        if (errno || *end || target < 0 || target > 2147483647L) {
            failed = 1;
            break;
        }
        int fd = syscall(SYS_pidfd_getfd, pidfd, (int)target, 0);
        if (fd < 0) {
            perror("pidfd_getfd");
            failed = 1;
            break;
        }
        int family = 0;
        socklen_t length = sizeof(family);
        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &family, &length) < 0) {
            if (errno != ENOTSOCK) {
                perror("SO_DOMAIN");
                failed = 1;
            }
            close(fd);
            if (failed)
                break;
            continue;
        }
        if (family == AF_NETLINK) {
            int receive = 0, send = 0, protocol = 0;
            struct stat st;
            struct sockaddr_nl address;
            socklen_t addrlen = sizeof(address);
            length = sizeof(int);
            if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive, &length) ||
                getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send, &length) ||
                getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &length) ||
                getsockname(fd, (struct sockaddr *)&address, &addrlen) ||
                fstat(fd, &st)) {
                perror("socket observation");
                failed = 1;
            } else {
                printf("{\"fd\":%ld,\"inode\":%llu,\"protocol\":%d,"
                       "\"portid\":%u,\"groups\":%u,\"rcvbuf\":%d,\"sndbuf\":%d}\n",
                       target, (unsigned long long)st.st_ino, protocol,
                       address.nl_pid, address.nl_groups, receive, send);
                count++;
            }
        }
        close(fd);
        if (failed)
            break;
    }
    closedir(dir);
    close(pidfd);
    if (!count && !failed)
        fprintf(stderr, "no netlink sockets observed\n");
    return failed || !count;
}
