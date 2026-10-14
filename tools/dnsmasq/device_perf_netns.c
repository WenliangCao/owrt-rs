/* Measurement helper only. Never fall back to the caller's network namespace.
 * Build with the image SDK: cc -Os -static -Wall -Wextra -Werror ...
 * Usage: device_perf_netns COMMAND [ARG...]
 * Only the fresh namespace's loopback is brought up. No host link is changed.
 * The caller owns the command's lifetime and temporary files.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fputs("usage: device_perf_netns COMMAND [ARG...]\n", stderr);
        return 2;
    }
    struct stat before, after;
    if (stat("/proc/self/ns/net", &before)) {
        perror("initial network namespace");
        return 2;
    }
    if (unshare(CLONE_NEWNET)) {
        perror("unshare(CLONE_NEWNET); command NOT executed");
        return 2;
    }
    if (stat("/proc/self/ns/net", &after) ||
        (before.st_dev == after.st_dev && before.st_ino == after.st_ino)) {
        fputs("network namespace identity did not change; command NOT executed\n", stderr);
        return 2;
    }
    struct if_nameindex *interfaces = if_nameindex();
    if (!interfaces) {
        perror("if_nameindex");
        return 2;
    }
    unsigned count = 0;
    int unexpected = 0;
    for (struct if_nameindex *it = interfaces; it->if_index; ++it) {
        ++count;
        if (strcmp(it->if_name, "lo")) unexpected = 1;
    }
    if_freenameindex(interfaces);
    if (count != 1 || unexpected) {
        fputs("fresh namespace is not loopback-only; command NOT executed\n", stderr);
        return 2;
    }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    memcpy(request.ifr_name, "lo", 3);
    if (fd < 0 || ioctl(fd, SIOCGIFFLAGS, &request)) {
        perror("read isolated loopback flags");
        return 2;
    }
    request.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &request)) {
        perror("enable isolated loopback");
        return 2;
    }
    close(fd);
    fprintf(stderr, "isolated_netns parent=%lu child=%lu loopback_only=true\n",
            (unsigned long)before.st_ino, (unsigned long)after.st_ino);
    execvp(argv[1], argv + 1);
    perror("exec isolated command");
    return errno == ENOENT ? 127 : 126;
}
