/* Diagnostic only: request eviction of clean pages for explicitly selected
 * inactive reference files. This does not write bytes or drop global caches.
 * The caller must exclude every active executable inode and record mincore
 * before/after; POSIX_FADV_DONTNEED is advice, not proof of reclamation.
 * Build with a Linux target compiler, -Os -static -Wall -Wextra -Werror. */
#define _POSIX_C_SOURCE 200112L
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        struct stat before, after;
        if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode)) return 1;
        int error = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        if (error) { fprintf(stderr, "%s: %s\n", argv[i], strerror(error)); return 1; }
        if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            before.st_size != after.st_size || before.st_mtime != after.st_mtime) return 1;
        close(fd);
        printf("advised-clean-pages\t%s\n", argv[i]);
    }
    return 0;
}
