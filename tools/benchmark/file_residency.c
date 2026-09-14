/* Read-only file-cache observation: mmap(PROT_NONE) + mincore never faults
 * file contents in. Count by (device,inode) when aggregating output. Values
 * describe page-cache residency, not exclusive process RSS or reclaimability.
 * Diagnostic helper only. Record compiler and binary identity separately;
 * build with a Linux target compiler, -Os -static -Wall -Wextra -Werror. */
#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    long page = sysconf(_SC_PAGESIZE);
    if (argc < 2 || page <= 0) return 2;
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY | O_CLOEXEC);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
            perror(argv[i]);
            if (fd >= 0) close(fd);
            return 1;
        }
        size_t pages = ((size_t)st.st_size + (size_t)page - 1) / (size_t)page;
        unsigned char *vec = calloc(pages, 1);
        void *area = mmap(NULL, (size_t)st.st_size, PROT_NONE, MAP_PRIVATE, fd, 0);
        if (!vec || area == MAP_FAILED || mincore(area, (size_t)st.st_size, vec)) {
            perror("file residency");
            return 1;
        }
        size_t resident = 0;
        for (size_t j = 0; j < pages; j++) resident += (vec[j] & 1) != 0;
        printf("%ju\t%ju\t%ju\t%zu\t%zu\t%ld\t%s\n", (uintmax_t)st.st_dev,
               (uintmax_t)st.st_ino, (uintmax_t)st.st_size, pages, resident, page, argv[i]);
        munmap(area, (size_t)st.st_size);
        free(vec);
        close(fd);
    }
    return 0;
}
