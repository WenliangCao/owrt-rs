
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int copy_file(const char *from, const char *to) {
    int input = open(from, O_RDONLY), output;
    if (input < 0) return 1;
    output = open(to, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (output < 0) { close(input); return 1; }
    char buffer[8192];
    ssize_t count;
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t done = 0;
        while (done < count) {
            ssize_t written = write(output, buffer + done, count - done);
            if (written <= 0) return 1;
            done += written;
        }
    }
    int failed = count < 0 || fsync(output) != 0;
    close(output); close(input);
    return failed;
}

int main(int argc, char **argv) {
    /* install_bin's ldd fallback may execute a static program. */
    if (getpid() != 1) return 0;
    /* Exact upgraded starts by escaping its prefix with its retained cwd.
       Stay inside the fixture's old root; never execute stage2 or reboot. */
    if (chroot(".") || chdir("/")) return 21;
    int fd = open("/tmp/handoff-out/upgraded.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 22;
    FILE *out = fdopen(fd, "w");
    if (!out) return 23;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    fprintf(out, "pid=%ld\nargc=%d\nmonotonic=%.9f\n", (long)getpid(), argc,
            now.tv_sec + now.tv_nsec / 1e9);
    for (int i = 0; i < argc; i++) fprintf(out, "argv%d=%s\n", i, argv[i]);
    const char *names[] = {"UPGRADE_BACKUP", "UPGRADE_OPT_SAVE_PARTITIONS",
                          "UPGRADE_OPT_ADD_PROVISIONING", "WDTFD", NULL};
    for (int i = 0; names[i]; i++) {
        const char *value = getenv(names[i]);
        if (value) fprintf(out, "%s=%s\n", names[i], value);
    }
    fflush(out); fsync(fd); fclose(out);
    const char *backup = getenv("UPGRADE_BACKUP");
    if (!backup || copy_file(backup, "/tmp/handoff-out/actual-backup.tar.gz")) return 24;
    sync();
    return 0;
}
