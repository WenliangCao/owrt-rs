/* Match the existing protocol even on images without a nice executable. */
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2 || setpriority(PRIO_PROCESS, 0, 10) != 0 || getpriority(PRIO_PROCESS, 0) != 10) {
        perror("setpriority nice 10");
        return 2;
    }
    execvp(argv[1], argv + 1);
    perror("exec measurement group");
    return 2;
}
