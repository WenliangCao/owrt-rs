/* Compile with -DPROCD_WATCHDOG_SOURCE='"/exact/procd/watchdog.c"' and
 * -I/path/to/exact/components. Only ioctl and the event timer are injected;
 * the matching production watchdog.c is included without editing it. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>
#include <libubox/uloop.h>

int uloop_timeout_set(struct uloop_timeout *t, int msecs) { t->pending = true; return 0; }
int uloop_timeout_cancel(struct uloop_timeout *t) { t->pending = false; return 0; }
static int injected_ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *value = va_arg(ap, void *);
    va_end(ap);
    if (request == WDIOC_SETTIMEOUT) { *(int *)value = 20; return 0; }
    return -1;
}
#define __PROCD_H
#define DEBUG(...) ((void)0)
#define LOG(...) ((void)0)
#define ERROR(...) ((void)0)
#define ioctl injected_ioctl
#include PROCD_WATCHDOG_SOURCE

int main(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 2;
    char number[32];
    snprintf(number, sizeof(number), "%d", pair[0]);
    setenv("WDTFD", number, 1);
    watchdog_init(0);
    int initial = watchdog_timeout(0);
    int adjusted = watchdog_timeout(17);
    printf("init=%d set=%d\n", initial, adjusted);
    return 0;
}
