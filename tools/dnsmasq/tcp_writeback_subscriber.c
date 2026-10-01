/* Private gate: hold a real DNS doctor callback, then queue metrics before
 * returning it. The control socket is inherited from the isolated harness. */
#include <libubus.h>
#include <libubox/uloop.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int control;
static uint32_t metrics_id;
static struct ubus_request metrics;

static unsigned long long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static void marker(char c)
{
    fflush(stdout);
    if (write(control, &c, 1) != 1)
        _exit(4);
}

static void wire(const char *event, struct blob_attr *msg)
{
    const unsigned char *bytes = blob_data(msg);
    printf("{\"event\":\"%s\",\"ns\":%llu,\"wire\":\"", event, now_ns());
    for (unsigned i = 0; i < blob_len(msg); i++)
        printf("%02x", bytes[i]);
    puts("\"}");
}

static void data(struct ubus_request *req, int type, struct blob_attr *msg)
{
    (void)req;
    (void)type;
    wire("metrics", msg);
}

static void complete(struct ubus_request *req, int status)
{
    (void)req;
    printf("{\"event\":\"metrics-complete\",\"ns\":%llu,\"status\":%d}\n", now_ns(), status);
    marker('m');
}

static int notify(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    (void)obj;
    if (strcmp(method, "dns_result"))
        return UBUS_STATUS_INVALID_ARGUMENT;
    wire("notify", msg);
    marker('n');
    struct pollfd fd = {.fd = control, .events = POLLIN};
    char command = 0;
    if (poll(&fd, 1, 2000) != 1 || read(control, &command, 1) != 1 || command != 'r')
        _exit(5);
    printf("{\"event\":\"release\",\"ns\":%llu}\n", now_ns());
    struct blob_buf b = {0};
    blob_buf_init(&b, 0);
    int ret = ubus_invoke_async(ctx, metrics_id, "metrics", b.head, &metrics);
    if (ret)
        _exit(6);
    metrics.data_cb = data;
    metrics.complete_cb = complete;
    ubus_complete_request_async(ctx, &metrics);
    printf("{\"event\":\"metrics-queued\",\"ns\":%llu}\n", now_ns());
    marker('q');
    blobmsg_add_string(&b, "address", "192.0.2.250");
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    return 0;
}

static void stop(int sig)
{
    (void)sig;
    uloop_end();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strncmp(argv[1], "/run/", 5))
        return 2;
    control = atoi(argv[4]);
    struct ubus_context *ctx = ubus_connect(argv[1]);
    uint32_t dns_id = 0;
    if (!ctx || ubus_lookup_id(ctx, argv[2], &metrics_id) ||
        ubus_lookup_id(ctx, argv[3], &dns_id))
        return 3;
    uloop_init();
    ubus_add_uloop(ctx);
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    struct ubus_subscriber sub = {.cb = notify};
    int ret = ubus_register_subscriber(ctx, &sub);
    if (!ret)
        ret = ubus_subscribe(ctx, &sub, dns_id);
    printf("{\"event\":\"ready\",\"ns\":%llu,\"status\":%d}\n", now_ns(), ret);
    marker('r');
    if (!ret)
        uloop_run();
    uloop_done();
    ubus_free(ctx);
    close(control);
    return ret;
}
