/* Isolated test client, linked to the image-matching libubus/libubox.
 * It observes real daemon methods and answers real subscription requests.
 * Wire payloads are retained so Python can check blob type, width and order.
 */
#include <libubus.h>
#include <libubox/uloop.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *response;
static unsigned delay_ms;
static struct ubus_request_data deferred;

static void hex(const void *data, size_t length)
{
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; i++)
        printf("%02x", bytes[i]);
}

static void lookup(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
    (void)ctx;
    (void)priv;
    /* Paths in this fixture are fixed ASCII, never user supplied config. */
    printf("{\"event\":\"lookup\",\"path\":\"%s\",\"type\":%u,\"wire\":\"", obj->path, obj->type_id);
    if (obj->signature)
        hex(blob_data(obj->signature), blob_len(obj->signature));
    puts("\"}");
}

static void data(struct ubus_request *req, int type, struct blob_attr *msg)
{
    (void)req;
    (void)type;
    printf("{\"event\":\"data\",\"wire\":\"");
    hex(blob_data(msg), blob_len(msg));
    puts("\"}");
}

static int notify(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    (void)obj;
    printf("{\"event\":\"notify\",\"method\":\"%s\",\"wire\":\"", method);
    hex(blob_data(msg), blob_len(msg));
    puts("\"}");
    fflush(stdout);
    if (!strcmp(response, "silent")) {
        ubus_defer_request(ctx, req, &deferred);
        return 0;
    }
    if (!strcmp(response, "disconnect"))
        _exit(0);
    if (delay_ms)
        usleep(delay_ms * 1000);
    if (strcmp(response, "none")) {
        struct blob_buf b = {0};
        blob_buf_init(&b, 0);
        if (!strcmp(response, "u32"))
            blobmsg_add_u32(&b, "address", 1);
        else
            blobmsg_add_string(&b, "address", response);
        ubus_send_reply(ctx, req, b.head);
        blob_buf_free(&b);
    }
    return 0;
}

static void stop(int sig)
{
    (void)sig;
    uloop_end();
}

int main(int argc, char **argv)
{
    if (argc < 4 || strncmp(argv[1], "/run/", 5))
        return 2;
    struct ubus_context *ctx = ubus_connect(argv[1]);
    if (!ctx)
        return 3;
    int ret;
    if (!strcmp(argv[2], "lookup")) {
        ret = ubus_lookup(ctx, argv[3], lookup, NULL);
    } else {
        uint32_t id = 0;
        ret = ubus_lookup_id(ctx, argv[3], &id);
        if (!ret && !id)
            ret = UBUS_STATUS_NO_DATA;
        if (ret)
            goto done;
        if (!strcmp(argv[2], "call") && argc == 5) {
            struct blob_buf b = {0};
            blob_buf_init(&b, 0);
            ret = ubus_invoke(ctx, id, argv[4], b.head, data, NULL, 1000);
            blob_buf_free(&b);
        } else if (!strcmp(argv[2], "watch") && argc == 6) {
            struct ubus_subscriber sub = {.cb = notify};
            response = argv[4];
            delay_ms = (unsigned)strtoul(argv[5], NULL, 10);
            uloop_init();
            ubus_add_uloop(ctx);
            signal(SIGTERM, stop);
            signal(SIGINT, stop);
            ret = ubus_register_subscriber(ctx, &sub);
            if (!ret)
                ret = ubus_subscribe(ctx, &sub, id);
            printf("{\"event\":\"ready\",\"status\":%d}\n", ret);
            fflush(stdout);
            if (!ret)
                uloop_run();
            uloop_done();
        } else {
            ret = 2;
        }
    }
done:
    printf("{\"event\":\"status\",\"status\":%d}\n", ret);
    ubus_free(ctx);
    return 0;
}
