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
static uint32_t metrics_id;

static void reply_raw(struct ubus_context *ctx, struct ubus_request_data *req,
                      const char *hex_data, size_t chars)
{
    if (chars % 2 || chars > 8192)
        exit(4);
    unsigned char bytes[4096];
    for (size_t i = 0; i < chars / 2; i++) {
        char pair[] = {hex_data[2 * i], hex_data[2 * i + 1], 0};
        char *end;
        bytes[i] = (unsigned char)strtoul(pair, &end, 16);
        if (*end)
            exit(4);
    }
    struct blob_buf b = {0};
    blob_buf_init(&b, 0);
    blob_put_raw(&b, bytes, chars / 2);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
}

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

static void lookup_hex(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
    (void)ctx;
    (void)priv;
    printf("{\"event\":\"lookup\",\"path_hex\":\"");
    hex(obj->path, strlen(obj->path));
    printf("\",\"type\":%u,\"wire\":\"", obj->type_id);
    if (obj->signature)
        hex(blob_data(obj->signature), blob_len(obj->signature));
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
    if (!strcmp(response, "metrics")) {
        struct blob_buf b = {0};
        blob_buf_init(&b, 0);
        int ret = ubus_invoke(ctx, metrics_id, "metrics", b.head, data, NULL, 1000);
        blob_buf_free(&b);
        printf("{\"event\":\"nested-metrics-status\",\"status\":%d}\n", ret);
        fflush(stdout);
        return 0;
    }
    if (!strcmp(response, "silent")) {
        ubus_defer_request(ctx, req, &deferred);
        return 0;
    }
    if (!strcmp(response, "disconnect"))
        _exit(0);
    if (delay_ms)
        usleep(delay_ms * 1000);
    if (!strncmp(response, "raw:", 4) || !strncmp(response, "rawsilent:", 10)) {
        const char *value = strchr(response, ':') + 1;
        do {
            const char *end = strchr(value, ',');
            reply_raw(ctx, req, value, end ? (size_t)(end - value) : strlen(value));
            value = end ? end + 1 : NULL;
        } while (value);
        if (!strncmp(response, "rawsilent:", 10))
            ubus_defer_request(ctx, req, &deferred);
        return 0;
    }
    if (!strcmp(response, "error"))
        return UBUS_STATUS_INVALID_ARGUMENT;
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
    } else if (!strcmp(argv[2], "lookup-hex")) {
        ret = ubus_lookup(ctx, argv[3], lookup_hex, NULL);
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
            if (!strcmp(response, "metrics")) {
                size_t length = strlen(argv[3]);
                if (length < 4 || strcmp(argv[3] + length - 4, ".dns"))
                    return 2;
                char *main_path = strndup(argv[3], length - 4);
                if (!main_path)
                    return 3;
                ret = ubus_lookup_id(ctx, main_path, &metrics_id);
                free(main_path);
                if (ret || !metrics_id)
                    goto done;
            }
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
