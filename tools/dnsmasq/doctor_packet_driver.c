/* Unchanged exact rfc1035.o / do_doctor, with a deterministic callback
 * transport. Actual C blobmsg payloads are observed through matching libubox.
 * Reply storage remains alive until do_doctor consumes the address, so this
 * fixture does not reproduce the separate libubus receive-buffer lifetime bug.
 */
#include "dnsmasq.h"
#include <libubox/blobmsg.h>
#include <assert.h>
#include <inttypes.h>

static struct blob_buf request_buf, response_buf;
static int enabled, awaiting_parse;
static unsigned static_writes, ubus_writes, notifications;
static char *replies;

static void hex(const void *data, size_t length)
{
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

int __real_inet_pton(int family, const char *text, void *address);
int __wrap_inet_pton(int family, const char *text, void *address)
{
    int observed = awaiting_parse;
    awaiting_parse = 0;
    int result = __real_inet_pton(family, text, address);
    if (observed && result == 1) ubus_writes++;
    return result;
}

void __real_log_query(unsigned int flags, char *name, union all_addr *addr, char *arg, unsigned short type);
void __wrap_log_query(unsigned int flags, char *name, union all_addr *addr, char *arg, unsigned short type)
{
    if ((flags & (F_FORWARD | F_CONFIG | F_IPV4)) == (F_FORWARD | F_CONFIG | F_IPV4)) static_writes++;
    __real_log_query(flags, name, addr, arg, type);
}

char *ubus_init(void) { return NULL; }
void set_ubus_listeners(void) {}
void check_ubus_listeners(void) {}
void drop_ubus_listeners(void) { enabled = 0; }
int ubus_dns_notify_has_subscribers(void) { return enabled; }
struct blob_buf *ubus_dns_notify_prepare(void)
{
    if (!enabled) return NULL;
    blob_buf_init(&request_buf, 0);
    return &request_buf;
}
void ubus_event_bcast(const char *type, const char *mac, const char *ip, const char *name, const char *interface)
{ (void)type; (void)mac; (void)ip; (void)name; (void)interface; }

int ubus_dns_notify(const char *type, ubus_dns_notify_cb callback, void *private_data)
{
    struct blobmsg_policy policy[] = {
        {"name", BLOBMSG_TYPE_STRING}, {"ttl", BLOBMSG_TYPE_INT32},
        {"type", BLOBMSG_TYPE_STRING}, {"address", BLOBMSG_TYPE_STRING},
    };
    struct blob_attr *values[4];
    assert(!strcmp(type, "dns_result"));
    assert(!blobmsg_parse(policy, 4, values, blob_data(request_buf.head), blob_len(request_buf.head)));
    for (int i = 0; i < 4; i++) assert(values[i]);
    int family = !strcmp(blobmsg_get_string(values[2]), "A") ? AF_INET : AF_INET6;
    unsigned char address[16];
    assert(__real_inet_pton(family, blobmsg_get_string(values[3]), address) == 1);
    const char *name = blobmsg_get_string(values[0]);
    printf("E "); hex(name, strlen(name));
    printf(" %" PRIu32 " %d ", blobmsg_get_u32(values[1]), family == AF_INET ? 4 : 6);
    hex(address, family == AF_INET ? 4 : 16); putchar('\n');
    notifications++;
    char *response = strsep(&replies, ",");
    if (response && strcmp(response, "-")) {
        if (!strcmp(response, "=")) response = blobmsg_get_string(values[3]);
        blob_buf_init(&response_buf, 0);
        blobmsg_add_string(&response_buf, "address", response);
        callback(response_buf.head, private_data);
        awaiting_parse = 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    rand_init(); read_opts(argc, argv, "doctor-packet-oracle");
    for (struct doctor *rule = daemon->doctors; rule; rule = rule->next) {
        printf("D "); hex(&rule->in, 4); putchar(' '); hex(&rule->end, 4); putchar(' ');
        hex(&rule->out, 4); putchar(' '); hex(&rule->mask, 4); putchar('\n');
    }
    char *line = NULL;
    size_t capacity = 0;
    while (getline(&line, &capacity, stdin) >= 0) {
        char *cursor = line;
        char *mode = strsep(&cursor, " ");
        char *encoded = strsep(&cursor, " ");
        assert(mode && encoded && cursor);
        cursor[strcspn(cursor, "\r\n")] = 0;
        replies = cursor;
        enabled = atoi(mode);
        size_t length = strlen(encoded) / 2;
        assert(length >= sizeof(struct dns_header) && length <= 65535 && !(strlen(encoded) % 2));
        unsigned char *packet = calloc(1, length); assert(packet);
        for (size_t i = 0; i < length; i++) {
            unsigned value; assert(sscanf(encoded + 2 * i, "%2x", &value) == 1); packet[i] = value;
        }
        static_writes = ubus_writes = notifications = 0;
        int result = do_doctor((struct dns_header *)packet, length, daemon->namebuff);
        printf("R %d %u %u %u ", result, static_writes, ubus_writes, notifications);
        hex(packet, length); putchar('\n'); fflush(stdout);
        free(packet);
    }
    free(line); blob_buf_free(&request_buf); blob_buf_free(&response_buf);
    return 0;
}
