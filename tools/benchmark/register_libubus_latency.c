/* Registration latency diagnostic using the exact image's libubus/libubox.
 * Two monotonic reads bracket each ADD + REMOVE cycle. Clock overhead is
 * retained. This is a separate workload from the frozen Rust caller and the
 * original registration CPU diagnostic; their results must not be pooled.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libubus.h>

static void require(int ok, const char *message)
{
    if (!ok) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static unsigned number(const char *s, unsigned max)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    require(*s && !*end && !errno && n <= max, "invalid numeric argument");
    return n;
}

static uint64_t read_clock(clockid_t id, int resolution)
{
    struct timespec t;
    int rc = resolution ? clock_getres(id, &t) : clock_gettime(id, &t);
    require(!rc && t.tv_sec >= 0 && t.tv_nsec >= 0 && t.tv_nsec < 1000000000,
            "clock read failed");
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}

static int compare_ns(const void *a, const void *b)
{
    uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;
    return (left > right) - (left < right);
}

/* Same index convention as the Rust benchmark: round((n - 1) * fraction),
 * with halves rounded upward. */
static uint64_t percentile(const uint64_t *ordered, unsigned n, unsigned percent)
{
    return ordered[((uint64_t)(n - 1) * percent + 50) / 100];
}

static void check_affinity(pid_t pid, int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    require(!sched_getaffinity(pid, sizeof(set), &set), "affinity read failed");
    require(CPU_COUNT(&set) == 1 && CPU_ISSET(cpu, &set), "unexpected affinity");
}

struct lookup_check {
    struct ubus_object *object;
    struct blob_attr *signature;
    unsigned count;
};

static void check_lookup(struct ubus_context *ctx, struct ubus_object_data *data,
                         void *priv)
{
    (void)ctx;
    struct lookup_check *check = priv;
    check->count++;
    if (!check->object)
        return;
    require(data->id == check->object->id && data->type_id == check->object->type->id
            && !strcmp(data->path, check->object->name), "lookup identity mismatch");
    require(data->signature && blob_len(data->signature) == blob_len(check->signature)
            && !memcmp(blob_data(data->signature), blob_data(check->signature),
                       blob_len(check->signature)), "lookup signature mismatch");
}

static void add(struct ubus_context *ctx, struct ubus_object *obj)
{
    require(!obj->id && !obj->type->id, "registration unexpectedly reuses a type");
    require(!ubus_add_object(ctx, obj) && obj->id && obj->type->id, "ADD_OBJECT failed");
}

static void remove_object(struct ubus_context *ctx, struct ubus_object *obj)
{
    require(!ubus_remove_object(ctx, obj) && !obj->id && !obj->type->id,
            "REMOVE_OBJECT failed or last type remained cached");
}

static void empty_lookup(struct ubus_context *ctx)
{
    struct lookup_check check = {0};
    require(!ubus_lookup(ctx, NULL, check_lookup, &check) && !check.count,
            "registration left a visible object");
}

int main(int argc, char **argv)
{
    if (argc >= 4 && !strcmp(argv[1], "exec-cpu")) {
        unsigned cpu = number(argv[2], 1);
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        require(!sched_setaffinity(0, sizeof(set), &set), "exec pin failed");
        check_affinity(0, (int)cpu);
        execvp(argv[3], &argv[3]);
        perror("execvp");
        return 1;
    }
    require(argc == 5, "usage: register-libubus-latency SOCKET N WARMUP SUBJECT_PID");
    unsigned n = number(argv[2], 1000000), warmup = number(argv[3], 100000);
    pid_t subject = (pid_t)number(argv[4], INT_MAX);
    require(n && subject > 0 && subject != getpid(), "invalid loop count or subject");
    /* Pin only this newly created client; the harness pins its own daemon. */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    require(!sched_setaffinity(0, sizeof(mask), &mask), "client pin failed");
    check_affinity(0, 0);
    check_affinity(subject, 1);
    clockid_t subject_clock;
    require(!clock_getcpuclockid(subject, &subject_clock), "subject CPU clock unavailable");
    uint64_t subject_resolution = read_clock(subject_clock, 1);
    uint64_t client_resolution = read_clock(CLOCK_PROCESS_CPUTIME_ID, 1);
    uint64_t wall_resolution = read_clock(CLOCK_MONOTONIC, 1);
    require(subject_resolution && client_resolution && wall_resolution,
            "zero clock resolution");
    struct ubus_context *ctx = ubus_connect(argv[1]);
    require(ctx != NULL, "connect failed");
    static const struct blobmsg_policy policy[] = {{"policy", BLOBMSG_TYPE_INT32}};
    static const struct ubus_method method = {
        .name = "00000000", .policy = policy, .n_policy = 1,
    };
    struct ubus_object_type type = {.name = "bench.cycle", .methods = &method, .n_methods = 1};
    struct ubus_object obj = {.name = "bench.cycle", .type = &type, .methods = &method, .n_methods = 1};
    struct blob_buf expected = {0};
    blob_buf_init(&expected, 0);
    void *table = blobmsg_open_table(&expected, method.name);
    require(table && !blobmsg_add_u32(&expected, policy[0].name, policy[0].type),
            "expected signature allocation failed");
    blobmsg_close_table(&expected, table);
    add(ctx, &obj);
    struct lookup_check check = {.object = &obj, .signature = expected.head};
    require(!ubus_lookup(ctx, obj.name, check_lookup, &check) && check.count == 1,
            "preflight lookup failed");
    remove_object(ctx, &obj);
    empty_lookup(ctx);
    uint64_t *latency_ns = calloc(n, sizeof(*latency_ns));
    require(latency_ns != NULL, "latency sample allocation failed");
    volatile uint64_t *touch = latency_ns;
    for (unsigned i = 0; i < n; i++)
        touch[i] = 0;
    for (unsigned i = 0; i < warmup; i++) {
        add(ctx, &obj);
        remove_object(ctx, &obj);
    }
    uint64_t wall_before = read_clock(CLOCK_MONOTONIC, 0);
    uint64_t client_before = read_clock(CLOCK_PROCESS_CPUTIME_ID, 0);
    uint64_t subject_before = read_clock(subject_clock, 0);
    for (unsigned i = 0; i < n; i++) {
        uint64_t before = read_clock(CLOCK_MONOTONIC, 0);
        add(ctx, &obj);
        remove_object(ctx, &obj);
        uint64_t after = read_clock(CLOCK_MONOTONIC, 0);
        require(after > before, "non-increasing operation clock");
        latency_ns[i] = after - before;
    }
    uint64_t subject_after = read_clock(subject_clock, 0);
    uint64_t client_after = read_clock(CLOCK_PROCESS_CPUTIME_ID, 0);
    uint64_t wall_after = read_clock(CLOCK_MONOTONIC, 0);
    require(subject_after > subject_before && client_after > client_before
            && wall_after > wall_before, "non-increasing measured clock");
    check_affinity(0, 0);
    check_affinity(subject, 1);
    empty_lookup(ctx);
    add(ctx, &obj);
    check.count = 0;
    require(!ubus_lookup(ctx, obj.name, check_lookup, &check) && check.count == 1,
            "final signature lookup failed");
    remove_object(ctx, &obj);
    empty_lookup(ctx);
    blob_buf_free(&expected);
    ubus_free(ctx);
    uloop_done();
    uint64_t *ordered = malloc(n * sizeof(*ordered));
    require(ordered != NULL, "percentile allocation failed");
    memcpy(ordered, latency_ns, n * sizeof(*ordered));
    qsort(ordered, n, sizeof(*ordered), compare_ns);
    uint64_t sum_ns = 0;
    for (unsigned i = 0; i < n; i++) {
        require(UINT64_MAX - sum_ns >= latency_ns[i], "latency sum overflow");
        sum_ns += latency_ns[i];
    }
    printf("{\"n\":%u,\"warmup\":%u,\"subject_pid\":%d,\"client_pid\":%d,"
           "\"subject_cpu\":1,\"client_cpu\":0,\"subject_resolution_ns\":%" PRIu64 ","
           "\"client_resolution_ns\":%" PRIu64 ",\"subject_before_ns\":%" PRIu64 ","
           "\"subject_after_ns\":%" PRIu64 ",\"client_before_ns\":%" PRIu64 ","
           "\"client_after_ns\":%" PRIu64 ",\"wall_before_ns\":%" PRIu64 ","
           "\"wall_after_ns\":%" PRIu64 ",\"full_signature_checked\":true,"
           "\"last_type_reset_checked_each_cycle\":true,\"final_empty\":true,"
           "\"final_signature_checked\":true,\"successful\":%u,\"errors\":0,"
           "\"latency_clock\":\"CLOCK_MONOTONIC\",\"latency_resolution_ns\":%" PRIu64 ","
           "\"latency_overhead_unsubtracted\":true,\"latency_sample_count\":%u,"
           "\"latency_quantile\":\"ordered[round((n-1)*q)]\","
           "\"mean_us\":%.9f,\"p50_us\":%.9f,\"p95_us\":%.9f,\"p99_us\":%.9f,"
           "\"latency_ns\":[",
           n, warmup, subject, getpid(), subject_resolution, client_resolution,
           subject_before, subject_after, client_before, client_after, wall_before, wall_after,
           n, wall_resolution, n, (double)sum_ns / n / 1000.0,
           (double)percentile(ordered, n, 50) / 1000.0,
           (double)percentile(ordered, n, 95) / 1000.0,
           (double)percentile(ordered, n, 99) / 1000.0);
    for (unsigned i = 0; i < n; i++)
        printf("%s%" PRIu64, i ? "," : "", latency_ns[i]);
    printf("]}\n");
    free(ordered);
    free(latency_ns);
    return 0;
}
