/*
 * Direct user-event CPU diagnostic using the exact image's libubus/libubox.
 * The daemon under test is the only process whose CPU clock is timed. The
 * listener is pumped synchronously so every matched event is validated before
 * the next one is sent. Run only in the disposable router namespace.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

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
	return (unsigned)n;
}

static uint64_t read_clock(clockid_t id, int resolution)
{
	struct timespec t;
	int rc = resolution ? clock_getres(id, &t) : clock_gettime(id, &t);
	require(!rc && t.tv_sec >= 0 && t.tv_nsec >= 0 && t.tv_nsec < 1000000000,
			"clock read failed");
	return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}

static void check_affinity(pid_t pid, int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	require(!sched_getaffinity(pid, sizeof(set), &set), "affinity read failed");
	require(CPU_COUNT(&set) == 1 && CPU_ISSET(cpu, &set), "unexpected affinity");
}

static unsigned subject_fds(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	DIR *dir = opendir(path);
	require(dir != NULL, "subject fd directory unavailable");
	unsigned count = 0;
	struct dirent *entry;
	errno = 0;
	while ((entry = readdir(dir)))
		if (entry->d_name[0] != '.')
			count++;
	require(!errno, "subject fd directory read failed");
	require(!closedir(dir), "subject fd directory close failed");
	return count;
}

struct event_state {
	unsigned received;
	unsigned bad;
	char first_type[32];
	int first_value;
	unsigned first_attr_type;
};

static struct event_state *current_state;

static void receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
				  const char *type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy = {
		.name = "value", .type = BLOBMSG_TYPE_INT32,
	};
	struct blob_attr *tb[1] = {0};
	(void)ctx;
	(void)ev;
	current_state->received++;
	if (!type || strcmp(type, "bench.user") || !msg ||
		blobmsg_parse(&policy, 1, tb, blobmsg_data(msg), blobmsg_data_len(msg)) != 0 ||
		!tb[0] || blobmsg_get_u32(tb[0]) != 0x12345678) {
		current_state->bad++;
		if (current_state->bad == 1) {
			if (type)
				snprintf(current_state->first_type, sizeof(current_state->first_type), "%s", type);
			if (tb[0]) {
				current_state->first_value = (int)blobmsg_get_u32(tb[0]);
				current_state->first_attr_type = blobmsg_type(tb[0]);
			}
		}
	}
}

static void pump_until(struct ubus_context *listener, unsigned target)
{
	while (current_state->received < target) {
		struct pollfd pfd = {.fd = listener->sock.fd, .events = POLLIN};
		int rc = poll(&pfd, 1, 5000);
		require(rc > 0 && (pfd.revents & POLLIN) &&
				!(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)),
				"event receive timeout or socket failure");
		ubus_handle_event(listener);
	}
}

static void drain_unmatched(struct ubus_context *listener, unsigned before)
{
	for (;;) {
		struct pollfd pfd = {.fd = listener->sock.fd, .events = POLLIN};
		int rc = poll(&pfd, 1, 0);
		if (!rc)
			break;
		require(rc > 0 && (pfd.revents & POLLIN) &&
				!(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)),
				"unexpected listener socket failure");
		ubus_handle_event(listener);
	}
	require(current_state->received == before, "unmatched event was delivered");
}

static int run_user_event(const char *socket, unsigned listeners, int matched,
			  unsigned n, unsigned warmup, pid_t subject, unsigned held_clients)
{
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
	struct ubus_context *sender = ubus_connect(socket);
	struct ubus_context *listener = ubus_connect(socket);
	require(sender && listener, "connect failed");
	unsigned base_fds = subject_fds(subject);
	struct ubus_context *held[64] = {0};
	for (unsigned i = 0; i < held_clients; i++) {
		held[i] = ubus_connect(socket);
		require(held[i] != NULL, "held connect failed");
		require(ubus_lookup(held[i], "r106.missing", NULL, NULL) == UBUS_STATUS_NOT_FOUND,
				"held connection request validation failed");
	}
	unsigned held_fds = subject_fds(subject);
	require(held_fds == base_fds + held_clients, "held connection count mismatch");

	struct ubus_event_handler handlers[8] = {0};
	struct event_state state = {0};
	current_state = &state;
	for (unsigned i = 0; i < listeners; i++) {
		handlers[i].cb = receive_event;
		const char *pattern = matched ? "bench.user" : "unrelated.*";
		require(!ubus_register_event_handler(listener, &handlers[i], pattern),
				"event handler registration failed");
	}

	struct blob_buf data = {0};
	blob_buf_init(&data, 0);
	require(!blobmsg_add_u32(&data, "value", 0x12345678), "event payload allocation failed");
	unsigned target_per_send = matched ? listeners : 0;
	for (unsigned i = 0; i < warmup; i++) {
		require(!ubus_send_event(sender, "bench.user", data.head), "warmup send failed");
		if (matched)
			pump_until(listener, state.received + target_per_send);
		else
			drain_unmatched(listener, state.received);
	}
	unsigned warmup_received = state.received;
	state.received = 0;
	state.bad = 0;

	uint64_t wall_before = read_clock(CLOCK_MONOTONIC, 0);
	uint64_t client_before = read_clock(CLOCK_PROCESS_CPUTIME_ID, 0);
	uint64_t subject_before = read_clock(subject_clock, 0);
	for (unsigned i = 0; i < n; i++) {
		require(!ubus_send_event(sender, "bench.user", data.head), "timed send failed");
		if (matched)
			pump_until(listener, state.received + target_per_send);
		else
			drain_unmatched(listener, state.received);
	}
	if (!matched)
		drain_unmatched(listener, 0);
	uint64_t subject_after = read_clock(subject_clock, 0);
	uint64_t client_after = read_clock(CLOCK_PROCESS_CPUTIME_ID, 0);
	uint64_t wall_after = read_clock(CLOCK_MONOTONIC, 0);
	require(subject_after > subject_before && client_after > client_before &&
			wall_after > wall_before, "non-increasing measured clock");
	if (state.bad || state.received != (matched ? n * listeners : 0)) {
		fprintf(stderr, "event callback validation failed: received=%u expected=%u bad=%u type=%s value=%d attr_type=%u\n",
				state.received, matched ? n * listeners : 0, state.bad, state.first_type,
				state.first_value, state.first_attr_type);
		exit(1);
	}

	require(subject_fds(subject) == held_fds, "held connections changed during measurement");
	for (unsigned i = 0; i < held_clients; i++) {
		require(ubus_lookup(held[i], "r106.missing", NULL, NULL) == UBUS_STATUS_NOT_FOUND,
				"held connection lost after measurement");
		ubus_free(held[i]);
	}
	for (unsigned i = 0; i < listeners; i++)
		require(!ubus_unregister_event_handler(listener, &handlers[i]),
				"event handler removal failed");
	blob_buf_free(&data);
	ubus_free(listener);
	ubus_free(sender);
	uloop_done();
	printf("{\"n\":%u,\"warmup\":%u,\"listeners\":%u,\"matched\":%s,"
		   "\"subject_pid\":%d,\"client_pid\":%d,\"subject_cpu\":1,\"client_cpu\":0,"
		   "\"subject_resolution_ns\":%" PRIu64 ",\"client_resolution_ns\":%" PRIu64 ","
		   "\"subject_before_ns\":%" PRIu64 ",\"subject_after_ns\":%" PRIu64 ","
		   "\"client_before_ns\":%" PRIu64 ",\"client_after_ns\":%" PRIu64 ","
		   "\"wall_before_ns\":%" PRIu64 ",\"wall_after_ns\":%" PRIu64 ","
		   "\"warmup_received\":%u,\"received\":%u,\"payload_checked\":true,"
		   "\"handlers_removed\":true,\"held_clients\":%u,\"base_fds\":%u,\"held_fds\":%u}\n",
		   n, warmup, listeners, matched ? "true" : "false", subject, getpid(),
		   subject_resolution, client_resolution, subject_before, subject_after,
		   client_before, client_after, wall_before, wall_after, warmup_received,
		   state.received, held_clients, base_fds, held_fds);
	return 0;
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
	require((argc == 8 || argc == 9) && !strcmp(argv[1], "user-event"),
			"usage: user-event SOCKET LISTENERS MATCHED N WARMUP SUBJECT_PID [HELD_CLIENTS]");
	unsigned listeners = number(argv[3], 8);
	unsigned matched = number(argv[4], 1);
	unsigned n = number(argv[5], 1000000);
	unsigned warmup = number(argv[6], 100000);
	pid_t subject = (pid_t)number(argv[7], INT_MAX);
	require(listeners && n && subject > 0 && subject != getpid(), "invalid workload arguments");
	unsigned held_clients = argc == 9 ? number(argv[8], 64) : 0;
	return run_user_event(argv[2], listeners, matched != 0, n, warmup, subject, held_clients);
}
