/*
 * Dedicated event memory probe (one handler or eight-handler batch) using the exact image's libubus/libubox.
 * This is a separate ELF: never replace/rebuild the normal CPU client for it.
 * stdin commands: SEND\n, then CLOSE\n. stdout: READY, DELIVERED, CLOSED JSON.
 * Run inside the guarded disposable namespace; no timing benchmark here.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

#define EVENT_NAME "r124.memory"
#define MISSING_OBJECT "r124.memory.no-such-object"
#define SMALL_BYTES 16
#ifndef EVENT_MEMORY_HANDLERS
#define EVENT_MEMORY_HANDLERS 1
#endif
#define HANDLERS EVENT_MEMORY_HANDLERS
_Static_assert(HANDLERS == 1 || HANDLERS == 8, "supported handler counts");
static struct ubus_event_handler handlers[HANDLERS];
static unsigned seen_handlers;
#define MAX_BLOB_BYTES 1048576

static struct {
	struct blob_buf data;
	unsigned payload_bytes, received, total_received;
	size_t data_blob_bytes, request_frame_bytes, relay_frame_bytes;
} state;

static void require(int ok, const char *message)
{
	if (!ok) {
		fprintf(stderr, "%s\n", message);
		exit(1);
	}
}

static void timed_out(int signal_number)
{
	(void)signal_number;
	static const char message[] = "event-memory operation or control timeout\n";
	(void)write(STDERR_FILENO, message, sizeof(message) - 1);
	_exit(124);
}

static unsigned number(const char *text, unsigned max)
{
	char *end;
	errno = 0;
	unsigned long value = strtoul(text, &end, 10);
	require(*text && !*end && !errno && value <= max, "invalid numeric argument");
	return (unsigned)value;
}

static void check_affinity(pid_t pid, unsigned cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	require(!sched_getaffinity(pid, sizeof(mask), &mask), "affinity read failed");
	require(CPU_COUNT(&mask) == 1 && CPU_ISSET(cpu, &mask), "unexpected CPU affinity");
}

static void pin(unsigned cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	require(!sched_setaffinity(0, sizeof(mask), &mask), "CPU pin failed");
	check_affinity(0, cpu);
}

static unsigned subject_fds(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	DIR *dir = opendir(path);
	require(dir != NULL, "subject FD directory unavailable");
	unsigned count = 0;
	struct dirent *entry;
	errno = 0;
	while ((entry = readdir(dir)))
		if (entry->d_name[0] != '.')
			count++;
	require(!errno && !closedir(dir), "subject FD enumeration failed");
	return count;
}

/* Reconstruct only for length reporting, using the pinned libubus event
 * envelope. These helper-side allocations never enter daemon memory totals. */
static void encoded_lengths(void)
{
	struct blob_buf frame = {0};
	require(!blob_buf_init(&frame, 0), "request length buffer allocation failed");
	require(blob_put_u32(&frame, UBUS_ATTR_OBJID, UBUS_SYSTEM_OBJECT_EVENT) != NULL,
		"request OBJID allocation failed");
	require(blob_put_string(&frame, UBUS_ATTR_METHOD, "send") != NULL,
		"request METHOD allocation failed");
	void *data = blob_nest_start(&frame, UBUS_ATTR_DATA);
	require(data != NULL, "request DATA allocation failed");
	require(!blobmsg_add_string(&frame, "id", EVENT_NAME), "event id allocation failed");
	require(!blobmsg_add_field(&frame, BLOBMSG_TYPE_TABLE, "data",
		blob_data(state.data.head), blob_len(state.data.head)), "event table allocation failed");
	blob_nest_end(&frame, data);
	require(blob_pad_len(frame.head) <= MAX_BLOB_BYTES, "request exceeds image message limit");
	state.request_frame_bytes = sizeof(struct ubus_msghdr) + blob_raw_len(frame.head);
	require(!blob_buf_init(&frame, 0), "relay length buffer reset failed");
	require(blob_put_u32(&frame, UBUS_ATTR_OBJID, 0) != NULL, "relay OBJID allocation failed");
	require(blob_put_string(&frame, UBUS_ATTR_METHOD, EVENT_NAME) != NULL,
		"relay METHOD allocation failed");
	require(blob_put(&frame, UBUS_ATTR_DATA, blob_data(state.data.head),
		blob_len(state.data.head)) != NULL, "relay DATA allocation failed");
	require(blob_pad_len(frame.head) <= MAX_BLOB_BYTES, "relay exceeds image message limit");
	state.relay_frame_bytes = sizeof(struct ubus_msghdr) + blob_raw_len(frame.head);
	blob_buf_free(&frame);
}

static void prepare_data(unsigned bytes)
{
	char *payload = malloc((size_t)bytes + 1);
	require(payload != NULL, "payload allocation failed");
	for (unsigned i = 0; i < bytes; i++)
		payload[i] = (char)('A' + i % 23);
	payload[bytes] = '\0';
	require(!blob_buf_init(&state.data, 0), "data buffer allocation failed");
	require(!blobmsg_add_string(&state.data, "bytes", payload), "bytes field allocation failed");
	free(payload);
	state.payload_bytes = bytes;
	state.data_blob_bytes = blob_raw_len(state.data.head);
	state.received = 0;
	seen_handlers = 0;
	encoded_lengths();
}

static void receive_event(struct ubus_context *ctx, struct ubus_event_handler *handler,
			  const char *type, struct blob_attr *msg)
{
	(void)ctx;
	unsigned index = (unsigned)(handler - handlers);
	require(index < HANDLERS && !(seen_handlers & (1u << index)), "duplicate or unknown handler");
	seen_handlers |= 1u << index;
	require(type && !strcmp(type, EVENT_NAME) && msg, "unexpected event name or absent data");
	/* Compare every encoded field byte, including field name/type, string
	 * terminator and padding. This also rejects extra or duplicate fields. */
	require(!blob_is_extended(msg) && blob_len(msg) == blob_len(state.data.head) &&
		!memcmp(blob_data(msg), blob_data(state.data.head), blob_len(msg)),
		"event payload differs from complete expected bytes");
	state.received++;
	state.total_received++;
}

static void drain_pending(struct ubus_context *listener)
{
	for (;;) {
		struct pollfd pfd = {.fd = listener->sock.fd, .events = POLLIN};
		int rc = poll(&pfd, 1, 0);
		if (rc < 0 && errno == EINTR)
			continue;
		require(rc >= 0, "listener poll failed");
		if (!rc)
			break;
		require((pfd.revents & POLLIN) && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)),
			"listener disconnected while held");
		ubus_handle_event(listener);
	}
}

static void send_and_validate(struct ubus_context *sender, struct ubus_context *listener,
			      unsigned bytes)
{
	alarm(10);
	prepare_data(bytes);
	require(!ubus_send_event(sender, EVENT_NAME, state.data.head), "event send STATUS failed");
	while (state.received < HANDLERS) {
		struct pollfd pfd = {.fd = listener->sock.fd, .events = POLLIN};
		int rc = poll(&pfd, 1, 5000);
		if (rc < 0 && errno == EINTR)
			continue;
		require(rc > 0 && (pfd.revents & POLLIN) &&
			!(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)), "event receive failed or timed out");
		ubus_handle_event(listener);
	}
	/* This is deliberately outside both the callback and ubus_handle_event.
	 * The reply follows the complete event on this socket; it is the drain
	 * barrier, whereas the sender's STATUS alone is insufficient. */
	require(ubus_lookup(listener, MISSING_OBJECT, NULL, NULL) == UBUS_STATUS_NOT_FOUND,
		"listener LOOKUP/STATUS barrier failed");
	drain_pending(listener);
	require(state.received == HANDLERS, "event count mismatch after barrier");
	alarm(0);
}

static void command(const char *expected)
{
	char line[16];
	alarm(15);
	require(fgets(line, sizeof(line), stdin) != NULL, "control pipe closed");
	require(!strcmp(line, expected), "unexpected control command");
	alarm(0);
}

static void phase(const char *name, pid_t subject, unsigned large_bytes,
		  unsigned base_fds, int holding)
{
	struct timespec now;
	require(!clock_gettime(CLOCK_MONOTONIC, &now), "phase clock failed");
	uint64_t ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
	printf("{\"phase\":\"%s\",\"monotonic_ns\":%" PRIu64 ","
		"\"subject_pid\":%d,\"helper_pid\":%d,\"subject_cpu\":1,\"client_cpu\":0,"
		"\"large_payload_bytes\":%u,\"payload_bytes\":%u,\"data_blob_bytes\":%zu,"
		"\"request_frame_bytes\":%zu,\"relay_frame_bytes\":%zu,"
		"\"received\":%u,\"total_received\":%u,\"base_fds\":%u,"
		"\"payload_checked\":true,\"listener_barrier\":true,"
		"\"holding\":%s,\"handlers_removed\":%s}\n",
		name, ns, subject, getpid(), large_bytes, state.payload_bytes,
		state.data_blob_bytes, state.request_frame_bytes, state.relay_frame_bytes,
		state.received, state.total_received, base_fds,
		holding ? "true" : "false", holding ? "false" : "true");
	require(!fflush(stdout), "phase output failed");
}

int main(int argc, char **argv)
{
	if (argc >= 5 && !strcmp(argv[1], "exec-cpu-as")) {
		pin(number(argv[2], 1));
		execvp(argv[3], &argv[4]);
		perror("execvp");
		return 1;
	}
	require(argc == 6 && !strcmp(argv[1], "event-memory"),
		"usage: event-memory SOCKET PAYLOAD_BYTES SUBJECT_PID BASE_FDS");
	unsigned bytes = number(argv[3], 786432);
	pid_t subject = (pid_t)number(argv[4], INT_MAX);
	unsigned base_fds = number(argv[5], 4096);
	require(HANDLERS == 8 ? (bytes == 1024 || bytes == 8192 || bytes == 32768) :
		(bytes == 32768 || bytes == 262144 || bytes == 786432), "unsupported payload size");
	require(subject > 0 && subject != getpid() && base_fds > 0, "invalid subject identity");
	require(signal(SIGALRM, timed_out) != SIG_ERR, "timeout handler failed");
	pin(0);
	check_affinity(subject, 1);
	require(subject_fds(subject) == base_fds, "initial daemon FD count changed");
	alarm(10);
	struct ubus_context *sender = ubus_connect(argv[2]);
	struct ubus_context *listener = ubus_connect(argv[2]);
	require(sender && listener, "ubus connect failed");
	for (unsigned i = 0; i < HANDLERS; i++) {
		handlers[i].cb = receive_event;
		require(!ubus_register_event_handler(listener, &handlers[i], EVENT_NAME), "event registration failed");
	}
	send_and_validate(sender, listener, SMALL_BYTES);
	require(subject_fds(subject) == base_fds + 2, "READY does not hold exactly two connections");
	phase("READY", subject, bytes, base_fds, 1);
	command("SEND\n");
	send_and_validate(sender, listener, bytes);
	require(state.total_received == 2 * HANDLERS && subject_fds(subject) == base_fds + 2,
		"DELIVERED count or held connections changed");
	phase("DELIVERED", subject, bytes, base_fds, 1);
	command("CLOSE\n");
	alarm(10);
	drain_pending(listener);
	for (unsigned i = 0; i < HANDLERS; i++)
		require(!ubus_unregister_event_handler(listener, &handlers[i]), "handler removal failed");
	require(state.received == HANDLERS && state.total_received == 2 * HANDLERS, "unexpected event before CLOSE");
	ubus_free(listener);
	ubus_free(sender);
	uloop_done();
	blob_buf_free(&state.data);
	alarm(0);
	phase("CLOSED", subject, bytes, base_fds, 0);
	return 0;
}
