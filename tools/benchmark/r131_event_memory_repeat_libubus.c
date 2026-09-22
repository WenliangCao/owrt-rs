/* Reuse the exact event payload/callback/barrier validator unchanged.
 * Separate ELF for a fixed 1 KiB, eight-handler residency plateau probe.
 * Three STEP commands advance to 1, 1000, and 10000 total large events;
 * CLOSE unregisters everything.  No performance conclusion uses these loops.
 */
#define EVENT_MEMORY_HANDLERS 8
#define main single_event_memory_main
#include "event_memory_libubus.c"
#undef main

int main(int argc, char **argv)
{
	if (argc >= 5 && !strcmp(argv[1], "exec-cpu-as"))
		return single_event_memory_main(argc, argv);
	require(argc == 5 && !strcmp(argv[1], "event-memory-repeat"),
		"usage: event-memory-repeat SOCKET SUBJECT_PID BASE_FDS");
	pid_t subject = (pid_t)number(argv[3], INT_MAX);
	unsigned base_fds = number(argv[4], 4096);
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
	require(subject_fds(subject) == base_fds + 2, "READY connection count");
	phase("READY", subject, 1024, base_fds, 1);
	const unsigned targets[] = {1, 1000, 10000};
	const char *names[] = {"DELIVERED_1", "DELIVERED_1000", "DELIVERED_10000"};
	unsigned sent = 0;
	for (unsigned step = 0; step < 3; step++) {
		command("STEP\n");
		while (sent < targets[step]) {
			send_and_validate(sender, listener, 1024);
			sent++;
		}
		require(state.total_received == (sent + 1) * HANDLERS && subject_fds(subject) == base_fds + 2,
			"DELIVERED count or held connections changed");
		phase(names[step], subject, 1024, base_fds, 1);
	}
	command("CLOSE\n");
	alarm(10);
	drain_pending(listener);
	for (unsigned i = 0; i < HANDLERS; i++)
		require(!ubus_unregister_event_handler(listener, &handlers[i]), "handler removal failed");
	require(state.received == HANDLERS && state.total_received == 10001 * HANDLERS,
		"unexpected event before CLOSE");
	ubus_free(listener);
	ubus_free(sender);
	uloop_done();
	blob_buf_free(&state.data);
	alarm(0);
	phase("CLOSED", subject, 1024, base_fds, 0);
	return 0;
}
