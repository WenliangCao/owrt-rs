/* Test-only ubus socket probe for r36. Built for the target with the SDK and
 * copied into the sandbox rootfs; never installed on a device.
 *
 *   busprobe raw   <socket> <hex>   connect, write those bytes, close
 *   busprobe slow  <socket> <secs>  connect, send a full LOOKUP, never read
 *   busprobe half  <socket>         send half a message, then close
 *   busprobe drop  <socket>         send a LOOKUP then close without reading
 *   busprobe big   <socket> <bytes> send one message whose blob declares
 *                                   <bytes> total, padded with zeros, and
 *                                   report whether the daemon kept the
 *                                   connection (accepted) or dropped it
 *
 * Exit code is 0 on a successful connect+write, 1 otherwise, so the caller
 * can tell "the probe ran" from "the probe could not connect".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

static int connect_to(const char *path) {
	struct sockaddr_un a;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	memset(&a, 0, sizeof(a));
	a.sun_family = AF_UNIX;
	snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
	if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
	return fd;
}

/* header(version 0, type, seq, peer) + an empty blob attr: a no-path LOOKUP */
static const unsigned char lookup_all[12] = {
	0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
};

static int hexval(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int main(int argc, char **argv) {
	if (argc < 3) { fprintf(stderr, "usage: busprobe <raw|slow|half|drop> <socket> [arg]\n"); return 2; }
	const char *mode = argv[1], *sock = argv[2];
	int fd = connect_to(sock);
	if (fd < 0) { perror("connect"); return 1; }

	if (!strcmp(mode, "raw")) {
		if (argc < 4) { fprintf(stderr, "raw needs hex\n"); return 2; }
		const char *h = argv[3];
		size_t n = strlen(h) / 2;
		unsigned char *buf = malloc(n ? n : 1);
		for (size_t i = 0; i < n; i++) {
			int hi = hexval(h[2 * i]), lo = hexval(h[2 * i + 1]);
			if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); return 2; }
			buf[i] = (unsigned char)((hi << 4) | lo);
		}
		if (write(fd, buf, n) < 0) { close(fd); return 1; }
	} else if (!strcmp(mode, "half")) {
		/* a header claiming a 64-byte blob, of which only 8 bytes follow */
		unsigned char h[20] = { 0x00, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x40 };
		if (write(fd, h, 20) < 0) { close(fd); return 1; }
	} else if (!strcmp(mode, "slow") || !strcmp(mode, "drop")) {
		if (write(fd, lookup_all, sizeof(lookup_all)) < 0) { close(fd); return 1; }
		if (!strcmp(mode, "slow")) {
			int secs = argc > 3 ? atoi(argv[3]) : 2;
			sleep(secs);          /* hold the connection open, never read */
		}
	} else if (!strcmp(mode, "big")) {
		/* header + a blob attr declaring `total` bytes including its own
		 * 4-byte header. The daemon either reads it all or hangs up. */
		if (argc < 4) { fprintf(stderr, "big needs a byte count\n"); return 2; }
		unsigned long total = strtoul(argv[3], 0, 10);
		if (total < 4) { fprintf(stderr, "too small\n"); return 2; }
		unsigned char hdr[12] = { 0x00, 0x04, 0x00, 0x01, 0, 0, 0, 0 };
		hdr[8] = (unsigned char)((total >> 24) & 0x7f);
		hdr[9] = (unsigned char)((total >> 16) & 0xff);
		hdr[10] = (unsigned char)((total >> 8) & 0xff);
		hdr[11] = (unsigned char)(total & 0xff);
		if (write(fd, hdr, 12) < 0) { printf("write_header_failed\n"); close(fd); return 1; }
		unsigned long left = total - 4;
		static unsigned char zeros[4096];
		while (left > 0) {
			size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : left;
			ssize_t w = write(fd, zeros, chunk);
			if (w <= 0) { printf("dropped_during_body\n"); close(fd); return 0; }
			left -= (unsigned long)w;
		}
		/* if the daemon accepted it, the connection is still usable */
		unsigned char reply[64];
		struct timeval tv = { 2, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		ssize_t r = read(fd, reply, sizeof(reply));
		if (r > 0) printf("accepted_replied\n");
		else if (r == 0) printf("dropped_eof\n");
		else printf("accepted_silent\n");
	} else {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 2;
	}
	close(fd);
	return 0;
}
