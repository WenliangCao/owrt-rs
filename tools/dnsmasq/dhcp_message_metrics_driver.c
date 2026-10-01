/* Calls actual rfc2131.c dhcp_reply with configured contexts and actual lease
 * storage. No DHCP socket is opened; no-ping and an isolated netns are required.
 * lease.c is included only to observe its live list and initialize capacity. */
#include "lease.c"
#include <assert.h>
#include <inttypes.h>

static unsigned active_count(void) {
  unsigned count = 0;
  for (struct dhcp_lease *lease = leases; lease; lease = lease->next) count++;
  return count;
}

int main(int argc, char **argv) {
  assert(getenv("DNSMASQ_TEST_ISOLATED") && !strcmp(getenv("DNSMASQ_TEST_ISOLATED"), "1"));
  rand_init(); read_opts(argc, argv, "dhcp-message-metrics-oracle");
  assert(option_bool(OPT_NO_PING) && option_bool(OPT_LEASE_RO) && !daemon->lease_change_command);
  daemon->pipe_to_parent = -1;
  daemon->packet_buff_sz = 4096;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  dhcp_common_init(); lease_init(100);
  cache_init(); blockdata_init(); cache_reload();
  struct in_addr local, source;
  assert(inet_pton(AF_INET, "192.0.2.1", &local) == 1);
  assert(inet_pton(AF_INET, "192.0.2.100", &source) == 1);
  for (struct dhcp_context *context = daemon->dhcp; context; context = context->next) {
    context->local = context->router = local;
    context->broadcast.s_addr = context->start.s_addr | ~context->netmask.s_addr;
  }
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0) {
    unsigned response = 0;
    size_t length = 0;
    if (line[0] == 'H') {
      cache_reload();
    } else if (line[0] == 'M') {
      unsigned index, value;
      assert(sscanf(line, "M %u %u", &index, &value) == 2 && index < 11);
      daemon->metrics[METRIC_BOOTP + index] = value;
    } else {
      long long now; int unicast;
      char encoded[8193];
      assert(sscanf(line, "P %lld %d %8192s", &now, &unicast, encoded) == 3);
      size_t bytes = strlen(encoded) / 2;
      assert(strlen(encoded) % 2 == 0 && bytes <= 4096);
      assert(expand_buf(&daemon->dhcp_packet, bytes > sizeof(struct dhcp_packet) ? bytes : sizeof(struct dhcp_packet)));
      memset(daemon->dhcp_packet.iov_base, 0, daemon->dhcp_packet.iov_len);
      for (size_t i = 0; i < bytes; i++) {
        unsigned value;
        assert(sscanf(encoded + i * 2, "%2x", &value) == 1);
        ((unsigned char *)daemon->dhcp_packet.iov_base)[i] = value;
      }
      /* dhcp.c's pre-dhcp_reply prune happens only after datagram admission.
       * This driver models that caller boundary for complete BOOTP headers. */
      if (bytes >= offsetof(struct dhcp_packet, options)) {
        lease_prune(NULL, (time_t)now);
        for (struct dhcp_context *context = daemon->dhcp; context; context = context->next)
          context->current = context->next;
        int inform = 0;
        length = dhcp_reply(daemon->dhcp, "fixture0", 1, bytes, (time_t)now, unicast,
                            1, &inform, 0, local, (time_t)now, source);
        if (length) {
          const unsigned char *wire = daemon->dhcp_packet.iov_base;
          response = 16; /* BOOTP response has no DHCP message type. */
          for (size_t at = offsetof(struct dhcp_packet, options) + 4; at < length;) {
            unsigned code = wire[at++];
            if (code == OPTION_END) break;
            if (code == OPTION_PAD) continue;
            assert(at < length);
            unsigned size = wire[at++]; assert(at + size <= length);
            if (code == OPTION_MESSAGE_TYPE && size) { response = wire[at]; break; }
            at += size;
          }
        }
      }
    }
    printf("%c %u %u", line[0], response, active_count());
    for (unsigned index = 0; index < 11; index++)
      printf(" %" PRIu32, (uint32_t)daemon->metrics[METRIC_BOOTP + index]);
    putchar('\n');
    if (length) {
      fputs("WIRE ", stderr);
      for (size_t i = 0; i < length; i++) fprintf(stderr, "%02x", ((unsigned char *)daemon->dhcp_packet.iov_base)[i]);
      fputc('\n', stderr);
    }
    fflush(stdout);
  }
  free(line);
  return 0;
}
