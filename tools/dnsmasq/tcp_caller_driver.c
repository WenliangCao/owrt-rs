/* Exact C TCP reply/error-policy oracle. No network listeners are opened. */
#include "dnsmasq.h"
#include <assert.h>
#include "tcp-caller-exact.inc"

static size_t decode(const char *hex, unsigned char *packet) {
  size_t length = strlen(hex) / 2;
  assert(strlen(hex) % 2 == 0 && length >= sizeof(struct dns_header) && length <= 65535);
  for (size_t i = 0; i < length; i++) {
    unsigned value;
    assert(sscanf(hex + i * 2, "%2x", &value) == 1);
    packet[i] = value;
  }
  return length;
}

int main(int argc, char **argv) {
  rand_init();
  read_opts(argc, argv, "tcp-caller-oracle");
  daemon->pipe_to_parent = -1;
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init(); blockdata_init(); build_server_array(); cache_reload();
  unsigned char *query = safe_malloc(65536);
  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0) {
    char op, encoded_query[131072], encoded_reply[131072];
    unsigned maximum, error;
    assert(sscanf(line, "%c %u %u %131071s %131071s", &op, &maximum, &error,
                  encoded_query, encoded_reply) == 5);
    daemon->edns_pktsz = maximum;
    size_t query_length = decode(encoded_query, query);
    struct dns_header *request = (struct dns_header *)query;
    unsigned char *sizep = NULL;
    int has_opt = !!find_pseudoheader(request, query_length, NULL, &sizep, NULL, NULL);
    int do_bit = has_opt && (sizep[4] & 0x80);
    unsigned gotname = extract_request(request, query_length, daemon->namebuff, NULL, NULL);
    struct dns_header *response = (struct dns_header *)daemon->packet;
    size_t length;
    if (op == 'Q') {
      memcpy(response, request, query_length);
      if (OPCODE(request) != QUERY || !gotname)
        length = make_local_answer(OPCODE(request) != QUERY ? F_RCODE : 0, 0,
            query_length, response, daemon->namebuff, 65536, 0, 0,
            OPCODE(request) != QUERY ? EDE_UNSET : EDE_INVALID_DATA);
      else { puts("FORWARD"); continue; }
      if (!length) { puts("CLOSE"); continue; }
    } else if (op == 'R') {
      memcpy(response, request, query_length);
      length = make_local_answer(0, gotname, query_length, response, daemon->namebuff,
                                 65536, 0, 0, error);
      if (has_opt) {
        u16 code = htons(error);
        length = add_pseudoheader(response, length, 65536, EDNS0_OPTION_EDE,
                                  (unsigned char *)&code, 2, do_bit, 0);
      }
    } else {
      assert(op == 'P');
      length = decode(encoded_reply, (unsigned char *)response);
      if (request->hb4 & HB4_CD) response->hb4 |= HB4_CD;
      else response->hb4 &= ~HB4_CD;
      struct server server;
      memset(&server, 0, sizeof(server));
      server.flags = SERV_WARNED_RECURSIVE;
      union mysockaddr peer;
      memset(&peer, 0, sizeof(peer)); peer.in.sin_family = AF_INET;
      length = process_reply(response, 1000, &server, length,
          option_bool(OPT_NO_REBIND) && !domain_no_rebind(daemon->namebuff),
          1, 0, 0, do_bit || (request->hb4 & HB4_AD), do_bit, !has_opt, &peer, 65536, EDE_UNSET);
    }
    for (size_t i = 0; i < length; i++) printf("%02x", ((unsigned char *)response)[i]);
    putchar('\n'); fflush(stdout);
  }
  free(query); free(line);
  return 0;
}
