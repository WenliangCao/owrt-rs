/*
 * Isolated dnsmasq 2.93 answer oracle.
 *
 * The object files are linked from the exact OpenWrt-patched source build. The
 * program never opens a listener: it reads one hexadecimal DNS query per line
 * and prints the resulting hexadecimal packet, or NONE when the real C path
 * delegates to forwarding. It is deliberately a test oracle, never a product
 * dependency.
 */
#include "dnsmasq.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t decode_hex(const char *line, unsigned char *out, size_t cap) {
  size_t n = 0;
  int high = -1;
  for (; *line && !isspace((unsigned char)*line); line++) {
    int value = hex_value((unsigned char)*line);
    if (value < 0) return 0;
    if (high < 0) high = value;
    else {
      if (n == cap) return 0;
      out[n++] = (unsigned char)((high << 4) | value);
      high = -1;
    }
  }
  return high < 0 ? n : 0;
}

static void print_hex(const unsigned char *packet, size_t length) {
  for (size_t i = 0; i < length; i++) printf("%02x", packet[i]);
  putchar('\n');
}

/* Socket-free caller plumbing from forward.c:1880-1990 and :587-605.
 * Selection and encoding stay in the real source functions. NONE marks the
 * handoff to the upstream dispatcher; no upstream sockets are opened. */
static size_t answer_one(unsigned char *packet, size_t length, int tcp) {
  if (length < sizeof(struct dns_header)) return 0;
  struct dns_header *header = (struct dns_header *)packet;
  if (header->hb3 & HB3_QR) return 0;
  size_t limit = tcp ? 65536 : PACKETSZ;
  int do_bit = 0, has_opt = 0;
  unsigned char *udp_len = NULL;
  if (find_pseudoheader(header, length, NULL, &udp_len, NULL, NULL)) {
    unsigned short advertised, edns_flags;
    has_opt = 1;
    GETSHORT(advertised, udp_len);
    udp_len += 2;
    GETSHORT(edns_flags, udp_len);
    do_bit = (edns_flags & 0x8000) != 0;
    if (!tcp) {
      if (advertised > daemon->edns_pktsz) limit = daemon->edns_pktsz;
      else limit = advertised < PACKETSZ ? PACKETSZ : advertised;
    }
  }
  int cacheable = 1;
  union mysockaddr source;
  memset(&source, 0, sizeof(source));
  source.in.sin_family = AF_INET;
  source.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  length = add_edns0_config(header, length, tcp ? 65536 : daemon->edns_pktsz,
                           &source, 0, &cacheable);
  unsigned char *saved = safe_malloc(length);
  memcpy(saved, packet, length);
  int stale = 0, filtered = 0;
  size_t answer = answer_request(header, (char *)packet + limit, length,
                                 (struct in_addr){0}, (struct in_addr){0},
                                 0, do_bit || (header->hb4 & HB4_AD), do_bit,
                                 !cacheable, &stale, &filtered);
  if (!answer) {
    memcpy(packet, saved, length);
    char qname[MAXDNAMESTR + 1];
    unsigned int got = extract_request(header, length, qname, NULL, NULL);
    int first = 0, last = 0;
    if (got && lookup_domain(qname, got, &first, &last)) {
      int local_flags = is_local_answer(0, first, qname);
      if (local_flags) {
        answer = make_local_answer(local_flags, got, length, header, qname,
                                   limit, first, last, EDE_UNSET);
        /* UDP forward_query's local-reply branch does not restore DO. */
        if (!tcp) do_bit = 0;
      }
    }
  }
  if (answer && has_opt)
    answer = add_pseudoheader(header, answer, tcp ? 65536 : daemon->edns_pktsz,
                             0, NULL, 0, do_bit, 0);
  free(saved);
  return answer;
}

int main(int argc, char **argv) {
  rand_init();
  read_opts(argc, argv, "local-answer-oracle");
  if (daemon->edns_pktsz < PACKETSZ) daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init();
  blockdata_init();
  check_servers(0);
  cache_reload();

  char *line = NULL;
  size_t cap = 0;
  while (getline(&line, &cap, stdin) >= 0) {
    int tcp = strncmp(line, "tcp ", 4) == 0;
    char *input = (tcp || strncmp(line, "udp ", 4) == 0) ? line + 4 : line;
    size_t length = decode_hex(input, (unsigned char *)daemon->packet, 65535);
    size_t answer = length ? answer_one((unsigned char *)daemon->packet, length, tcp) : 0;
    if (answer) print_hex((unsigned char *)daemon->packet, answer);
    else puts("NONE");
    fflush(stdout);
  }
  free(line);
  return 0;
}
