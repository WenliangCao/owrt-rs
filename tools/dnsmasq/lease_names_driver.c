/* Exact C lease-name publication/cache-answer oracle; no listeners or leases
 * from a device. The ordered D commands are lease_update_dns's publication
 * sequence. R unhashes DHCP entries only; P uses real extract_addresses. */
#ifndef LEASE_NAMES_CACHE_INTERNAL
#include "dnsmasq.h"
#endif
#include <assert.h>

static size_t decode(const char *text, unsigned char *packet) {
  size_t length = strlen(text) / 2;
  assert(strlen(text) % 2 == 0 && length >= 12 && length <= 65535);
  for (size_t i = 0; i < length; i++) {
    unsigned value;
    assert(sscanf(text + i*2, "%2x", &value) == 1);
    packet[i] = value;
  }
  return length;
}

int main(int argc, char **argv) {
  rand_init(); read_opts(argc, argv, "lease-names-oracle");
  daemon->pipe_to_parent = -1;
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init(); blockdata_init(); build_server_array(); cache_reload();
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0) {
#ifdef LEASE_NAMES_CACHE_INTERNAL
    /* Clock-transition fixtures freeze same/different-bucket conditions
     * before observing answers; the normal driver has no internal access. */
    if (line[0] == 'V') {
      char first[504], second[504];
      assert(sscanf(line, "V %503s %503s", first, second) == 2);
      printf("V %d\n", hash_bucket(first) == hash_bucket(second));
      fflush(stdout); continue;
    }
#endif
    if (line[0] == 'R') {
      cache_unhash_dhcp(); puts("R");
    } else if (line[0] == 'S') {
      cache_reload(); puts("S");
    } else if (line[0] == 'D') {
      long long expiry;
      char address[64], name[1024];
      assert(sscanf(line, "D %lld %63s %1023s", &expiry, address, name) == 3);
      union all_addr addr; memset(&addr, 0, sizeof(addr));
      assert(inet_pton(AF_INET, address, &addr.addr4) == 1);
      /* cache entries retain the publication's name pointer. Keep each name
       * alive for this bounded oracle process, including after expiration. */
      char *owned = strdup(name); assert(owned);
      cache_add_dhcp_entry(owned, AF_INET, &addr, (time_t)expiry);
      puts("D");
    } else if (line[0] == 'E') {
      cache_enumerate(1);
      struct crec *c;
      while ((c = cache_enumerate(0))) {
        char address[ADDRSTRLEN] = "-";
        if ((c->flags & (F_IPV4 | F_IPV6)) && (!(c->flags & F_NEG) || (c->flags & F_REVERSE)))
          inet_ntop((c->flags & F_IPV4) ? AF_INET : AF_INET6, &c->addr, address, sizeof(address));
        printf("E %s %s %d %d %d %d %d %d %d %d %d %lld\n", cache_get_name(c), address,
               !!(c->flags & F_DHCP), !!(c->flags & F_HOSTS), !!(c->flags & F_CONFIG),
               !!(c->flags & F_IPV4), !!(c->flags & F_IPV6), !!(c->flags & F_CNAME),
               !!(c->flags & F_NEG), !!(c->flags & F_NXDOMAIN), !!(c->flags & F_REVERSE),
               (c->flags & F_IMMORTAL) ? 0LL : (long long)c->ttd);
      }
      puts("END");
    } else {
      char op, encoded[131072]; long long now;
      assert(sscanf(line, "%c %lld %131071s", &op, &now, encoded) == 3);
      memset(daemon->packet, 0, daemon->packet_buff_sz);
      size_t length = decode(encoded, (unsigned char *)daemon->packet);
      struct dns_header *header = (struct dns_header *)daemon->packet;
      if (op == 'P') {
        int result = extract_addresses(header, length, daemon->namebuff, (time_t)now,
                                       NULL, NULL, 0, 0, 0);
        printf("P %d\n", result);
      } else if (op == 'K') {
        assert(extract_request(header, length, daemon->namebuff, NULL, NULL));
        printf("K %d\n", check_for_local_domain(daemon->namebuff, (time_t)now));
      } else if (op == 'N') {
        unsigned short type; unsigned count = 0;
        assert(extract_request(header, length, daemon->namebuff, &type, NULL));
        unsigned flags = type == T_A ? F_IPV4 : type == T_AAAA ? F_IPV6 : type == T_CNAME ? F_CNAME : F_RR;
        struct crec *entry = NULL;
        while ((entry = cache_find_by_name(entry, daemon->namebuff, (time_t)now, flags | F_NO_RR)))
          if (!(entry->flags & (F_HOSTS | F_DHCP | F_CONFIG))) count++;
        printf("N %u\n", count);
      } else {
        assert(op == 'Q');
        int stale = 0, filtered = 0;
        length = answer_request(header, daemon->packet + 65535, length, (struct in_addr){0},
                                (struct in_addr){0}, (time_t)now, 0, 0, 0, &stale, &filtered);
        if (!length) puts("NONE");
        else {
          for (size_t i = 0; i < length; i++) printf("%02x", ((unsigned char *)header)[i]);
          putchar('\n');
        }
      }
    }
    fflush(stdout);
  }
  free(line);
  return 0;
}
