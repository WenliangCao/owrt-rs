/* Unchanged exact cache.c plus matching rfc1035.o. All inserts enter through
 * extract_addresses; inspection never injects records or changes hash/LRU. */
#include "cache.c"
#include <assert.h>
#include <inttypes.h>

static void entry_json(struct crec *entry)
{
  char address[INET6_ADDRSTRLEN] = "";
  unsigned type = entry->flags & F_IPV4 ? 1 : entry->flags & F_IPV6 ? 28 :
                  entry->flags & F_CNAME ? 5 : entry->flags & F_NXDOMAIN ? 65536 :
                  entry->flags & F_KEYTAG ? entry->addr.rrblock.rrtype : entry->addr.rrdata.rrtype;
  if (entry->flags & (F_IPV4 | F_IPV6))
    assert(inet_ntop(entry->flags & F_IPV6 ? AF_INET6 : AF_INET, &entry->addr,
                     address, sizeof(address)));
  /* Fixture names contain only letters, digits, dots and hyphens. */
  printf("{\"name\":\"%s\",\"forward\":%u,\"reverse\":%u,\"kind\":%u,"
         "\"negative\":%u,\"expires\":%lld,\"address\":\"%s\",\"bucket\":%td}",
         cache_get_name(entry), !!(entry->flags & F_FORWARD), !!(entry->flags & F_REVERSE),
         type, !!(entry->flags & F_NEG), (long long)entry->ttd, address,
         hash_bucket(cache_get_name(entry)) - hash_table);
}

static void packet_hex(const unsigned char *packet, size_t length)
{
  putchar('"');
  for (size_t i = 0; i < length; i++) printf("%02x", packet[i]);
  putchar('"');
}

int main(int argc, char **argv)
{
  rand_init(); read_opts(argc, argv, "reverse-cache-oracle");
  daemon->pipe_to_parent = -1;
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init(); blockdata_init(); build_server_array(); cache_reload();
  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0)
    {
      long long now;
      char value[504];
      if (!strcmp(line, "M\n"))
        printf("{\"op\":\"M\",\"inserted\":%" PRIu32 ",\"live_freed\":%" PRIu32 "}",
               (uint32_t)daemon->metrics[METRIC_DNS_CACHE_INSERTED],
               (uint32_t)daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
      else if (!strcmp(line, "S\n"))
        {
          int comma = 0;
          printf("{\"op\":\"S\",\"entries\":[");
          for (struct crec *entry = cache_head; entry; entry = entry->next)
            if (entry->flags & (F_FORWARD | F_REVERSE))
              { if (comma++) putchar(','); entry_json(entry); }
          printf("]}");
        }
      else if (line[0] == 'N')
        {
          assert(sscanf(line, "N %lld %503s", &now, value) == 2);
          printf("{\"op\":\"N\",\"exists\":%d}", cache_find_non_terminal(value, now));
        }
      else if (line[0] == 'A')
        {
          union all_addr address = {0};
          assert(sscanf(line, "A %lld %503s", &now, value) == 2);
          unsigned family = strchr(value, ':') ? F_IPV6 : F_IPV4;
          assert(inet_pton(family == F_IPV6 ? AF_INET6 : AF_INET, value, &address) == 1);
          struct crec *entry = NULL;
          int comma = 0;
          printf("{\"op\":\"A\",\"entries\":[");
          while ((entry = cache_find_by_addr(entry, &address, now, family)))
            { if (comma++) putchar(','); entry_json(entry); }
          printf("]}");
        }
      else
        {
          int offset = 0;
          assert((line[0] == 'P' || line[0] == 'Q') &&
                 sscanf(line + 1, " %lld %n", &now, &offset) == 1);
          char *hex = line + 1 + offset;
          size_t digits = strcspn(hex, "\r\n"), length = digits / 2;
          assert(!(digits & 1) && length >= sizeof(struct dns_header) && length <= 65535);
          memset(daemon->packet, 0, daemon->packet_buff_sz);
          for (size_t i = 0; i < length; i++)
            {
              unsigned byte;
              assert(sscanf(hex + 2*i, "%2x", &byte) == 1);
              ((unsigned char *)daemon->packet)[i] = byte;
            }
          struct dns_header *header = (struct dns_header *)daemon->packet;
          if (line[0] == 'P')
            {
              int status = extract_addresses(header, length, daemon->namebuff, now,
                                             NULL, NULL, 0, 0, 0);
              printf("{\"op\":\"P\",\"status\":%d,\"packet\":", status);
              packet_hex((unsigned char *)header, length);
            }
          else
            {
              int stale = 0, filtered = 0;
              length = answer_request(header, daemon->packet + 65535, length,
                                      (struct in_addr){0}, (struct in_addr){0}, now,
                                      0, 0, 0, &stale, &filtered);
              printf("{\"op\":\"Q\",\"stale\":%d,\"filtered\":%d,\"packet\":", stale, filtered);
              if (length) packet_hex((unsigned char *)header, length); else printf("null");
            }
          putchar('}');
        }
      putchar('\n'); fflush(stdout);
    }
  free(line);
  return 0;
}
