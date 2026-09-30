/* Socket-free oracle linked to the exact OpenWrt dnsmasq 2.93 object files.
 * P feeds a complete upstream packet to extract_addresses at a frozen time;
 * Q invokes answer_request; RESET performs the real cache_reload lifecycle.
 * Input: OP NOW LIMIT HEX. Configuration is supplied through normal -C FILE.
 */
#include "dnsmasq.h"
#include <assert.h>

int main(int argc, char **argv)
{
  rand_init();
  read_opts(argc, argv, "cache-answer-oracle");
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init();
  blockdata_init();
  cache_reload();
  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0)
    {
      if (!strcmp(line, "RESET\n"))
        {
          cache_reload();
          puts("RESET");
          continue;
        }
      char op, encoded[131072];
      long long now;
      unsigned limit;
      assert(sscanf(line, "%c %lld %u %131071s", &op, &now, &limit, encoded) == 4);
      size_t length = strlen(encoded) / 2;
      assert(!(strlen(encoded) & 1) && length >= sizeof(struct dns_header) && length <= 65535);
      assert(limit <= 65535);
      memset(daemon->packet, 0, daemon->packet_buff_sz);
      for (size_t i = 0; i < length; i++)
        {
          unsigned byte;
          assert(sscanf(encoded + 2*i, "%2x", &byte) == 1);
          ((unsigned char *)daemon->packet)[i] = byte;
        }
      struct dns_header *header = (struct dns_header *)daemon->packet;
      if (op == 'P')
        {
          int status = extract_addresses(header, length, daemon->namebuff, (time_t)now,
                                         NULL, NULL, 0, 0, 0);
          assert(status == 0);
          puts("P");
        }
      else
        {
          assert(op == 'Q');
          int stale = 0, filtered = 0;
          size_t answer = answer_request(header, daemon->packet + limit, length,
                                         (struct in_addr){0}, (struct in_addr){0},
                                         (time_t)now, 0, 0, 0, &stale, &filtered);
          if (!answer) puts("NONE");
          else
            {
              for (size_t i = 0; i < answer; i++)
                printf("%02x", ((unsigned char *)daemon->packet)[i]);
              putchar('\n');
            }
        }
      fflush(stdout);
    }
  free(line);
  return 0;
}
