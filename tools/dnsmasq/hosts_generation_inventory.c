/* Test-only inventory from exact read_opts/cache_reload objects. No sockets. */
#include "dnsmasq.h"
#include <stdio.h>
#include <string.h>

static void hex(const unsigned char *bytes, size_t length)
{
  for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

int main(int argc, char **argv)
{
  rand_init();
  read_opts(argc, argv, "hosts-generation-inventory");
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init();
  blockdata_init();
  check_servers(0);
  cache_reload();
  cache_enumerate(1);
  for (struct crec *entry = cache_enumerate(0); entry; entry = cache_enumerate(0))
    if ((entry->flags & F_HOSTS) && (entry->flags & (F_IPV4 | F_IPV6)))
      {
        const char *name = cache_get_name(entry);
        hex((const unsigned char *)name, strlen(name));
        putchar(' ');
        hex((const unsigned char *)&entry->addr,
            (entry->flags & F_IPV4) ? sizeof(struct in_addr) : sizeof(struct in6_addr));
        printf(" %llu %u\n", (unsigned long long)entry->ttd, entry->flags);
      }
  return 0;
}
