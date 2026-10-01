/* Exact lease.c and matching object files. No listeners or device state.
 * Including the source exposes read_leases and its static store without
 * replacing allocation, prune, restoration or metric operations. */
#include "lease.c"
#include <assert.h>
#include <inttypes.h>

static unsigned active(void)
{
  unsigned count = 0;
  for (struct dhcp_lease *lease = leases; lease; lease = lease->next) count++;
  return count;
}

int main(int argc, char **argv)
{
  rand_init();
  read_opts(argc, argv, "lease-metrics-oracle");
  daemon->pipe_to_parent = -1;
  daemon->packet_buff_sz = 4096;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  daemon->dhcp_buff = safe_malloc(DHCP_BUFF_SZ);
  daemon->dhcp_buff2 = safe_malloc(DHCP_BUFF_SZ);
  daemon->dhcp_buff3 = safe_malloc(DHCP_BUFF_SZ);
  cache_init(); blockdata_init(); cache_reload();
  char *line = NULL;
  size_t capacity = 0;
  int initialized = 0;
  while (getline(&line, &capacity, stdin) >= 0)
    {
      char op = line[0];
      unsigned address, length;
      long long now;
      int result = 1;
      if (op == 'S')
        {
          assert(!initialized && sscanf(line, "S %d", &leases_left) == 1 && leases_left >= 0);
          initialized = 1;
        }
      else
        {
          assert(initialized);
          if (op == 'A')
            {
              assert(sscanf(line, "A %u", &address) == 1);
              /* Callers select an unowned address before lease4_allocate. */
              struct in_addr addr = { .s_addr = htonl(address) };
              assert(!lease_find_by_addr(addr));
              result = lease4_allocate(addr) != NULL;
            }
          else if (op == 'E')
            {
              assert(sscanf(line, "E %u %u %lld", &address, &length, &now) == 3);
              struct dhcp_lease *lease = lease_find_by_addr((struct in_addr){ .s_addr = htonl(address) });
              result = lease != NULL;
              if (lease) lease_set_expires(lease, length, (time_t)now);
            }
          else if (op == 'P')
            {
              char target[32];
              assert(sscanf(line, "P %31s %lld", target, &now) == 2);
              struct dhcp_lease *lease = NULL;
              if (strcmp(target, "-"))
                lease = lease_find_by_addr((struct in_addr){ .s_addr = htonl(strtoul(target, NULL, 10)) });
              unsigned before = active();
              lease_prune(lease, (time_t)now);
              result = (int)(before - active());
            }
          else if (op == 'R')
            {
              char path[4096];
              assert(!leases && sscanf(line, "R %lld %4095s", &now, path) == 2);
              FILE *input = fopen(path, "r");
              assert(input);
              result = read_leases((time_t)now, input);
              fclose(input);
              file_dirty = 0;
              lease_prune(NULL, (time_t)now);
              dns_dirty = 1;
            }
          else if (op == 'H') cache_reload();
          else assert(op == 'Q');
        }
      printf("%c %d %" PRIu32 " %" PRIu32 " %" PRIu32 " %u\n", op, result,
             (uint32_t)daemon->metrics[METRIC_LEASES_ALLOCATED_4],
             (uint32_t)daemon->metrics[METRIC_LEASES_PRUNED_4],
             (uint32_t)daemon->metrics[METRIC_LEASES_PRUNED_6], active());
      fflush(stdout);
    }
  free(line);
  return 0;
}
