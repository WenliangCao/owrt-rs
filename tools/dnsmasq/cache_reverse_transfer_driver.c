/* Exact cache.c, real child cache_end_insert and parent cache_recv_insert.
 * New reverse-transfer primitive fixture; the original 307-row gate is unchanged.
 */
#include "cache.c"
#include <assert.h>
#include <sys/wait.h>

static unsigned family(unsigned bits) { assert(bits == 4 || bits == 6); return bits == 4 ? F_IPV4 : F_IPV6; }
static void address(union all_addr *addr, unsigned bits, const char *hex)
{
  size_t len = bits == 4 ? 4 : 16;
  assert(strlen(hex) == 2 * len);
  memset(addr, 0, sizeof(*addr));
  for (size_t i = 0; i < len; i++)
    { unsigned byte; assert(sscanf(hex + 2 * i, "%2x", &byte) == 1); ((unsigned char *)addr)[i] = byte; }
}
static void data(struct crec *entry)
{
  size_t len = entry->flags & F_IPV4 ? 4 : 16;
  for (size_t i = 0; i < len; i++) printf("%02x", ((unsigned char *)&entry->addr)[i]);
}
static void commands(const char *path, const char *stage)
{
  FILE *input = fopen(path, "r"); assert(input);
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, input) >= 0)
    {
      char name[504], hex[33]; unsigned bits, ttl; long long now;
      printf("%s ", stage);
      if (line[0] == 'B') { cache_start_insert(); printf("B"); }
      else if (line[0] == 'C') { cache_end_insert(); printf("C %d", !insert_error); }
      else if (line[0] == 'V' || line[0] == 'I')
        {
          assert(sscanf(line, "%*c %503s %u %32s %u %lld", name, &bits, hex, &ttl, &now) == 5);
          union all_addr addr; address(&addr, bits, hex);
          unsigned flags = family(bits) | (line[0] == 'V' ? F_REVERSE : F_FORWARD);
          struct crec *entry = cache_insert(name, &addr, C_IN, now, ttl, flags);
          printf("%c %d", line[0], entry != NULL);
          fprintf(stderr, "%s HASH %s %td\n", stage, name, hash_bucket(name) - hash_table);
        }
      else if (line[0] == 'H')
        {
          assert(sscanf(line, "H %503s %u %32s %lld", name, &bits, hex, &now) == 4);
          union all_addr addr; address(&addr, bits, hex);
          char *owned = strdup(name); assert(owned);
          cache_add_dhcp_entry(owned, bits == 4 ? AF_INET : AF_INET6, &addr, now);
          printf("H");
        }
      else if (line[0] == 'A')
        {
          assert(sscanf(line, "A %u %32s %lld", &bits, hex, &now) == 3);
          union all_addr addr; address(&addr, bits, hex); struct crec *entry = NULL;
          printf("A");
          while ((entry = cache_find_by_addr(entry, &addr, now, family(bits))))
            printf(" %s:%lld:%u", cache_get_name(entry), (long long)entry->ttd,
                   !!(entry->flags & (F_DHCP | F_HOSTS | F_CONFIG)));
        }
      else if (line[0] == 'Q')
        {
          assert(sscanf(line, "Q %503s %u %lld", name, &bits, &now) == 3);
          struct crec *entry = NULL; printf("Q");
          while ((entry = cache_find_by_name(entry, name, now, family(bits))))
            {
              printf(" %lld:%u:", (long long)entry->ttd, !!(entry->flags & (F_DHCP | F_HOSTS | F_CONFIG)));
              data(entry);
            }
        }
      else if (line[0] == 'T')
        {
          printf("T");
          for (struct crec *entry = cache_head; entry; entry = entry->next)
            if (entry->flags & (F_FORWARD | F_REVERSE))
              {
                assert(!(entry->flags & (F_DHCP | F_HOSTS | F_CONFIG | F_CNAME | F_RR)));
                printf(" %c%u:%s:%lld:", entry->flags & F_REVERSE ? 'R' : 'F', entry->flags & F_IPV4 ? 4 : 6,
                       cache_get_name(entry), (long long)entry->ttd);
                data(entry);
              }
        }
      else abort();
      printf(" | %u %u\n", daemon->metrics[METRIC_DNS_CACHE_INSERTED], daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
    }
  free(line); fclose(input);
}
int main(int argc, char **argv)
{
  assert(argc == 7);
  char *options[] = {argv[0], "-C", argv[1], NULL};
  rand_init(); read_opts(3, options, "reverse-transfer");
  daemon->pipe_to_parent = -1; daemon->namebuff = safe_malloc(MAXDNAME); daemon->addrbuff = safe_malloc(ADDRSTRLEN);
  cache_init(); blockdata_init(); cache_reload();
  commands(argv[2], "P0"); fflush(stdout);
  FILE *child_log = tmpfile(); assert(child_log); int channel[2]; assert(pipe(channel) == 0);
  pid_t child = fork(); assert(child >= 0);
  if (child == 0)
    {
      close(channel[0]); daemon->pipe_to_parent = channel[1];
      assert(dup2(fileno(child_log), STDOUT_FILENO) >= 0);
      commands(argv[3], "CH"); fflush(stdout); close(channel[1]); _exit(0);
    }
  close(channel[1]); commands(argv[4], "P1"); time_t now = strtoll(argv[6], NULL, 10);
  while (cache_recv_insert(now, channel[0]))
    printf("R %d | %u %u\n", !insert_error, daemon->metrics[METRIC_DNS_CACHE_INSERTED], daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
  close(channel[0]); int status; assert(waitpid(child, &status, 0) == child); assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  rewind(child_log); char buffer[8192]; while (fgets(buffer, sizeof(buffer), child_log)) fputs(buffer, stdout); fclose(child_log);
  commands(argv[5], "P2"); return 0;
}
