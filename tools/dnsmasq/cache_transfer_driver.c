/* Unchanged exact cache.c, with real fork/pipe transfer into cache_recv_insert.
 * Commands expose primitive effects only; no listener or replacement algorithm.
 */
#include "cache.c"
#include <assert.h>
#include <sys/wait.h>

static struct crec *ids[256];
static unsigned id_count;

static unsigned type_flags(unsigned type)
{
  return type == 1 ? F_IPV4 : type == 28 ? F_IPV6 : type == 5 ? F_CNAME :
         type == 65536 ? F_NXDOMAIN : F_RR;
}

static void commands(const char *path, const char *stage)
{
  FILE *input = fopen(path, "r");
  assert(input);
  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, input) >= 0)
    {
      char name[504], authority[504];
      unsigned type, ttl, value, negative;
      long long now;
      printf("%s ", stage);
      if (line[0] == 'B')
        { cache_start_insert(); printf("B"); }
      else if (line[0] == 'C')
        { cache_end_insert(); printf("C %d", !insert_error); }
      else if (line[0] == 'I' || line[0] == 'N' || line[0] == 'G')
        {
          union all_addr address = {0};
          unsigned flags;
          struct blockdata *block = NULL;
          if (line[0] == 'N')
            {
              assert(sscanf(line, "N %503s %u %u %503s %lld", name, &type,
                            &ttl, authority, &now) == 5);
              assert(strlen(authority) <= strlen(name));
              size_t offset = strlen(name) - strlen(authority);
              assert(offset <= 255 && strcmp(name + offset, authority) == 0);
              address.rrdata.rrtype = type == 65536 ? 1 : type;
              address.rrdata.datalen = offset;
              flags = F_FORWARD | F_NEG | type_flags(type);
            }
          else
            {
              assert(sscanf(line, "%*c %503s %u %u %u %u %lld", name, &type,
                            &ttl, &value, &negative, &now) == 6);
              flags = F_FORWARD | type_flags(type) | (negative ? F_NEG | F_NO_RR : 0);
              if (line[0] == 'G')
                {
                  char data[24];
                  memset(data, value, sizeof(data));
                  assert(type != 1 && type != 28 && type != 5 && !negative);
                  block = blockdata_alloc(data, sizeof(data));
                  assert(block);
                  address.rrblock.rrtype = type;
                  address.rrblock.datalen = sizeof(data);
                  address.rrblock.rrdata = block;
                  flags |= F_KEYTAG;
                }
              else if (type == 1 || type == 28)
                address.addr4.s_addr = value;
              else if (type != 5)
                { address.rrdata.rrtype = type; address.rrdata.datalen = 1; address.rrdata.data[0] = value; }
            }
          struct crec *entry = cache_insert(name, type == 5 ? NULL : &address,
                                           C_IN, now, ttl, flags);
          if (!entry && block)
            blockdata_free(block);
          if (entry && type == 5)
            { entry->addr.cname.target.cache = NULL; entry->addr.cname.is_name_ptr = 0; }
          assert(id_count < 256);
          ids[id_count++] = entry;
          printf("%c %d", line[0], entry != NULL);
        }
      else if (line[0] == 'L')
        {
          unsigned a, b;
          assert(sscanf(line, "L %u %u", &a, &b) == 2 && a < id_count && b < id_count);
          int ok = ids[a] && ids[b] && (ids[a]->flags & F_CNAME);
          if (ok)
            { next_uid(ids[b]); ids[a]->addr.cname.target.cache = ids[b]; ids[a]->addr.cname.uid = ids[b]->uid; }
          printf("L %d", ok);
        }
      else if (line[0] == 'H')
        {
          assert(sscanf(line, "H %503s %u %lld", name, &value, &now) == 3);
          union all_addr address = {0};
          address.addr4.s_addr = value;
          char *owned = strdup(name);
          assert(owned);
          cache_add_dhcp_entry(owned, AF_INET, &address, now);
          printf("H");
        }
      else if (line[0] == 'Q')
        {
          assert(sscanf(line, "Q %503s %u %lld", name, &type, &now) == 3);
          struct crec *entry = NULL;
          printf("Q");
          while ((entry = cache_find_by_name(entry, name, now, type_flags(type) | F_NO_RR)))
            {
              printf(" %u:%lld:%u:", !!(entry->flags & F_NEG), (long long)entry->ttd,
                     !!(entry->flags & (F_DHCP | F_HOSTS | F_CONFIG)));
              if (entry->flags & F_NEG)
                printf("%s", entry->flags & F_NO_RR ? "-" : cache_get_name(entry) + entry->addr.rrdata.datalen);
              else if (entry->flags & F_CNAME)
                printf("%s", cache_get_cname_target(entry));
              else if (entry->flags & (F_IPV4 | F_IPV6))
                printf("%u", entry->addr.addr4.s_addr);
              else if (entry->flags & F_KEYTAG)
                {
                  unsigned char bytes[64];
                  assert(entry->addr.rrblock.datalen <= sizeof(bytes));
                  blockdata_retrieve(entry->addr.rrblock.rrdata, entry->addr.rrblock.datalen, bytes);
                  for (unsigned i = 0; i < entry->addr.rrblock.datalen; i++) printf("%02x", bytes[i]);
                }
              else
                printf("%u", (unsigned char)entry->addr.rrdata.data[0]);
            }
        }
      else
        abort();
      printf(" | %u %u\n", daemon->metrics[METRIC_DNS_CACHE_INSERTED],
             daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
    }
  free(line);
  fclose(input);
}

int main(int argc, char **argv)
{
  assert(argc == 7);
  char *options[] = {argv[0], "-C", argv[1], NULL};
  rand_init();
  read_opts(3, options, "cache-transfer");
  daemon->pipe_to_parent = -1;
  daemon->namebuff = safe_malloc(MAXDNAME);
  daemon->addrbuff = safe_malloc(ADDRSTRLEN);
  cache_init(); blockdata_init(); cache_reload();
  commands(argv[2], "P0");
  fflush(stdout);
  FILE *child_log = tmpfile();
  assert(child_log);
  int channel[2];
  assert(pipe(channel) == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0)
    {
      close(channel[0]);
      daemon->pipe_to_parent = channel[1];
      assert(dup2(fileno(child_log), STDOUT_FILENO) >= 0);
      commands(argv[3], "CH");
      fflush(stdout);
      close(channel[1]);
      _exit(0);
    }
  close(channel[1]);
  commands(argv[4], "P1");
  time_t now = strtoll(argv[6], NULL, 10);
  while (cache_recv_insert(now, channel[0]))
    printf("R %d | %u %u\n", !insert_error,
           daemon->metrics[METRIC_DNS_CACHE_INSERTED], daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
  close(channel[0]);
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  rewind(child_log);
  char buffer[4096];
  while (fgets(buffer, sizeof(buffer), child_log)) fputs(buffer, stdout);
  fclose(child_log);
  commands(argv[5], "P2");
  return 0;
}
