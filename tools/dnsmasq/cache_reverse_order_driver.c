/* Read-only hash/LRU observations around unchanged exact cache.c operations. */
#include "cache.c"
#include <assert.h>
#include <sys/wait.h>

#define POOL_COUNT 257
static char pool[POOL_COUNT][32];
static unsigned buckets[POOL_COUNT];
static unsigned selected[3], ttls[3], count;
static const char *profile;

static void token(struct crec *entry)
{
  assert(entry->flags & F_IPV4);
  assert(!(entry->flags & (F_NEG | F_HOSTS | F_DHCP | F_CONFIG | F_CNAME | F_RR)));
  printf("%c4:%s:%lld:%08x", entry->flags & F_REVERSE ? 'R' : 'F',
         cache_get_name(entry), (long long)entry->ttd, ntohl(entry->addr.addr4.s_addr));
}

static void snapshot(const char *phase, time_t now)
{
  printf("STATE %s %lld %u %u %d\n", phase, (long long)now,
         daemon->metrics[METRIC_DNS_CACHE_INSERTED], daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED], insert_error);
  printf("LRU %s", phase);
  for (struct crec *entry = cache_head; entry; entry = entry->next)
    if (entry->flags & (F_FORWARD | F_REVERSE)) { putchar(' '); token(entry); }
  putchar('\n');
  printf("TAIL %s ", phase);
  if (cache_tail && (cache_tail->flags & (F_FORWARD | F_REVERSE))) token(cache_tail);
  else putchar('-');
  putchar('\n');
  for (int bucket = 0; bucket < hash_size; bucket++)
    if (hash_table[bucket])
      {
        printf("HASH %s %d", phase, bucket);
        for (struct crec *entry = hash_table[bucket]; entry; entry = entry->hash_next)
          { putchar(' '); token(entry); }
        putchar('\n');
      }
}

static void insert(const char *phase, char *name, unsigned addr, unsigned ttl, time_t now, int reverse)
{
  union all_addr value = {0}; value.addr4.s_addr = htonl(addr);
  struct crec *entry = cache_insert(name, &value, C_IN, now, ttl, F_IPV4 | (reverse ? F_REVERSE : F_FORWARD));
  printf("INSERT %s %d\n", phase, entry != NULL);
}

static void forward_transaction(const char *phase, char *name, unsigned addr, time_t now)
{
  cache_start_insert(); insert(phase, name, addr, 120, now, 0); cache_end_insert();
  printf("COMMIT %s %d\n", phase, !insert_error);
}

static void lookup_address(const char *phase)
{
  union all_addr address = {0}; address.addr4.s_addr = htonl(0xc0000201);
  struct crec *entry = NULL; printf("A %s", phase);
  while ((entry = cache_find_by_addr(entry, &address, 120, F_IPV4)))
    { putchar(' '); token(entry); }
  putchar('\n');
}

static void lookup_name(const char *phase, char *name)
{
  struct crec *entry = NULL; printf("Q %s", phase);
  while ((entry = cache_find_by_name(entry, name, 120, F_IPV4 | F_NO_RR)))
    { putchar(' '); token(entry); }
  putchar('\n');
}

static void choose_names(void)
{
  /* Enumeration bound and selection policy are frozen before any run. This
     observes the real hash; it does not alter its salt or retry processes. */
  printf("META %s %d %d\n", profile, hash_size, daemon->cachesize);
  printf("MIX ");
  for (unsigned i = 0; i < 64; i++) printf("%02x", ((const unsigned char *)typestr)[i]);
  putchar('\n');
  assert(hash_size == 64);
  unsigned sizes[64] = {0};
  for (unsigned i = 0; i < POOL_COUNT; i++)
    {
      snprintf(pool[i], sizeof(pool[i]), "mp%03u.test", i);
      buckets[i] = (unsigned)(hash_bucket(pool[i]) - hash_table);
      sizes[buckets[i]]++;
      printf("POOL %u %s %u\n", i, pool[i], buckets[i]);
    }
  count = profile[0] == 'S' ? 2 : 3;
  if (strcmp(profile, "D") == 0)
    {
      unsigned found = 0;
      for (unsigned i = 0; i < POOL_COUNT && found < 3; i++)
        {
          unsigned j;
          for (j = 0; j < found && buckets[selected[j]] != buckets[i]; j++);
          if (j == found) selected[found++] = i;
        }
      assert(found == 3);
    }
  else if (strcmp(profile, "C") == 0 || strcmp(profile, "M") == 0 || strcmp(profile, "I") == 0)
    {
      unsigned bucket;
      for (bucket = 0; bucket < 64 && sizes[bucket] < 3; bucket++);
      assert(bucket < 64);
      unsigned found = 0;
      for (unsigned i = 0; i < POOL_COUNT && found < 3; i++)
        if (buckets[i] == bucket) selected[found++] = i;
      assert(found == 3);
      if (strcmp(profile, "M") == 0)
        {
          unsigned i;
          for (i = 0; i < POOL_COUNT && buckets[i] == bucket; i++);
          assert(i < POOL_COUNT); selected[2] = i;
        }
      else if (strcmp(profile, "I") == 0) selected[2] = selected[0];
    }
  else
    for (unsigned i = 0; i < count; i++) selected[i] = 0;
  for (unsigned i = 0; i < count; i++) ttls[i] = 120;
  if (strcmp(profile, "E") == 0 || strcmp(profile, "I") == 0)
    for (unsigned i = 0; i < count; i++) ttls[i] = 30 * (i + 1);
  else if (strcmp(profile, "S1") == 0) { ttls[0] = 10; ttls[1] = 60; }
  else if (strcmp(profile, "S2") == 0) { ttls[0] = 60; ttls[1] = 10; }
  else assert(strcmp(profile, "D") == 0 || strcmp(profile, "C") == 0 || strcmp(profile, "M") == 0);
  for (unsigned i = 0; i < count; i++)
    printf("SELECT %u %u %s %u %u\n", i, selected[i], pool[selected[i]], buckets[selected[i]], ttls[i]);
}

int main(int argc, char **argv)
{
  assert(argc == 3); assert(setvbuf(stdout, NULL, _IOLBF, 0) == 0); profile = argv[2];
  char *options[] = {argv[0], "-C", argv[1], NULL};
  rand_init(); read_opts(3, options, "reverse-order");
  daemon->pipe_to_parent = -1;
  daemon->namebuff = safe_malloc(MAXDNAME); daemon->addrbuff = safe_malloc(ADDRSTRLEN);
  cache_init(); blockdata_init(); cache_reload(); choose_names();
  forward_transaction("seed", "seed.test", 0xc0000221, 100);
  snapshot("parent-seed", 100); fflush(stdout);
  FILE *child_log = tmpfile(); assert(child_log);
  int channel[2]; assert(pipe(channel) == 0); pid_t child = fork(); assert(child >= 0);
  if (child == 0)
    {
      close(channel[0]); daemon->pipe_to_parent = channel[1];
      assert(dup2(fileno(child_log), STDOUT_FILENO) >= 0);
      cache_start_insert();
      for (unsigned i = 0; i < count; i++) insert("child", pool[selected[i]], 0xc0000201, ttls[i], 100, 1);
      cache_end_insert(); printf("COMMIT child %d\n", !insert_error);
      snapshot("child-before", 120); lookup_address("child-first"); snapshot("child-after1", 120);
      lookup_address("child-repeat"); snapshot("child-after2", 120);
      fflush(stdout); close(channel[1]); _exit(0);
    }
  close(channel[1]); forward_transaction("between", "parent.test", 0xc0000222, 101);
  snapshot("parent-between", 103);
  unsigned imports = 0;
  while (cache_recv_insert(103, channel[0])) { imports++; printf("IMPORT %d\n", !insert_error); }
  assert(imports == 1); close(channel[0]);
  int status; assert(waitpid(child, &status, 0) == child); assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  rewind(child_log); char buffer[8192]; while (fgets(buffer, sizeof(buffer), child_log)) fputs(buffer, stdout); fclose(child_log);
  snapshot("parent-before", 120); lookup_address("parent-first"); snapshot("parent-after1", 120);
  lookup_address("parent-repeat"); snapshot("parent-after2", 120);
  lookup_name("promote-parent", "parent.test"); lookup_name("promote-seed", "seed.test");
  snapshot("parent-victim", 120);
  /* C counts the selected actual tail only when difftime(now, tail->ttd)<0.
     At equality it is not a live eviction, even if another RRset member lives. */
  forward_transaction("pressure", "new.test", 0xc0000223, 120);
  snapshot("parent-spill", 120); lookup_address("parent-removed");
  lookup_name("retained-parent", "parent.test"); lookup_name("retained-seed", "seed.test"); lookup_name("inserted-new", "new.test");
  snapshot("parent-final", 120);
  return 0;
}
