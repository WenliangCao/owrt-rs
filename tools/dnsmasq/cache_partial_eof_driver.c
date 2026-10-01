/* Exact cache.c and real util.o read_write: bounded native-ABI partial EOF.
 * The only synthetic input is a valid insertion transaction cut at a recorded
 * byte offset. No cache implementation or I/O helper is replaced.
 */
#include "cache.c"
#include <assert.h>
#include <sys/wait.h>

static unsigned char wire[1024];
static size_t wire_size;

struct spans {
  size_t length, name, ttd, flags, address, end;
};

static void append(const void *value, size_t size)
{
  assert(wire_size + size <= sizeof(wire));
  memcpy(wire + wire_size, value, size);
  wire_size += size;
}

static union all_addr ipv4(unsigned suffix)
{
  union all_addr value;
  char text[32];
  memset(&value, 0, sizeof(value));
  snprintf(text, sizeof(text), "192.0.2.%u", suffix);
  assert(inet_pton(AF_INET, text, &value.addr4) == 1);
  return value;
}

static struct spans record(const char *host, unsigned value)
{
  struct spans offsets;
  ssize_t length = strlen(host);
  time_t expiry = 220;
  unsigned int flags = F_FORWARD | F_IPV4;
  union all_addr addr = ipv4(value);
  offsets.length = wire_size; append(&length, sizeof(length));
  offsets.name = wire_size; append(host, length);
  offsets.ttd = wire_size; append(&expiry, sizeof(expiry));
  offsets.flags = wire_size; append(&flags, sizeof(flags));
  offsets.address = wire_size; append(&addr, sizeof(addr));
  offsets.end = wire_size;
  return offsets;
}

static struct crec *insert_a(char *host, unsigned value)
{
  union all_addr addr = ipv4(value);
  struct crec *entry = cache_insert(host, &addr, C_IN, 100, 120, F_FORWARD | F_IPV4);
  assert(entry);
  return entry;
}

static unsigned pending_count(void)
{
  unsigned count = 0;
  for (struct crec *entry = new_chain; entry; entry = entry->next)
    count++;
  return count;
}

static void lookup(char *host, unsigned flags)
{
  struct crec *entry = NULL;
  int comma = 0;
  printf("\"%s\":[", host);
  while ((entry = cache_find_by_name(entry, host, 103, flags | F_NO_RR)))
    {
      if (comma++) printf(",");
      printf("{\"expiry\":%lld,\"value\":", (long long)entry->ttd);
      if (entry->flags & F_CNAME)
        printf("\"%s\"", cache_get_cname_target(entry));
      else
        {
          char addr[INET_ADDRSTRLEN];
          assert(inet_ntop(AF_INET, &entry->addr.addr4, addr, sizeof(addr)));
          printf("\"%s\"", addr);
        }
      printf("}");
    }
  printf("]");
}

static void observe(const char *stage, int received)
{
  printf("{\"stage\":\"%s\",\"received\":%d,\"pending_before_lookup\":%u,\"lookups\":{",
         stage, received, pending_count());
  lookup("owner.test", F_IPV4); printf(",");
  lookup("alias.test", F_CNAME); printf(",");
  lookup("filler.test", F_IPV4); printf(",");
  lookup("extra.test", F_IPV4); printf(",");
  lookup("second.test", F_IPV4);
  printf("},\"pending_after_lookup\":%u,\"insert_error\":%d,\"inserted\":%u,\"live_freed\":%u}\n",
         pending_count(), insert_error, daemon->metrics[METRIC_DNS_CACHE_INSERTED],
         daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
}

static void print_spans(const char *label, struct spans offsets)
{
  printf("\"%s\":{\"length\":%zu,\"name\":%zu,\"ttd\":%zu,\"flags\":%zu,\"address\":%zu,\"end\":%zu}",
         label, offsets.length, offsets.name, offsets.ttd, offsets.flags, offsets.address, offsets.end);
}

int main(int argc, char **argv)
{
  assert(argc == 4);
  const char *label = argv[2];
  int prior = !strcmp(label, "no-op-eof") || !strcmp(label, "op-only-eof");
  int pressure = !strcmp(label, "pressure-partial-second");
  int tail_record = pressure || !strcmp(label, "complete-record-eof");
  char *options[] = {argv[0], "-C", argv[1], NULL};
  rand_init();
  read_opts(3, options, "cache-partial-eof");
  daemon->pipe_to_parent = -1;
  daemon->namebuff = safe_malloc(MAXDNAME);
  daemon->addrbuff = safe_malloc(ADDRSTRLEN);
  cache_init(); blockdata_init(); cache_reload();

  cache_start_insert();
  struct crec *alias = cache_insert("alias.test", NULL, C_IN, 100, 120, F_FORWARD | F_CNAME);
  assert(alias);
  struct crec *owner = insert_a("owner.test", 11);
  next_uid(owner);
  alias->addr.cname.is_name_ptr = 0;
  alias->addr.cname.target.cache = owner;
  alias->addr.cname.uid = owner->uid;
  cache_end_insert();
  if (pressure)
    {
      cache_start_insert(); insert_a("filler.test", 55); cache_end_insert();
    }
  if (prior)
    {
      cache_start_insert(); insert_a("owner.test", 31);
    }

  unsigned char op = PIPE_OP_INSERT;
  append(&op, sizeof(op));
  struct spans first = record(pressure ? "extra.test" : "owner.test", 21);
  struct spans second = {0};
  if (tail_record) second = record("second.test", 22);
  size_t marker = wire_size;
  ssize_t end = -1;
  append(&end, sizeof(end));
  size_t cut;
  if (!strcmp(label, "no-op-eof")) cut = 0;
  else if (!strcmp(label, "op-only-eof")) cut = 1;
  else if (!strcmp(label, "partial-length")) cut = first.length + sizeof(ssize_t) - 1;
  else if (!strcmp(label, "partial-name")) cut = first.name + 3;
  else if (!strcmp(label, "partial-address")) cut = first.address + sizeof(union all_addr) - 1;
  else if (!strcmp(label, "complete-record-eof")) cut = first.end;
  else if (pressure) cut = second.address + sizeof(union all_addr) - 1;
  else if (!strcmp(label, "partial-marker")) cut = marker + sizeof(ssize_t) - 1;
  else { assert(!strcmp(label, "complete-control")); cut = wire_size; }

  unsigned endian = 1;
  printf("{\"case\":\"%s\",\"abi\":{\"ssize_t\":%zu,\"time_t\":%zu,\"unsigned_int\":%zu,\"union_all_addr\":%zu,\"little_endian\":%u,\"insert_op\":%u,\"address_flags\":%u},\"cut\":%zu,\"total\":%zu,\"marker\":%zu,",
         label, sizeof(ssize_t), sizeof(time_t), sizeof(unsigned int), sizeof(union all_addr),
         *(unsigned char *)&endian, op, F_FORWARD | F_IPV4, cut, wire_size, marker);
  print_spans("first", first);
  if (tail_record) { printf(","); print_spans("second", second); }
  printf("}\n");
  FILE *raw = fopen(argv[3], "wb");
  assert(raw && fwrite(wire, 1, wire_size, raw) == wire_size);
  assert(fclose(raw) == 0);
  observe("before", -1);
  fflush(stdout);

  int channel[2];
  assert(pipe(channel) == 0);
  pid_t writer = fork();
  assert(writer >= 0);
  if (writer == 0)
    {
      close(channel[0]);
      if (cut) assert(read_write(channel[1], wire, cut, RW_WRITE));
      close(channel[1]);
      _exit(0);
    }
  close(channel[1]);
  int received = cache_recv_insert(103, channel[0]);
  close(channel[0]);
  int status;
  assert(waitpid(writer, &status, 0) == writer);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  observe("after-receive", received);
  cache_start_insert();
  observe("after-next-start", -1);
  return 0;
}
