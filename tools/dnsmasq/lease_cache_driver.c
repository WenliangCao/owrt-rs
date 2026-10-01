/* Compile the unchanged exact cache.c in this translation unit so the fixture
 * can call cache_hash/get_config_crec to place local blockers. All cache
 * operations, including DHCP publication, remain the real implementation. */
#include "cache.c"
#include <assert.h>

static unsigned kind_flags(unsigned type) {
  return type == 1 ? F_IPV4 : type == 28 ? F_IPV6 : type == 5 ? F_CNAME :
         type == 65536 ? F_NXDOMAIN : F_RR;
}

static unsigned kind_type(struct crec *c) {
  return c->flags & F_IPV4 ? 1 : c->flags & F_IPV6 ? 28 : c->flags & F_CNAME ? 5 :
         c->flags & F_NXDOMAIN ? 65536 : c->addr.rrdata.rrtype;
}

int main(int argc, char **argv) {
  rand_init(); read_opts(argc, argv, "lease-cache-oracle");
  daemon->pipe_to_parent = -1;
  cache_init(); blockdata_init();
  struct crec *ids[2048] = {0}; unsigned count = 0;
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0) {
    char name[504]; unsigned type, ttl, value, negative, reverse, immortal, local;
    long long now;
    if (line[0] == 'B') { cache_start_insert(); puts("B"); }
    else if (line[0] == 'C') { cache_end_insert(); printf("C %d\n", !insert_error); }
    else if (line[0] == 'I') {
      assert(sscanf(line, "I %503s %u %u %u %u %lld", name, &type, &ttl, &value, &negative, &now) == 6);
      union all_addr address = {0};
      if (type == 1 || type == 28) address.addr4.s_addr = value;
      else if (type != 5) { address.rrdata.rrtype = type; address.rrdata.data[0] = value; }
      struct crec *c = cache_insert(name, type == 5 ? NULL : &address, C_IN, now, ttl,
                                    F_FORWARD | kind_flags(type) | (negative ? F_NEG : 0));
      if (c && type == 5) { c->addr.cname.target.cache = NULL; c->addr.cname.is_name_ptr = 0; }
      assert(count < 2048); ids[count++] = c;
      printf("I %d\n", c != NULL);
    } else if (line[0] == 'L') {
      unsigned a, b; assert(sscanf(line, "L %u %u", &a, &b) == 2 && a < count && b < count);
      int ok = ids[a] && ids[b] && (ids[a]->flags & F_CNAME);
      if (ok) { next_uid(ids[b]); ids[a]->addr.cname.target.cache = ids[b]; ids[a]->addr.cname.uid = ids[b]->uid; }
      printf("L %d\n", ok);
    } else if (line[0] == 'H') {
      assert(sscanf(line, "H %503s %u %u %u %u", name, &type, &reverse, &immortal, &local) == 5);
      struct crec *c = get_config_crec(); assert(c);
      c->flags = F_NAMEP | F_FORWARD | kind_flags(type) | (local ? F_CONFIG : F_DHCP) |
                 (reverse ? F_REVERSE : 0) | (immortal ? F_IMMORTAL : 0);
      c->name.namep = strdup(name); assert(c->name.namep); c->ttd = 2000; c->uid = UID_NONE;
      memset(&c->addr, 0, sizeof(c->addr));
      if (type == 5) { c->addr.cname.is_name_ptr = 1; c->addr.cname.target.name = "target.test"; }
      cache_hash(c); puts("H");
    } else if (line[0] == 'D') {
      assert(sscanf(line, "D %503s", name) == 1);
      union all_addr address = {0}; assert(inet_pton(AF_INET, "192.0.2.7", &address.addr4) == 1);
      char *owned = strdup(name); assert(owned);
      cache_add_dhcp_entry(owned, AF_INET, &address, 2000); puts("D");
    } else if (line[0] == 'Q') {
      assert(sscanf(line, "Q %503s %u %lld", name, &type, &now) == 3);
      struct crec *c = NULL; printf("Q");
      while ((c = cache_find_by_name(c, name, now, kind_flags(type) | F_NO_RR))) {
        if (c->flags & (F_HOSTS | F_DHCP | F_CONFIG)) continue;
        unsigned t = kind_type(c), v = t == 5 ? 0 : t == 1 || t == 28 ? c->addr.addr4.s_addr : (unsigned char)c->addr.rrdata.data[0];
        printf(" %u:%u:%u:%lld", t, v, !!(c->flags & F_NEG), (long long)c->ttd);
      }
      puts("");
    } else abort();
    fflush(stdout);
  }
  free(line); return 0;
}
