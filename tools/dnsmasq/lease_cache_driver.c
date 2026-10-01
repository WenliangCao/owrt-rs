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
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init(); blockdata_init(); build_server_array(); cache_reload();
  struct crec *ids[2048] = {0}; unsigned count = 0;
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0) {
    char name[504]; unsigned type, ttl, value, negative, reverse, immortal, local;
    long long now;
    if (line[0] == 'B') { cache_start_insert(); puts("B"); }
    else if (line[0] == 'C') { cache_end_insert(); printf("C %d\n", !insert_error); }
    else if (line[0] == 'R') { cache_unhash_dhcp(); puts("R"); }
    else if (line[0] == 'S') { cache_reload(); puts("S"); }
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
    } else if (line[0] == 'V') {
      char other[504]; assert(sscanf(line, "V %503s %503s", name, other) == 2);
      printf("V %d\n", hash_bucket(name) == hash_bucket(other));
    } else if (line[0] == 'X') {
      unsigned same; assert(sscanf(line, "X %503s %u", name, &same) == 2);
      char other[504]; unsigned i;
      for (i = 0; i < 100000; i++) {
        snprintf(other, sizeof(other), "collision%u.test", i);
        if ((hash_bucket(name) == hash_bucket(other)) == !!same) break;
      }
      assert(i < 100000); printf("X %s\n", other);
    } else if (line[0] == 'P' || line[0] == 'W') {
      int offset = 0; assert(sscanf(line + 1, " %lld %n", &now, &offset) == 1);
      char *hex = line + 1 + offset;
      size_t length = strcspn(hex, "\r\n") / 2;
      assert(length >= 12 && length <= 65535);
      memset(daemon->packet, 0, daemon->packet_buff_sz);
      for (size_t i = 0; i < length; i++) {
        unsigned byte; assert(sscanf(hex + 2*i, "%2x", &byte) == 1);
        ((unsigned char *)daemon->packet)[i] = byte;
      }
      struct dns_header *header = (struct dns_header *)daemon->packet;
      if (line[0] == 'P') {
        int result = extract_addresses(header, length, daemon->namebuff, now, NULL, NULL, 0, 0, 0);
        printf("P %d\n", result);
      } else {
        int stale = 0, filtered = 0;
        length = answer_request(header, daemon->packet + 65535, length, (struct in_addr){0},
                                (struct in_addr){0}, now, 0, 0, 0, &stale, &filtered);
        printf("W ");
        if (!length) printf("NONE");
        else for (size_t i = 0; i < length; i++) printf("%02x", ((unsigned char *)header)[i]);
        putchar('\n');
      }
    } else if (line[0] == 'E') {
      assert(sscanf(line, "E %503s", name) == 1);
      cache_enumerate(1); struct crec *c; printf("E");
      while ((c = cache_enumerate(0))) {
        if (!(c->flags & F_FORWARD) || !hostname_isequal(cache_get_name(c), name)) continue;
        printf(" %u:%u:%d:%d", kind_type(c), c->flags, is_outdated_cname_pointer(c), is_expired(0, c));
      }
      puts("");
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
