#!/usr/bin/env python3
"""Compare Rust DHCP primitives with functions extracted from exact C sources.

No sockets, privilege, system service or physical device access. Generated C,
binaries, random input and full results must remain under ignored private/.
This is a primitive oracle, not a complete DHCP server equivalence test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "rfc2131.c": "14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c",
    "lease.c": "4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763",
    "util.c": "33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973",
    "dhcp-common.c": "9139906c5d3a438853fe84e90387cfc299c3c28e7b16a23c7d0d6922847ccc79",
}


def function(source, name):
    # Definitions in this source start at column zero. Requiring a return type
    # prevents accidentally selecting an indented call inside an if expression.
    match = re.search(r"\n(?:static\s+)?[A-Za-z_][\w \t*]*[ \t*]\b" + re.escape(name) + r"\([^;{}]*\)\s*\{", source)
    if not match:
        raise ValueError(f"missing source function: {name}")
    brace = source.index("{", match.start())
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


PREFIX = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <arpa/inet.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define option_len(opt) ((int)((opt)[1]))
#define option_ptr(opt, i) (&((opt)[(i)+2]))
#define CONFIG_TIME 1
#define have_config(config, flag) ((config) && ((config)->flags & (flag)))
#define LEASE_AUX_CHANGED 1
#define LEASE_EXP_CHANGED 2
#define LEASE_NEW 4
#define LEASE_CHANGED 8
#define LEASE_AUTH_NAME 16
#define LEASE_NA 32
#define LEASE_TA 64
#define OPT_DHCP_FQDN 1
#define OPT_LEASE_RO 2
#define OPT_LEASE_RENEW 4
#define METRIC_LEASES_ALLOCATED_4 2
#define HAVE_SCRIPT
#define ACTION_ADD 1
#define ACTION_OLD 2
#define ACTION_DEL 3
#define ACTION_OLD_HOSTNAME 4
#define whine_malloc malloc
#define MAXDNAMESTR 1024
#define PACKETSZ 512
#define MAXDNAME 255
#define MAXLABEL 63
#define RRFIXEDSZ 10
#define ARPHRD_ETHER 1
#define MS_DHCP 0
#define LOG_WARNING 0
#define LOG_ERR 0
#define DHOPT_VENDOR_MATCH 1
#define INADDRSZ 4
#define EC_MISC 0
#define _(s) (s)
#define METRIC_LEASES_PRUNED_4 0
#define METRIC_LEASES_PRUNED_6 1
struct dhcp_config { unsigned int lease_time; int flags; };
struct dhcp_context { unsigned int lease_time; };
struct dhcp_netid { char *net; struct dhcp_netid *next; };
struct dhcp_opt { int flags, opt, len; unsigned char *val; struct dhcp_netid *netid; struct dhcp_opt *next; };
struct pxe_service { int CSA, type; char *menu, *basename, *sname; struct in_addr server; struct dhcp_netid *netid; struct pxe_service *next; };
struct dhcp_lease {
  unsigned char hwaddr[16], *clid;
  int hwaddr_len, hwaddr_type, clid_len, flags;
  struct in_addr addr;
  time_t expires;
  char *hostname, *fqdn, *old_hostname;
  unsigned char *extradata;
  unsigned char *agent_id, *vendorclass;
  int agent_id_len, vendorclass_len;
  struct dhcp_lease *next;
};
union all_addr { struct in_addr addr4; };
static struct { unsigned long metrics[3]; char dhcp_buff3[256], dhcp_buff2[256], dhcp_buff[256], namebuff[1024], packet[1024]; struct pxe_service *pxe_services; struct dhcp_opt *dhcp_opts; } oracle_daemon;
#define daemon (&oracle_daemon)
static struct dhcp_lease *leases, *old_leases;
static int leases_left, file_dirty, dns_dirty;
static struct dhcp_lease file_entries[64];
static int file_count, invalid_records;
static unsigned int script_options;
static int option_bool(unsigned int flag) { return (script_options & flag) != 0; }
static int hostname_isequal(const char *a, const char *b) {
  while (*a && *b) { unsigned char x = *a++, y = *b++; if (x >= 'A' && x <= 'Z') x += 32; if (y >= 'A' && y <= 'Z') y += 32; if (x != y) return 0; }
  return *a == *b;
}
static void queue_script(int action, struct dhcp_lease *lease, char *name, time_t now) {
  (void)now; printf("%d:%u:", action, ntohl(lease->addr.s_addr));
  if (!name) printf("-"); else for (unsigned char *p = (unsigned char *)name; *p; p++) printf("%02x", *p);
  printf(";");
}
static struct in_addr a_record_from_hosts(char *name, time_t now) {
  (void)now; struct in_addr addr = { .s_addr = strcmp(name, "server.test") ? 0 : htonl(0xc000022c) }; return addr;
}
static void my_syslog(int priority, const char *format, ...) { (void)priority; (void)format; invalid_records++; }
static void die(const char *format, const char *extra, int code) { (void)format; (void)extra; (void)code; abort(); }
static struct dhcp_lease *lease4_allocate(struct in_addr addr) {
  if (file_count >= 64) abort();
  struct dhcp_lease *lease = &file_entries[file_count++];
  lease->addr = addr; lease->next = leases; leases = lease; return lease;
}
static void lease_set_hwaddr(struct dhcp_lease *lease, const unsigned char *hwaddr, const unsigned char *clid, int hwlen, int hwtype, int clidlen, time_t now, int force) {
  (void)now; (void)force; lease->hwaddr_len = hwlen; lease->hwaddr_type = hwtype;
  memcpy(lease->hwaddr, hwaddr, hwlen);
  if (clidlen) { lease->clid = malloc(clidlen); memcpy(lease->clid, clid, clidlen); lease->clid_len = clidlen; }
}
static void lease_set_hostname(struct dhcp_lease *lease, const char *name, int auth, char *domain, char *config_domain) {
  (void)auth; (void)domain; (void)config_domain; lease->hostname = strdup(name);
}
static void lease_set_agent_id(struct dhcp_lease *lease, unsigned char *bytes, int len) {
  free(lease->agent_id); lease->agent_id = calloc(len + 1, 1); memcpy(lease->agent_id, bytes, len); lease->agent_id_len = len;
}
static void lease_set_vendorclass(struct dhcp_lease *lease, unsigned char *bytes, int len) {
  free(lease->vendorclass); lease->vendorclass = calloc(len + 1, 1); memcpy(lease->vendorclass, bytes, len); lease->vendorclass_len = len;
}
'''

SUFFIX = r'''
static size_t decode(const char *s, unsigned char *out) {
  if (!s || !strcmp(s, "-")) return 0;
  size_t n = strlen(s) / 2;
  for (size_t i = 0; i < n; i++) {
    unsigned int x; if (sscanf(s + i * 2, "%2x", &x) != 1) abort();
    out[i] = x;
  }
  return n;
}
static char *word(void) { return strtok(NULL, " \t\r\n"); }
static void identity(struct dhcp_lease *lease) {
  lease->hwaddr_type = atoi(word());
  lease->hwaddr_len = decode(word(), lease->hwaddr);
  unsigned char *clid = calloc(256, 1);
  lease->clid_len = decode(word(), clid);
  if (lease->clid_len) lease->clid = clid; else free(clid);
}
static void print_bytes(unsigned char *bytes, int length) {
  if (!bytes) printf("-"); else for (int i = 0; i < length; i++) printf("%02x", bytes[i]);
  printf(",");
}
static struct dhcp_lease *entry(unsigned int address) {
  struct in_addr addr = { .s_addr = htonl(address) }; return lease_find_by_addr(addr);
}
int main(void) {
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0) {
    char *op = strtok(line, " \t\r\n");
    if (!strcmp(op, "V")) {
      int architecture = atoi(word()), custom_prompt = atoi(word()), port4011 = atoi(word());
      unsigned char tag[256] = {0}; decode(word(), tag); struct dhcp_netid pool = { .net = (char *)tag };
      int count = atoi(word()); if (count > 64) abort();
      struct pxe_service services[64] = {0}; struct dhcp_netid filters[64] = {0};
      for (int i = 0; i < count; i++) {
        services[i].CSA = atoi(word()); services[i].type = atoi(word());
        services[i].menu = calloc(1024, 1); decode(word(), (unsigned char *)services[i].menu);
        char *base = word(); if (strcmp(base, "-")) { services[i].basename = calloc(1024, 1); decode(base, (unsigned char *)services[i].basename); }
        services[i].server.s_addr = htonl(strtoul(word(), NULL, 10));
        char *name = word(); if (strcmp(name, "-")) { services[i].sname = calloc(1024, 1); decode(name, (unsigned char *)services[i].sname); }
        char *filter = word(); if (strcmp(filter, "-")) { filters[i].net = calloc(256, 1); decode(filter, (unsigned char *)filters[i].net); services[i].netid = &filters[i]; }
        services[i].next = i + 1 < count ? &services[i + 1] : NULL;
      }
      unsigned char prompt[] = {7, 'C'}; struct dhcp_opt configured = { .flags = DHOPT_VENDOR_MATCH, .opt = 10, .len = 2, .val = prompt };
      daemon->dhcp_opts = custom_prompt ? &configured : NULL; daemon->pxe_services = count ? services : NULL;
      struct in_addr local = { .s_addr = htonl(0xc0000201) }; struct dhcp_netid *tags = tag[0] ? &pool : NULL;
      struct dhcp_packet packet = {0}; int workaround = pxe_uefi_workaround(architecture, tags, &packet, local, 100, port4011);
      printf("%d:%u:", workaround, ntohl(packet.siaddr.s_addr));
      print_bytes(packet.file, strlen((char *)packet.file)); print_bytes(packet.sname, strlen((char *)packet.sname)); printf("|");
      for (struct dhcp_opt *option = pxe_opts(architecture, tags, local, 100); option; option = option->next) {
        printf("%d:", option->opt); for (int i = 0; i < option->len; i++) printf("%02x", option->val[i]); printf(";");
      }
      puts("");
      for (int i = 0; i < count; i++) { free(services[i].menu); free(services[i].basename); free(services[i].sname); free(filters[i].net); }
      daemon->dhcp_opts = NULL; daemon->pxe_services = NULL;
    } else if (!strcmp(op, "S")) {
      script_options = atoi(word()); leases = old_leases = NULL; leases_left = 64;
      int steps = atoi(word());
      for (int step = 0; step < steps; step++) {
        char *operation = word();
        if (!strcmp(operation, "a")) {
          unsigned int addr = strtoul(word(), NULL, 10); struct in_addr address = { .s_addr = htonl(addr) };
          struct dhcp_lease *lease = reference_lease4_allocate(address);
          unsigned char hardware[1] = {addr}; reference_set_hwaddr(lease, hardware, NULL, 1, 1, 0, 100, 0);
          lease_set_expires(lease, 1000, 100);
        } else if (!strcmp(operation, "n")) {
          struct dhcp_lease *lease = entry(strtoul(word(), NULL, 10));
          unsigned char name[1024] = {0}, domain[1024] = {0};
          char *name_hex = word(); int has_name = strcmp(name_hex, "-"); decode(name_hex, name);
          char *domain_hex = word(); int has_domain = strcmp(domain_hex, "-"); decode(domain_hex, domain);
          int auth = atoi(word());
          reference_set_hostname(lease, has_name ? (char *)name : NULL, auth, has_domain ? (char *)domain : NULL, NULL);
        } else if (!strcmp(operation, "r")) {
          struct dhcp_lease *lease = entry(strtoul(word(), NULL, 10));
          unsigned int length = strtoul(word(), NULL, 10); time_t now = strtoll(word(), NULL, 10); lease_set_expires(lease, length, now);
        } else if (!strcmp(operation, "p")) {
          unsigned int target = strtoul(word(), NULL, 10); time_t now = strtoll(word(), NULL, 10); lease_prune(target ? entry(target) : NULL, now);
        } else if (!strcmp(operation, "h")) rerun_scripts();
        else if (!strcmp(operation, "d")) while (do_script_run(100));
        else abort();
      }
      puts("");
      // Free undelivered state without emitting extra events into this case.
      for (int list = 0; list < 2; list++) {
        struct dhcp_lease *lease = list ? old_leases : leases;
        while (lease) { struct dhcp_lease *next = lease->next; free(lease->hostname); free(lease->fqdn); free(lease->old_hostname); free(lease->clid); free(lease); lease = next; }
      }
      leases = old_leases = NULL;
    } else if (!strcmp(op, "H")) {
      unsigned char bytes[256]={0};decode(word(),bytes);
      if(!legal_hostname((char *)bytes)){puts("-");continue;}
      strip_hostname((char *)bytes);
      if(!bytes[0])puts("-");else{for(size_t i=0;bytes[i];i++)printf("%02x",bytes[i]);puts("");}
    } else if (!strcmp(op, "X")) {
      unsigned char bytes[65536] = {0}; decode(word(), bytes);
      int maximum = atoi(word()), typed = atoi(word()), hardware_type = 0;
      int n = parse_hex((char *)bytes, bytes, maximum, NULL, typed ? &hardware_type : NULL);
      printf("%u:", (unsigned int)hardware_type);
      if (n < 0) printf("-"); else for (int i = 0; i < n; i++) printf("%02x", bytes[i]);
      puts("");
    } else if (!strcmp(op, "F")) {
      unsigned char bytes[65536] = {0}; size_t len = decode(word(), bytes);
      FILE *file = tmpfile(); if (!file) abort(); fwrite(bytes, 1, len, file); rewind(file);
      leases = NULL; memset(file_entries, 0, sizeof(file_entries)); file_count = invalid_records = 0;
      int clean = read_leases(100, file); fclose(file);
      printf("%d:%d", clean, invalid_records);
      for (int i = 0; i < file_count; i++) {
        struct dhcp_lease *lease = &file_entries[i]; char address[16];
        inet_ntop(AF_INET, &lease->addr, address, sizeof(address));
        printf("|%lld,%u,%s,", (long long)lease->expires, (unsigned int)lease->hwaddr_type, address);
        print_bytes(lease->hwaddr, lease->hwaddr_len);
        print_bytes((unsigned char *)lease->hostname, lease->hostname ? strlen(lease->hostname) : 0);
        print_bytes(lease->clid, lease->clid_len); print_bytes(lease->agent_id, lease->agent_id_len); print_bytes(lease->vendorclass, lease->vendorclass_len);
        free(lease->hostname); free(lease->clid); free(lease->agent_id); free(lease->vendorclass);
      }
      puts("");
    } else if (!strcmp(op, "O") || !strcmp(op, "W")) {
      unsigned char bytes[65536] = {0};
      size_t len = decode(word(), bytes);
      int code = atoi(word()), minimum = atoi(word());
      unsigned char *found = !strcmp(op, "O") ? option_find1(bytes, bytes + len, code, minimum) :
        option_find((struct dhcp_packet *)bytes, len, code, minimum);
      if (!found) puts("-"); else {
        printf("%zu:", (size_t)(found - bytes));
        if (code != 255) for (int i = 0; i < option_len(found); i++) printf("%02x", found[2 + i]);
        puts("");
      }
    } else if (!strcmp(op, "D")) {
      struct dhcp_context context = { .lease_time = strtoul(word(), NULL, 10) };
      struct dhcp_config config = {0};
      char *configured = word();
      if (strcmp(configured, "-")) { config.flags = CONFIG_TIME; config.lease_time = strtoul(configured, NULL, 10); }
      char *request = word(); unsigned char option[6] = {51, 4};
      uint32_t val = htonl(strtoul(request, NULL, 10)); memcpy(option + 2, &val, 4);
      printf("%u\n", calc_time(&context, &config, strcmp(request, "-") ? option : NULL));
    } else if (!strcmp(op, "E")) {
      unsigned int len = strtoul(word(), NULL, 10); time_t now = strtoll(word(), NULL, 10);
      struct dhcp_lease lease = {0}; lease_set_expires(&lease, len, now);
      printf("%lld\n", (long long)lease.expires);
    } else if (!strcmp(op, "I") || !strcmp(op, "P")) {
      struct dhcp_lease lookup = {0}, entries[64] = {0};
      time_t now = 0; int target = 0;
      if (!strcmp(op, "I")) identity(&lookup); else { now = strtoll(word(), NULL, 10); target = atoi(word()); }
      int count = atoi(word()); if (count > 64) abort(); leases = old_leases = NULL;
      for (int i = 0; i < count; i++) {
        entries[i].addr.s_addr = htonl(i + 1);
        if (!strcmp(op, "I")) identity(&entries[i]); else lease_set_expires(&entries[i], strtoul(word(), NULL, 10), 100);
        entries[i].next = leases; leases = &entries[i];
      }
      if (!strcmp(op, "I")) {
        struct dhcp_lease *found = lease_find_by_client(lookup.hwaddr, lookup.hwaddr_len, lookup.hwaddr_type, lookup.clid, lookup.clid_len);
        printf("%u\n", found ? ntohl(found->addr.s_addr) : 0);
      } else {
        lease_prune(target ? &entries[target - 1] : NULL, now);
        for (struct dhcp_lease *lease = old_leases; lease; lease = lease->next) {
          printf("%u", ntohl(lease->addr.s_addr)); if (lease->next) printf(",");
        }
        puts("");
      }
      free(lookup.clid); for (int i = 0; i < count; i++) free(entries[i].clid);
    } else abort();
  }
  free(line); return 0;
}
'''


def cases(seed, count):
    rng = random.Random(seed)
    samples = [
        "O 350103ff 53 1", "O 350000350103ff 53 1", "O 350103fe 53 1",
        "O 3505ff 53 1", "O ff 255 9", "O - 53 1",
        "D 43200 - 0", "D 60 - 0", "D 4294967295 - 4294967295",
        "E 0 100", "E 4294967295 100", "E 120 100",
        "I 1 010203 09 2 1 010203 09 1 010203 08",
        "I 1 010203 - 2 1 010203 09 1 010203 08",
        "P 220 0 3 120 121 4294967295",
        "F " + b"200\x0b02:00:00:00:00:01\x0c192.0.2.10\thost *\n".hex(),
    ]
    for _ in range(count):
        name=rng.choice([b"client",b"client.example",b"-bad",b"_bad",b"a b",b"name.",b".",b"a"*64,rng.randbytes(rng.randrange(256))])
        samples.append("H "+(name.hex() or "-"))
        region = bytearray()
        for _ in range(rng.randrange(0, 15)):
            tag = rng.randrange(256)
            if tag in (0, 255): region.append(tag)
            else:
                value = rng.randbytes(rng.randrange(0, 32))
                region.extend([tag, len(value)])
                region.extend(value)
        if rng.randrange(2) and region:
            del region[rng.randrange(len(region)):]
        code = rng.choice([0, 255, 52, 53, 61, rng.randrange(256)])
        minimum = rng.randrange(0, 36)
        samples.append(f"O {region.hex() or '-'} {code} {minimum}")
        packet = bytearray(240)
        packet[0:3] = bytes([1, 1, 6])
        packet[236:240] = bytes([99, 130, 83, 99])
        packet[44:108] = rng.randbytes(64)
        packet[108:236] = rng.randbytes(128)
        packet.extend([52, 1, rng.randrange(4)])
        packet.extend(region)
        samples.append(f"W {packet.hex()} {code} {minimum}")
        duration = rng.choice([0, 1, 60, 120, 43200, 0xffffffff, rng.randrange(0xffffffff)])
        requested = rng.choice(["-", str(duration), str(rng.randrange(0xffffffff))])
        configured = rng.choice(["-", "60", "4294967295", str(rng.randrange(0xffffffff))])
        samples.append(f"D {duration} {configured} {requested}")
        samples.append(f"E {duration} {rng.randrange(0, 1 << 40)}")
        identities = [(rng.randrange(1, 4), rng.choice(["-", "0102", "010203", "aabbcc", "ab"]), rng.choice(["-", "01", "0203", "abcd"])) for _ in range(rng.randrange(0, 12))]
        lookup = rng.choice(identities) if identities and rng.randrange(2) else (1, "010203", rng.choice(["-", "01", "0203"]))
        items = [lookup, *identities]
        samples.append("I " + " ".join(map(str, items[0])) + f" {len(identities)} " + " ".join(" ".join(map(str, item)) for item in items[1:]))
        lengths = [rng.choice([0, 1, 120, 121, 200, 0xffffffff]) for _ in range(rng.randrange(0, 12))]
        samples.append(f"P {rng.randrange(90, 350)} {rng.randrange(len(lengths) + 1)} {len(lengths)} " + " ".join(map(str, lengths)))
        token = "".join(rng.choices("abcdefABCDEF0123456789*:-", k=rng.randrange(0, 50))).encode()
        samples.append(f"X {token.hex() or '-'} {rng.choice([1, 2, 16, 255])} {rng.randrange(2)}")
        rows = []
        for index in range(rng.randrange(0, 8)):
            expiry = rng.choice(["0", "220", "-1", "99junk", "wrong"])
            hardware = rng.choice(["01:02:03:04:05:06", "06-aabbcc", "01:*", "bogus", "00-", "abcdef"])
            address = rng.choice([f"192.0.2.{index + 1}", "bad-address"])
            rows.append(f"{expiry} {hardware} {address} {rng.choice(['*', 'host', 'station'])} {rng.choice(['*', '01:02', 'wrong', '-'])}\n")
            if rng.randrange(2): rows.append(f"{rng.choice(['agent-info', 'vendorclass'])} {address} {rng.choice(['01:02', 'bad!', '-', '*'])}\n")
        if rng.randrange(4) == 0: rows.append(rng.choice(["tail", "tail short", "tail short invalid", "tail short invalid host"]))
        samples.append("F " + ("".join(rows).encode().hex() or "-"))
        name = rng.choice([b"host", b"HOST", b"station", b"h\xffst"]).hex()
        domain = rng.choice([b"a.test", b"b.test"]).hex()
        auth = rng.randrange(2)
        operations = ["a 1", f"n 1 {name} {domain} {auth}", "d", "a 2", f"n 2 {name} {domain} {rng.randrange(2)}", "d", "r 2 1000 200", "d", "h", "d", f"n 2 6e6577 - {auth}", "p 2 100", "d", "p 1 100", "d"]
        samples.append(f"S {rng.randrange(8)} {len(operations)} " + " ".join(operations))
        services = []
        for _ in range(rng.randrange(0, 8)):
            menu = rng.choice([b"boot", b"local", b"a" * 249, b"b" * 250, b"netboot"]).hex()
            base = rng.choice(["-", b"efi".hex(), b"boot.efi".hex()])
            sname = rng.choice(["-", b"server.test".hex(), b"unknown.test".hex()])
            filter_tag = rng.choice(["-", b"lan".hex(), b"!lan".hex(), b"guest".hex()])
            services.append(f"{rng.choice([0, 6, 7, 11])} {rng.choice([0, 1, 32768, 32769])} {menu} {base} {rng.choice([0, 0xc0000202])} {sname} {filter_tag}")
        samples.append(f"V {rng.choice([0, 6, 7, 11])} {rng.randrange(2)} {rng.randrange(2)} {rng.choice(['-', b'lan'.hex(), b'guest'.hex()])} {len(services)} " + " ".join(services))
    return samples


def run(command, log_path, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    log_path.write_text(json.dumps({"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
    if result.returncode:
        print(result.stderr)
        result.check_returncode()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "private/network-research-20260929/dns/dnsmasq-2.93-openwrt/src")
    parser.add_argument("--output", type=Path, default=ROOT / "private/dnsmasq-rewrite/dhcp-differential")
    parser.add_argument("--seed", type=int, default=20260929)
    parser.add_argument("--rounds", type=int, default=2000)
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to((ROOT / "private").resolve())
    output.mkdir(parents=True, exist_ok=True)
    sources = {}
    for name, expected in EXPECTED.items():
        content = (args.source / name).read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise SystemExit(f"source identity mismatch: {name}: {actual}")
        sources[name] = content.decode()
    extracted = [function(sources["rfc2131.c"], name) for name in ["option_find1", "option_find", "option_uint", "calc_time"]]
    extracted += [function(sources["util.c"], "parse_hex")]
    extracted += [function(sources["util.c"], name) for name in ["check_name", "legal_hostname"]]
    extracted += [function(sources["dhcp-common.c"], "strip_hostname")]
    extracted += [function(sources["lease.c"], name) for name in ["lease_set_expires", "lease_find_by_client", "lease_find_by_addr", "lease_prune", "read_leases"]]
    extracted += [function(sources["lease.c"], "kill_name"), function(sources["lease.c"], "lease_allocate")]
    for name, renamed in [("lease4_allocate", "reference_lease4_allocate"), ("lease_set_hwaddr", "reference_set_hwaddr"), ("lease_set_hostname", "reference_set_hostname")]:
        extracted.append(f"\n#define {name} {renamed}\n" + function(sources["lease.c"], name) + f"\n#undef {name}\n")
    extracted += [function(sources["lease.c"], name) for name in ["rerun_scripts", "do_script_run"]]
    extracted += [function(sources["dhcp-common.c"], "match_netid")]
    extracted += [function(sources["rfc2131.c"], name) for name in ["pxe_uefi_workaround", "pxe_opts"]]
    source = output / "oracle.c"
    source.write_text(PREFIX + (args.source / "dhcp-protocol.h").read_text() + "\n".join(extracted) + SUFFIX)
    cc = shutil.which("cc")
    rustc = shutil.which("rustc")
    cargo = shutil.which("cargo")
    if not cc or not rustc or not cargo: raise SystemExit("cc, cargo and rustc must be on PATH")
    target = ROOT / "components/dnsmasq/target/debug"
    commands = [
        [cc, "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O2", "-fsanitize=address,undefined", str(source), "-o", str(output / "c-oracle")],
        [cargo, "build", "--quiet", "--manifest-path", str(ROOT / "components/dnsmasq/Cargo.toml"), "--lib"],
        [rustc, "--edition=2021", "-O", str(ROOT / "tools/dnsmasq/dhcp_probe.rs"), "--extern", f"dnsmasq_rs={target / 'libdnsmasq_rs.rlib'}", "-L", f"dependency={target / 'deps'}", "-o", str(output / "rust-probe")],
    ]
    for index, command in enumerate(commands): run(command, output / f"build-{index}.json")
    inputs = cases(args.seed, args.rounds)
    input_text = "\n".join(inputs) + "\n"
    (output / "cases.txt").write_text(input_text)
    c_result = run([str(output / "c-oracle")], output / "c-command.json", input=input_text)
    rust_result = run([str(output / "rust-probe")], output / "rust-command.json", input=input_text)
    (output / "c.stdout").write_text(c_result.stdout)
    (output / "c.stderr").write_text(c_result.stderr)
    (output / "rust.stdout").write_text(rust_result.stdout)
    (output / "rust.stderr").write_text(rust_result.stderr)
    expected = c_result.stdout.splitlines()
    actual = rust_result.stdout.splitlines()
    if len(expected) != len(inputs) or len(actual) != len(inputs):
        raise SystemExit(f"counter calibration failed: {len(inputs)} cases, C={len(expected)}, Rust={len(actual)}")
    # These independent known answers calibrate success/failure paths, including
    # malformed TLVs and choosing a CLID over a newer matching hardware address.
    assert expected[:6] == ["0:03", "3:03", "0:03", "-", "0:", "-"]
    assert expected[12:15] == ["1", "2", "1"]
    differences = [{"index": i, "case": inputs[i], "c": left, "rust": right} for i, (left, right) in enumerate(zip(expected, actual)) if left != right]
    by_operation = {op: sum(line.startswith(op + " ") for line in inputs) for op in "OWDEIPXFSVH"}
    report = {"seed": args.seed, "rounds": args.rounds, "cases": len(inputs), "successful": len(inputs) - len(differences), "mismatches": len(differences), "by_operation": by_operation, "source_sha256": EXPECTED, "calibration": "passed", "c_sanitizers": "address,undefined", "differences": differences, "scope": "DHCP primitive differential; no service/transport/BOOTP/PXE integration claim"}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in ("differences", "source_sha256")}, indent=2))
    if differences: raise SystemExit(1)


if __name__ == "__main__":
    main()
