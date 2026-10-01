"""Exact C static inventory and cache_find_by_name transition oracle."""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import subprocess

import local_answer_diff

CACHE_HASH = "51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c"

PREFIX = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define F_IMMORTAL (1u<<0)
#define F_REVERSE (1u<<2)
#define F_FORWARD (1u<<3)
#define F_DHCP (1u<<4)
#define F_HOSTS (1u<<6)
#define F_IPV4 (1u<<7)
#define F_IPV6 (1u<<8)
#define F_CONFIG (1u<<13)
#define F_NO_RR (1u<<25)
#define option_bool(unused) no_round
struct crec { struct crec *next, *hash_next; unsigned flags; };
static struct crec *bucket, *cache_head;
static unsigned no_round;
static struct crec **hash_bucket(char *name) { (void)name; return &bucket; }
static char *cache_get_name(struct crec *entry) { (void)entry; return "model"; }
static int hostname_isequal(char *a, char *b) { return strcmp(a, b) == 0; }
static int is_expired(time_t now, struct crec *entry) { (void)now; (void)entry; return 0; }
static int is_outdated_cname_pointer(struct crec *entry) { (void)entry; return 0; }
static void cache_unlink(struct crec *entry) { (void)entry; abort(); }
static void cache_link(struct crec *entry) { (void)entry; abort(); }
static void cache_free(struct crec *entry) { (void)entry; abort(); }
'''

MAIN = r'''
int main(void) {
  struct crec entries[64] = {0}; unsigned n, prot, saved[64]; char command;
  setbuf(stdout, NULL);
  if (scanf("%u %u %u", &n, &no_round, &prot) != 3 || n == 0 || n > 64) return 2;
  for (unsigned i = 0; i < n; i++) {
    if (scanf("%u", &entries[i].flags) != 1) return 3;
    entries[i].hash_next = i + 1 < n ? &entries[i + 1] : NULL;
  }
  bucket = entries;
  while (scanf(" %c", &command) == 1) {
    if (command != 'Q' && command != 'T') return 4;
    unsigned index = 0;
    for (struct crec *p = bucket; p; p = p->hash_next) saved[index++] = (unsigned)(p - entries);
    struct crec *p = NULL;
    while ((p = cache_find_by_name(p, "model", 0, prot))) printf("%u ", (unsigned)(p - entries));
    puts("");
    /* T models a new TCP child's one query; parent hash links are unchanged. */
    if (command == 'T') {
      bucket = &entries[saved[0]];
      for (unsigned i = 0; i < n; i++)
        entries[saved[i]].hash_next = i + 1 < n ? &entries[saved[i + 1]] : NULL;
    }
  }
  return 0;
}
'''


def build(reference, out):
    out.mkdir()
    object_dir = reference / "dnsmasq"
    source = object_dir / "cache.c"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == CACHE_HASH
    text = source.read_text()
    body = text[text.index("struct crec *cache_find_by_name("):text.index("struct crec *cache_find_by_addr(")]
    c = out / "rotation.c"
    c.write_text(PREFIX + body + MAIN)
    rotation = out / "rotation"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(rotation)], check=True)
    old = local_answer_diff.DRIVER
    local_answer_diff.DRIVER = Path(__file__).with_name("hosts_generation_inventory.c")
    try:
        inventory = local_answer_diff.build_oracle(reference, out)
    finally:
        local_answer_diff.DRIVER = old
    return inventory, rotation


def inventory(binary, config, out):
    run = subprocess.run([str(binary), "-C", str(config)], text=True, capture_output=True, check=True)
    out.write_text(run.stdout)
    records = {}
    for line in run.stdout.splitlines():
        name, address, ttl, flags = line.split()
        key = (bytes.fromhex(name).decode().lower(), str(ipaddress.ip_address(bytes.fromhex(address))))
        assert key not in records, "C inventory duplicate"
        records[key] = {"ttl": int(ttl), "flags": int(flags)}
    assert records, "empty C inventory"
    return records


class Rotation:
    def __init__(self, binary, flags, no_round, ipv6):
        self.process = subprocess.Popen([str(binary)], text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.process.stdin.write(f"{len(flags)} {int(no_round)} {256 if ipv6 else 128}\n")
        self.process.stdin.write(" ".join(str(flag) for flag in flags) + "\n")
        self.process.stdin.flush()

    def next(self, tcp):
        self.process.stdin.write("T\n" if tcp else "Q\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, "C rotation oracle exited"
        return [int(value) for value in line.split()]

    def close(self):
        self.process.stdin.close()
        assert self.process.wait(3) == 0, "C rotation oracle failed"
