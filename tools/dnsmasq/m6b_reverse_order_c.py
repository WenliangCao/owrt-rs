#!/usr/bin/env python3
"""Prepare a private read-only C reverse-order diagnostic; no build/run entry.

prepare_c(reference_source, original_driver, destination) accepts cache.c (or
its directory), the original 21-case driver, and a fresh private directory.
It returns generated paths/hashes. The caller owns compilation and collection.
Original stdout, corpus, hash algorithm and comparator are unchanged.
"""
import difflib
import hashlib
from pathlib import Path

CACHE_SHA = '51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c'
DRIVER_SHA = '3360c37032f61933ac7b6516ec60374eea2973aeb2b37582b0e67e64651601e0'

HEADER = r'''
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static const char *m6b_owner = "INIT";
static unsigned long long m6b_command, m6b_seq;
static unsigned char m6b_op = 'I';
static int m6b_snapshot_probe;
static void m6b_hash_diag(const char *, unsigned int);
static void m6b_snapshot(const char *);
static void m6b_context(const char *owner, unsigned long long command, unsigned char op)
{ m6b_owner = owner; m6b_command = command; m6b_op = op; }
struct m6b_line { char data[4096]; size_t used; };
static void m6b_fail(void)
{ const char msg[]="M6B_REVERSE_ORDER_SIDECAR_FAILED\n"; ssize_t written=write(2,msg,sizeof(msg)-1); (void)written; _exit(118); }
static void m6b_add(struct m6b_line *line, const char *format, ...)
{
  va_list args; va_start(args,format);
  int n=vsnprintf(line->data+line->used,sizeof(line->data)-line->used,format,args);
  va_end(args);
  if(n<0 || (size_t)n>=sizeof(line->data)-line->used) m6b_fail();
  line->used+=(size_t)n;
}
static void m6b_string(struct m6b_line *line, const char *text)
{
  m6b_add(line,"\"");
  for(const unsigned char *p=(const unsigned char *)text; *p; p++)
    if(*p=='"' || *p=='\\') m6b_add(line,"\\%c",*p);
    else if(*p<32 || *p>=127) m6b_add(line,"\\u%04x",*p);
    else m6b_add(line,"%c",*p);
  m6b_add(line,"\"");
}
static void m6b_hex(struct m6b_line *line, const void *bytes, size_t length)
{
  const unsigned char *p=bytes;
  m6b_add(line,"\"");
  for(size_t i=0;i<length;i++) m6b_add(line,"%02x",p[i]);
  m6b_add(line,"\"");
}
static int m6b_enabled(void)
{ const char *path=getenv("DNSMASQ_REVERSE_ORDER_SIDECAR"); return path && *path; }
static void m6b_begin(struct m6b_line *line, const char *event)
{
  line->used=0;
  m6b_add(line,"{\"event\":"); m6b_string(line,event);
  m6b_add(line,",\"phase\":\"c\",\"pid\":%ld,\"owner\":",(long)getpid());
  m6b_string(line,m6b_owner);
  m6b_add(line,",\"command\":%llu,\"op\":\"%c\"",m6b_command,m6b_op);
}
static void m6b_write(struct m6b_line *line)
{
  static int fd=-1;
  if(fd<0) { fd=open(getenv("DNSMASQ_REVERSE_ORDER_SIDECAR"),O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600); if(fd<0)m6b_fail(); }
  m6b_add(line,",\"seq\":%llu}\n",m6b_seq++);
  /* Exactly one successful short write per JSONL record. Parent/child share
     O_APPEND after fork; never emit a partial record in multiple fragments. */
  ssize_t n;
  do { n=write(fd,line->data,line->used); } while(n<0 && errno==EINTR);
  if(n<0 || (size_t)n!=line->used) m6b_fail();
}
'''

IMPLEMENTATION = r'''
static void m6b_hash_diag(const char *name, unsigned int bucket)
{
  if(!m6b_enabled()) return;
  struct m6b_line line; m6b_begin(&line,"bucket");
  m6b_add(&line,",\"diagnostic\":%s,\"name_hex\":",m6b_snapshot_probe?"true":"false");
  m6b_hex(&line,name,strlen(name));
  m6b_add(&line,",\"bucket\":%u,\"hash_size\":%d,\"mix\":",bucket,hash_size);
  /* Read the real process-local mixing bytes, including address bytes. */
  m6b_hex(&line,(const unsigned char *)typestr,64); m6b_write(&line);
}
static int m6b_dynamic(struct crec *entry)
{
  return (entry->flags&(F_FORWARD|F_REVERSE)) &&
    !(entry->flags&(F_DHCP|F_HOSTS|F_CONFIG|F_CNAME|F_RR));
}
static void m6b_token(struct m6b_line *line, struct crec *entry)
{
  char token[1152], addr[33]; unsigned bits=(entry->flags&F_IPV4)?4:6;
  size_t length=bits==4?4:16; const unsigned char *bytes=(const unsigned char *)&entry->addr;
  for(size_t i=0;i<length;i++) snprintf(addr+2*i,3,"%02x",bytes[i]);
  int n=snprintf(token,sizeof(token),"%c%u:%s:%lld:%s",entry->flags&F_REVERSE?'R':'F',bits,
                 cache_get_name(entry),(long long)entry->ttd,addr);
  if(n<0 || (size_t)n>=sizeof(token)) m6b_fail();
  m6b_string(line,token);
}
static void m6b_snapshot(const char *when)
{
  if(!m6b_enabled()) return;
  struct m6b_line line; m6b_begin(&line,"snapshot");
  m6b_add(&line,",\"when\":"); m6b_string(&line,when);
  m6b_add(&line,",\"hash_size\":%d,\"counter\":[%u,%u],\"lru\":[",hash_size,
          daemon->metrics[METRIC_DNS_CACHE_INSERTED],daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
  int separator=0;
  for(struct crec *p=cache_head;p;p=p->next)
    if(m6b_dynamic(p)) { if(separator++)m6b_add(&line,","); m6b_token(&line,p); }
  m6b_add(&line,"],\"chains\":["); separator=0;
  for(int bucket=0;bucket<hash_size;bucket++)
    {
      int count=0;
      for(struct crec *p=hash_table[bucket];p;p=p->hash_next)
        if(m6b_dynamic(p) && (p->flags&F_REVERSE)) count++;
      if(!count) continue;
      if(separator++) { m6b_add(&line,","); }
      m6b_add(&line,"[%d,[",bucket);
      int comma=0;
      for(struct crec *p=hash_table[bucket];p;p=p->hash_next)
        if(m6b_dynamic(p) && (p->flags&F_REVERSE)) { if(comma++)m6b_add(&line,","); m6b_token(&line,p); }
      m6b_add(&line,"]]");
    }
  m6b_add(&line,"],\"name_buckets\":["); separator=0; m6b_snapshot_probe=1;
  for(int bucket=0;bucket<hash_size;bucket++)
    for(struct crec *p=hash_table[bucket];p;p=p->hash_next)
      if(m6b_dynamic(p) && (p->flags&F_REVERSE))
        {
          const char *name=cache_get_name(p);
          unsigned actual=(unsigned)(hash_bucket((char *)name)-hash_table);
          if(separator++) { m6b_add(&line,","); }
          m6b_add(&line,"["); m6b_hex(&line,name,strlen(name));
          m6b_add(&line,",%u]",actual);
        }
  m6b_snapshot_probe=0;
  m6b_add(&line,"],\"non_T\":["); separator=0;
  for(int bucket=0;bucket<hash_size;bucket++)
    for(struct crec *p=hash_table[bucket];p;p=p->hash_next)
      if(!m6b_dynamic(p))
        {
          if(separator++)m6b_add(&line,",");
          m6b_add(&line,"{\"bucket\":%d,\"flags\":%u,\"uid\":%u,\"ptr\":\"%p\",\"hash_next\":\"%p\",\"name_hex\":",
                  bucket,p->flags,p->uid,(void *)p,(void *)p->hash_next);
          const char *name=cache_get_name(p); m6b_hex(&line,name,strlen(name)); m6b_add(&line,"}");
        }
  m6b_add(&line,"]"); m6b_write(&line);
}
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('exact C diagnostic anchor changed: ' + old[:80])
    return text.replace(old, new)


def prepare_c(reference_source: Path, original_driver: Path, destination: Path) -> dict:
    cache = Path(reference_source)
    if cache.is_dir():
        cache = cache / 'cache.c'
    driver, out = Path(original_driver), Path(destination).resolve()
    if sha(cache) != CACHE_SHA or sha(driver) != DRIVER_SHA:
        raise ValueError('hash-pinned exact cache.c and original reverse driver required')
    if 'private' not in out.parts or out.exists():
        raise ValueError('fresh private diagnostic source directory required')
    original_cache, original_driver_text = cache.read_text(), driver.read_text()
    changed_cache = replace_once(original_cache, '#include "dnsmasq.h"\n',
        '#include "dnsmasq.h"\n#include "m6b_reverse_order_header.h"\n')
    changed_cache = replace_once(changed_cache, 'static struct crec **hash_bucket(char *name)\n{\n',
        'static struct crec **hash_bucket(char *name)\n{\n  const char *m6b_original_name = name;\n')
    changed_cache = replace_once(changed_cache,
        '  return hash_table + ((val ^ (val >> 16)) & (hash_size - 1));',
        '  struct crec **m6b_result = hash_table + ((val ^ (val >> 16)) & (hash_size - 1));\n'
        '  m6b_hash_diag(m6b_original_name, (unsigned int)(m6b_result - hash_table));\n  return m6b_result;')
    changed_driver = replace_once(original_driver_text, '#include "cache.c"',
        '#include "m6b_reverse_order_cache.inc"\n' + IMPLEMENTATION)
    changed_driver = replace_once(changed_driver, '  char *line = NULL; size_t capacity = 0;',
        '  char *line = NULL; size_t capacity = 0; unsigned long long m6b_index = 0;')
    changed_driver = replace_once(changed_driver, '      char name[504], hex[33]; unsigned bits, ttl; long long now;',
        '      m6b_context(stage, m6b_index++, (unsigned char)line[0]);\n'
        '      char name[504], hex[33]; unsigned bits, ttl; long long now;')
    changed_driver = replace_once(changed_driver, '          printf("A");',
        '          m6b_snapshot("before");\n          printf("A");')
    changed_driver = replace_once(changed_driver,
        '                   !!(entry->flags & (F_DHCP | F_HOSTS | F_CONFIG)));\n        }\n      else if (line[0] == \'Q\')',
        '                   !!(entry->flags & (F_DHCP | F_HOSTS | F_CONFIG)));\n'
        '          m6b_snapshot("after");\n        }\n      else if (line[0] == \'Q\')')
    changed_driver = replace_once(changed_driver, '          printf("T");',
        '          m6b_snapshot("before");\n          printf("T");')
    changed_driver = replace_once(changed_driver, '                data(entry);\n              }\n        }\n      else abort();',
        '                data(entry);\n              }\n          m6b_snapshot("after");\n        }\n      else abort();')
    changed_driver = replace_once(changed_driver, '  while (cache_recv_insert(now, channel[0]))',
        '  unsigned long long m6b_import_index = 0;\n'
        '  while ((m6b_context("R", m6b_import_index++, \'R\'), cache_recv_insert(now, channel[0])))')
    out.mkdir(parents=True)
    files = {'m6b_reverse_order_driver.c': changed_driver, 'm6b_reverse_order_cache.inc': changed_cache,
             'm6b_reverse_order_header.h': HEADER}
    for filename, text in files.items():
        (out / filename).write_text(text)
    patch = ''.join(difflib.unified_diff(original_cache.splitlines(True), changed_cache.splitlines(True),
                                        fromfile='cache.c', tofile='m6b_reverse_order_cache.inc'))
    patch += ''.join(difflib.unified_diff(original_driver_text.splitlines(True), changed_driver.splitlines(True),
                                         fromfile='cache_reverse_transfer_driver.c', tofile='m6b_reverse_order_driver.c'))
    (out / 'c-diagnostic.patch').write_text(patch)
    return {'source_cache_sha256': CACHE_SHA, 'source_driver_sha256': DRIVER_SHA,
            'driver': str(out / 'm6b_reverse_order_driver.c'), 'include': str(out / 'm6b_reverse_order_cache.inc'),
            'header': str(out / 'm6b_reverse_order_header.h'), 'patch': str(out / 'c-diagnostic.patch'),
            'files': {filename: sha(out / filename) for filename in [*files, 'c-diagnostic.patch']},
            'tool_sha256': sha(Path(__file__)), 'diagnostic_only': True, 'image_daemon_qualification': False,
            'schema': 'bucket/snapshot JSONL; owner+command0based+op+pid+seq; real hash/mix; dynamic reverse chains'}
