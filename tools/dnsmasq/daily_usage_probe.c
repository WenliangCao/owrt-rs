/* Read-only daily service observation; no packets, signals or smaps reads.
 * Build: cc -O2 -std=c11 -Wall -Wextra -Werror daily_usage_probe.c -o probe
 * Invoke: probe PID STARTTIME_TICKS SECONDS INTERVAL_SECONDS [LEASE_FILE]
 * One /proc process-map scan per sample. PID/starttime pinning is mandatory.
 * CPU counters are cumulative; live children and waited children are separate.
 * A proc scan is not atomic. RSS sums count shared mappings more than once.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NS UINT64_C(1000000000)
#define MAX_MAP 8192
#define MAX_TREE 256
struct process {
  long pid, ppid;
  uint64_t start, user, system, child_user, child_system;
  uint64_t rss, anon, threads;
  unsigned fds;
};
static struct process map[MAX_MAP];
static unsigned map_count;
static volatile sig_atomic_t stopped;
static void on_stop(int sig) { (void)sig; stopped = 1; }
static uint64_t now_ns(clockid_t clock_id) {
  struct timespec t;
  if (clock_gettime(clock_id, &t)) { perror("clock_gettime"); exit(2); }
  return (uint64_t)t.tv_sec * NS + (uint64_t)t.tv_nsec;
}
static FILE *open_proc(long pid, const char *name) {
  char path[128];
  int n = snprintf(path, sizeof path, "/proc/%ld/%s", pid, name);
  return n > 0 && n < (int)sizeof path ? fopen(path, "r") : NULL;
}
static bool read_stat(long pid, struct process *p) {
  FILE *f = open_proc(pid, "stat");
  char line[4096];
  if (!f) return false;
  bool ok = fgets(line, sizeof line, f) != NULL;
  fclose(f);
  if (!ok) return false;
  char *end = strrchr(line, ')'), *save = NULL;
  if (!end || end[1] != ' ') return false;
  memset(p, 0, sizeof *p); p->pid = pid;
  unsigned field = 3;
  for (char *v = strtok_r(end + 2, " \n", &save); v;
       v = strtok_r(NULL, " \n", &save), field++) {
    if (field == 4) p->ppid = strtol(v, NULL, 10);
    else if (field == 14) p->user = strtoull(v, NULL, 10);
    else if (field == 15) p->system = strtoull(v, NULL, 10);
    else if (field == 16) p->child_user = strtoull(v, NULL, 10);
    else if (field == 17) p->child_system = strtoull(v, NULL, 10);
    else if (field == 22) p->start = strtoull(v, NULL, 10);
  }
  return field > 22;
}
static bool read_process(long pid, uint64_t expected, struct process *p) {
  if (!read_stat(pid, p) || p->start != expected) return false;
  FILE *f = open_proc(pid, "status");
  char line[512]; unsigned fields = 0;
  if (!f) return false;
  while (fgets(line, sizeof line, f)) {
    char key[64]; uint64_t value;
    if (sscanf(line, "%63[^:]: %" SCNu64, key, &value) != 2) continue;
    if (!strcmp(key, "VmRSS")) { p->rss = value; fields |= 1; }
    else if (!strcmp(key, "RssAnon")) { p->anon = value; fields |= 2; }
    else if (!strcmp(key, "Threads")) { p->threads = value; fields |= 4; }
  }
  fclose(f);
  char path[128]; snprintf(path, sizeof path, "/proc/%ld/fd", pid);
  DIR *d = opendir(path);
  if (!d) return false;
  struct dirent *e;
  while ((e = readdir(d))) if (e->d_name[0] != '.') p->fds++;
  closedir(d);
  struct process after;
  return fields == 7 && read_stat(pid, &after) && after.start == expected;
}
static void emit_process(const struct process *p) {
  printf("{\"pid\":%ld,\"ppid\":%ld,\"starttime_ticks\":%" PRIu64
         ",\"user_ticks\":%" PRIu64 ",\"system_ticks\":%" PRIu64
         ",\"waited_child_user_ticks\":%" PRIu64 ",\"waited_child_system_ticks\":%" PRIu64
         ",\"rss_kib\":%" PRIu64 ",\"rss_anon_kib\":%" PRIu64
         ",\"thread_count\":%" PRIu64 ",\"fd_count\":%u}",
         p->pid, p->ppid, p->start, p->user, p->system,
         p->child_user, p->child_system, p->rss, p->anon, p->threads, p->fds);
}
static long lease_count(const char *path) {
  if (!path) return -1;
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  long count = 0; char line[4096];
  while (fgets(line, sizeof line, f)) {
    /* dnsmasq's lease file may include a DUID header; do not count it. */
    if (line[0] >= '0' && line[0] <= '9') count++;
  }
  fclose(f); return count;
}
static int sample(long pid, uint64_t expected, unsigned index, const char *leases) {
  uint64_t began = now_ns(CLOCK_MONOTONIC);
  struct process self_before, self_after;
  if (!read_stat(getpid(), &self_before)) return 2;
  DIR *d = opendir("/proc");
  if (!d) return 2;
  map_count = 0; struct dirent *e;
  while ((e = readdir(d))) {
    char *end; long candidate = strtol(e->d_name, &end, 10);
    if (candidate <= 0 || *end) continue;
    struct process p;
    if (!read_stat(candidate, &p)) continue;
    if (map_count == MAX_MAP) { closedir(d); return 2; }
    map[map_count++] = p;
  }
  closedir(d);
  long pending[MAX_TREE]; uint64_t starts[MAX_TREE];
  struct process rows[MAX_TREE];
  unsigned queued = 1, at = 0, count = 0, disappeared = 0;
  pending[0] = pid; starts[0] = expected;
  while (at < queued) {
    long next = pending[at]; uint64_t start = starts[at++];
    struct process p;
    if (!read_process(next, start, &p)) {
      if (next == pid) return 1;
      disappeared++; continue;
    }
    rows[count++] = p;
    for (unsigned i = 0; i < map_count; i++) {
      if (map[i].ppid != next) continue;
      bool seen = false;
      for (unsigned j = 0; j < queued; j++) if (pending[j] == map[i].pid) seen = true;
      if (seen) continue;
      if (queued == MAX_TREE) return 2;
      pending[queued] = map[i].pid; starts[queued++] = map[i].start;
    }
  }
  long leases_now = lease_count(leases);
  if (!read_stat(getpid(), &self_after)) return 2;
  printf("{\"schema\":1,\"index\":%u,\"monotonic_ns\":%" PRIu64
         ",\"realtime_ns\":%" PRIu64 ",\"clock_ticks_per_second\":%ld,\"processes\":[",
         index, began, now_ns(CLOCK_REALTIME), sysconf(_SC_CLK_TCK));
  for (unsigned i = 0; i < count; i++) { if (i) putchar(','); emit_process(&rows[i]); }
  printf("],\"children_disappeared\":%u,\"proc_parent_map_scans\":1,\"proc_parent_map_entries\":%u,\"lease_count\":",
         disappeared, map_count);
  if (leases_now >= 0) printf("%ld", leases_now); else fputs("null", stdout);
  fputs(",\"observer\":", stdout); emit_process(&self_after);
  printf(",\"observer_sample_ticks\":%" PRIu64 ",\"sample_duration_ns\":%" PRIu64 "}\n",
         self_after.user + self_after.system - self_before.user - self_before.system,
         now_ns(CLOCK_MONOTONIC) - began);
  return fflush(stdout) ? 2 : 0;
}
static long positive(const char *text) {
  char *end; errno = 0; long value = strtol(text, &end, 10);
  return errno || !*text || *end || value <= 0 ? -1 : value;
}
int main(int argc, char **argv) {
  if (argc != 5 && argc != 6) goto usage;
  long pid = positive(argv[1]), start = positive(argv[2]);
  long seconds = positive(argv[3]), interval = positive(argv[4]);
  if (pid <= 0 || start <= 0 || seconds <= 0 || seconds > 3600 ||
      interval <= 0 || interval > 60 || seconds % interval) goto usage;
  signal(SIGTERM, on_stop); signal(SIGINT, on_stop);
  uint64_t began = now_ns(CLOCK_MONOTONIC);
  for (unsigned i = 0; i <= (unsigned)(seconds / interval); i++) {
    uint64_t deadline = began + i * (uint64_t)interval * NS;
    while (!stopped) {
      uint64_t now = now_ns(CLOCK_MONOTONIC);
      if (now >= deadline) break;
      uint64_t remaining = deadline - now;
      struct timespec wait = {(time_t)(remaining / NS), (long)(remaining % NS)};
      if (nanosleep(&wait, NULL) && errno != EINTR) { perror("nanosleep"); return 2; }
    }
    if (stopped) return 1;
    int status = sample(pid, (uint64_t)start, i, argc == 6 ? argv[5] : NULL);
    if (status) { fputs("sample failed or target disappeared/reused\n", stderr); return status; }
  }
  return 0;
usage:
  fputs("usage: daily_usage_probe PID STARTTIME_TICKS SECONDS(1..3600) INTERVAL(1..60) [LEASE_FILE]\n", stderr);
  return 2;
}
