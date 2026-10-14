/* Read-only Linux audit helper; no product code. Build with the OpenWrt SDK:
 * cc -O2 -std=c11 -Wall -Wextra -Werror -static predeploy_resource_probe.c -o probe
 *
 * monitor PID SECONDS emits cumulative /proc counters once per second including
 * both endpoints. It never signals a process, limits duration to 240 seconds,
 * and stops on root PID disappearance/reuse. The caller owns process cleanup.
 * Child sampling is not atomic; retain rows to detect CPU/reaping races. PSS
 * is null if smaps_rollup is unavailable; RSS sums double-count shared pages.
 */
#define _GNU_SOURCE
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
#define MAX_PROCESSES 256
struct process {
  long pid, ppid;
  char state;
  uint64_t start, user, system, child_user, child_system;
  uint64_t virtual_pages, resident_pages, shared_pages;
  uint64_t rss, hwm, anon, file, shmem, threads, pss, private_clean, private_dirty;
  unsigned fd_count;
  bool have_pss;
};
static volatile sig_atomic_t stopped;
static void stop_handler(int number) { (void)number; stopped = 1; }
static uint64_t now_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) { perror("clock_gettime"); exit(2); }
  return (uint64_t)value.tv_sec * NS + (uint64_t)value.tv_nsec;
}
static FILE *proc_file(long pid, const char *name) {
  char path[256];
  if (snprintf(path, sizeof path, "/proc/%ld/%s", pid, name) >= (int)sizeof path) {
    errno = ENAMETOOLONG; return NULL;
  }
  return fopen(path, "r");
}
static bool read_stat(long pid, struct process *p) {
  memset(p, 0, sizeof *p); p->pid = pid;
  FILE *f = proc_file(pid, "stat");
  char line[4096];
  if (!f) return false;
  bool ok = fgets(line, sizeof line, f) != NULL;
  fclose(f);
  if (!ok) return false;
  char *end = strrchr(line, ')'), *save = NULL;
  if (!end || end[1] != ' ') return false;
  unsigned field = 3;
  for (char *v = strtok_r(end + 2, " \n", &save); v;
       v = strtok_r(NULL, " \n", &save), field++) {
    if (field == 3) p->state = v[0];
    else if (field == 4) p->ppid = strtol(v, NULL, 10);
    else if (field == 14) p->user = strtoull(v, NULL, 10);
    else if (field == 15) p->system = strtoull(v, NULL, 10);
    else if (field == 16) p->child_user = strtoull(v, NULL, 10);
    else if (field == 17) p->child_system = strtoull(v, NULL, 10);
    else if (field == 22) p->start = strtoull(v, NULL, 10);
  }
  return field > 22;
}
static bool read_process(long pid, struct process *p) {
  if (!read_stat(pid, p)) return false;
  char line[4096];
  FILE *f = proc_file(pid, "statm");
  if (f) {
    if (fscanf(f, "%" SCNu64 " %" SCNu64 " %" SCNu64,
               &p->virtual_pages, &p->resident_pages, &p->shared_pages) != 3) {
      fclose(f); return false;
    }
    fclose(f);
  }
  f = proc_file(pid, "status");
  if (!f) return false;
  while (fgets(line, sizeof line, f)) {
    char key[64]; uint64_t value;
    if (sscanf(line, "%63[^:]: %" SCNu64, key, &value) != 2) continue;
    if (!strcmp(key, "VmRSS")) p->rss = value;
    else if (!strcmp(key, "VmHWM")) p->hwm = value;
    else if (!strcmp(key, "RssAnon")) p->anon = value;
    else if (!strcmp(key, "RssFile")) p->file = value;
    else if (!strcmp(key, "RssShmem")) p->shmem = value;
    else if (!strcmp(key, "Threads")) p->threads = value;
  }
  fclose(f);
  f = proc_file(pid, "smaps_rollup");
  if (f) {
    while (fgets(line, sizeof line, f)) {
      char key[64]; uint64_t value;
      if (sscanf(line, "%63[^:]: %" SCNu64, key, &value) != 2) continue;
      if (!strcmp(key, "Pss")) { p->pss = value; p->have_pss = true; }
      else if (!strcmp(key, "Private_Clean")) p->private_clean = value;
      else if (!strcmp(key, "Private_Dirty")) p->private_dirty = value;
    }
    fclose(f);
  }
  char path[64]; snprintf(path, sizeof path, "/proc/%ld/fd", pid);
  DIR *dir = opendir(path);
  if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir))) if (entry->d_name[0] != '.') p->fd_count++;
    closedir(dir);
  }
  return true;
}
static void emit_process(const struct process *p) {
  printf("{\"pid\":%ld,\"ppid\":%ld,\"state\":\"%c\",\"starttime_ticks\":%" PRIu64
         ",\"user_ticks\":%" PRIu64 ",\"system_ticks\":%" PRIu64
         ",\"waited_child_user_ticks\":%" PRIu64 ",\"waited_child_system_ticks\":%" PRIu64
         ",\"virtual_pages\":%" PRIu64 ",\"resident_pages\":%" PRIu64
         ",\"shared_pages\":%" PRIu64 ",\"rss_kib\":%" PRIu64
         ",\"hwm_kib\":%" PRIu64 ",\"rss_anon_kib\":%" PRIu64
         ",\"rss_file_kib\":%" PRIu64 ",\"rss_shmem_kib\":%" PRIu64 ",\"thread_count\":%" PRIu64
         ",\"fd_count\":%u,\"pss_kib\":",
         p->pid, p->ppid, p->state, p->start, p->user, p->system,
         p->child_user, p->child_system, p->virtual_pages, p->resident_pages,
         p->shared_pages, p->rss, p->hwm, p->anon, p->file, p->shmem, p->threads, p->fd_count);
  if (p->have_pss) printf("%" PRIu64, p->pss); else fputs("null", stdout);
  printf(",\"private_clean_kib\":%" PRIu64 ",\"private_dirty_kib\":%" PRIu64 "}",
         p->private_clean, p->private_dirty);
}
static void emit_host(void) {
  FILE *f = fopen("/proc/meminfo", "r"); char line[512];
  fputs(",\"meminfo_kib\":{", stdout); bool first = true;
  if (f) {
    while (fgets(line, sizeof line, f)) {
      char key[64]; uint64_t value;
      if (sscanf(line, "%63[^:]: %" SCNu64, key, &value) != 2) continue;
      if (strcmp(key, "MemTotal") && strcmp(key, "MemAvailable") && strcmp(key, "MemFree") &&
          strcmp(key, "Buffers") && strcmp(key, "Cached") && strcmp(key, "Slab") &&
          strcmp(key, "SReclaimable") && strcmp(key, "Shmem") && strcmp(key, "SwapTotal") &&
          strcmp(key, "SwapFree")) continue;
      printf("%s\"%s\":%" PRIu64, first ? "" : ",", key, value); first = false;
    }
    fclose(f);
  }
  fputs("},\"host_cpu_ticks\":[", stdout);
  f = fopen("/proc/stat", "r");
  if (f) {
    if (fgets(line, sizeof line, f) && !strncmp(line, "cpu ", 4)) {
      char *save = NULL; first = true;
      for (char *v = strtok_r(line + 4, " \n", &save); v;
           v = strtok_r(NULL, " \n", &save)) {
        printf("%s%" PRIu64, first ? "" : ",", (uint64_t)strtoull(v, NULL, 10)); first = false;
      }
    }
    fclose(f);
  }
  fputs("]", stdout);
}
static int sample(long pid, uint64_t expected_start) {
  struct process rows[MAX_PROCESSES]; long pending[MAX_PROCESSES];
  unsigned count = 0, queued = 1, at = 0, disappeared = 0;
  bool truncated = false, all_pss = true, proc_scan_used = false;
  uint64_t cpu = 0, rss = 0, pss = 0;
  pending[0] = pid;
  while (at < queued) {
    long next = pending[at++];
    struct process p;
    if (!read_process(next, &p)) {
      if (next == pid) return 1;
      disappeared++; continue;
    }
    if (next == pid && p.start != expected_start) return 1;
    rows[count++] = p;
    cpu += p.user + p.system + p.child_user + p.child_system;
    rss += p.rss; pss += p.pss; all_pss = all_pss && p.have_pss;
    char path[128]; snprintf(path, sizeof path, "task/%ld/children", next);
    FILE *f = proc_file(next, path);
    if (f) {
      long child;
      while (fscanf(f, "%ld", &child) == 1) {
        bool seen = false;
        for (unsigned i = 0; i < queued; i++) if (pending[i] == child) seen = true;
        if (seen) continue;
        if (queued < MAX_PROCESSES) pending[queued++] = child; else truncated = true;
      }
      fclose(f);
    } else {
      /* OpenWrt can omit /proc/PID/task/PID/children. PPID is always in stat;
       * scan it without reading unrelated address spaces or command lines. */
      proc_scan_used = true;
      DIR *directory = opendir("/proc");
      if (!directory) return 2;
      struct dirent *entry;
      while ((entry = readdir(directory))) {
        char *end; long candidate = strtol(entry->d_name, &end, 10);
        if (candidate <= 0 || *end) continue;
        struct process child;
        if (!read_stat(candidate, &child) || child.ppid != next) continue;
        bool seen = false;
        for (unsigned i = 0; i < queued; i++) if (pending[i] == candidate) seen = true;
        if (seen) continue;
        if (queued < MAX_PROCESSES) pending[queued++] = candidate; else truncated = true;
      }
      closedir(directory);
    }
  }
  printf("{\"monotonic_ns\":%" PRIu64 ",\"clock_ticks_per_second\":%ld,\"page_bytes\":%ld,\"processes\":[",
         now_ns(), sysconf(_SC_CLK_TCK), sysconf(_SC_PAGESIZE));
  for (unsigned i = 0; i < count; i++) { if (i) putchar(','); emit_process(&rows[i]); }
  printf("],\"tree_cpu_ticks\":%" PRIu64 ",\"tree_rss_kib\":%" PRIu64 ",\"tree_pss_kib\":", cpu, rss);
  if (all_pss) printf("%" PRIu64, pss); else fputs("null", stdout);
  printf(",\"children_disappeared\":%u,\"tree_truncated\":%s,\"proc_stat_ppid_fallback_used\":%s",
         disappeared, truncated ? "true" : "false", proc_scan_used ? "true" : "false");
  emit_host(); fputs("}\n", stdout);
  return fflush(stdout) ? 2 : 0;
}
static int monitor(long pid, unsigned seconds) {
  struct process initial;
  if (!read_process(pid, &initial)) { perror("read target process"); return 2; }
  signal(SIGTERM, stop_handler); signal(SIGINT, stop_handler);
  uint64_t start = now_ns();
  for (unsigned i = 0; i <= seconds && !stopped; i++) {
    uint64_t deadline = start + i * NS;
    struct timespec when = {(time_t)(deadline / NS), (long)(deadline % NS)};
    int error;
    while ((error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &when, NULL)) == EINTR && !stopped) {}
    if (stopped) break;
    if (error) { errno = error; perror("clock_nanosleep"); return 2; }
    int status = sample(pid, initial.start);
    if (status) { fprintf(stderr, "target disappeared/reused or sample output failed\n"); return status; }
  }
  return stopped ? 1 : 0;
}
static long integer(const char *text) {
  char *end; errno = 0; long value = strtol(text, &end, 10);
  return errno || !*text || *end || value <= 0 ? -1 : value;
}
int main(int argc, char **argv) {
  if (argc == 4 && !strcmp(argv[1], "monitor")) {
    long pid = integer(argv[2]), seconds = integer(argv[3]);
    if (pid > 0 && pid <= 2147483647L && seconds > 0 && seconds <= 240)
      return monitor(pid, (unsigned)seconds);
  }
  fputs("usage: probe monitor PID SECONDS(1..240)\n", stderr);
  return 2;
}
