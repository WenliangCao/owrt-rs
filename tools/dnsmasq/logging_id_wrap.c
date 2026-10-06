/* Source control for cache.c:2496-2509, not a daemon counter load test.
 * Keep the C signed negation and %u vararg at its actual log_query site. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  if (argc != 2) return 2;
  volatile int seed = (int)(uint32_t)strtoull(argv[1], NULL, 0);
  int display_id = seed;
  char *proto = (display_id < 0) ? "TCP " : "UDP ";
  if (display_id < 0)
    display_id = -display_id;
  printf("%s%u config wrap.logging is value\n", proto, display_id);
  return 0;
}
