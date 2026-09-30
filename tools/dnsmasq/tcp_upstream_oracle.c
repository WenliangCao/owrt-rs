/* Include the unchanged reference TU so its static tcp_talk is callable.
 * The build omits the original forward.o; every other C object is reused. */
#define HAVE_UBUS 1
#define HAVE_POLL_H 1
#define NO_DHCP6 1
#define NO_AUTH 1
#define NO_IPSET 1
#define NO_ID 1
#include "forward.c"
#include <assert.h>

static int sockets(void)
{
  int count = 0;
  for (struct server *server = daemon->servers; server; server = server->next)
    if (server->tcpfd != -1) count++;
  return count;
}

int main(int argc, char **argv)
{
  rand_init();
  signal(SIGPIPE, SIG_IGN);
  read_opts(argc, argv, "tcp-upstream-oracle");
  daemon->pipe_to_parent = -1;
  daemon->packet_buff_sz = 65536 + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  cache_init();
  blockdata_init();
  check_servers(0);
  for (struct server *server = daemon->servers; server; server = server->next)
    server->tcpfd = -1;
  struct iovec received = {0};
  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, stdin) >= 0)
    {
      size_t length = strcspn(line, "\r\n") / 2;
      assert(length >= sizeof(struct dns_header) && length <= 65535);
      for (size_t i = 0; i < length; i++)
        {
          unsigned value;
          assert(sscanf(line + 2*i, "%2x", &value) == 1);
          ((unsigned char *)daemon->packet)[i] = value;
        }
      struct dns_header *header = (struct dns_header *)daemon->packet;
      unsigned gotname = extract_request(header, length, daemon->namebuff, NULL, NULL);
      int first = 0, last = 0;
      ssize_t count = 0;
      if (gotname && lookup_domain(daemon->namebuff, gotname, &first, &last))
        {
          struct server *server = NULL, *master = daemon->serverarray[first];
          int start = option_bool(OPT_ORDER) || master->last_server == -1 ? first : master->last_server;
          count = tcp_talk(first, last, start, header, length, &received, 0, 0, &server);
        }
      printf("%d ", sockets());
      if (count <= 0) puts("NONE");
      else
        {
          for (ssize_t i = 0; i < count; i++) printf("%02x", ((unsigned char *)received.iov_base)[i]);
          putchar('\n');
        }
      fflush(stdout);
    }
  for (struct server *server = daemon->servers; server; server = server->next)
    if (server->tcpfd != -1)
      {
        shutdown(server->tcpfd, SHUT_RDWR);
        close(server->tcpfd);
        server->tcpfd = -1;
      }
  printf("CLOSED %d\n", sockets());
  free(line);
  free(received.iov_base);
  return 0;
}
