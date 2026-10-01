/* Observe actual log_packet -> ubus_event_bcast arguments. The linked C
 * rfc2131.o is unchanged; bus delivery remains a separate integration gate. */
#include "dhcp_message_metrics_driver.c"

static void event_string(const char *value) {
  if (!value) { fputs("-", stdout); return; }
  if (!*value) { fputs("_", stdout); return; }
  for (const unsigned char *p = (const unsigned char *)value; *p; p++) printf("%02x", *p);
}

void __wrap_ubus_event_bcast(const char *type, const char *mac, const char *ip,
                           const char *name, const char *interface) {
  const char *values[] = { type, mac, ip, name, interface };
  fputs("EVENT", stdout);
  for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    putchar(' '); event_string(values[i]);
  }
  putchar('\n'); fflush(stdout);
}
