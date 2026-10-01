/* Include unchanged exact cache.c to observe insert_error and real metrics.
 * All other functions link to the already audited full reference objects.
 * No listener or replacement cache algorithm is used by this fixture.
 */
#include "cache.c"
#include <assert.h>

static unsigned flags(unsigned type)
{
    return type == 1 ? F_IPV4 : type == 28 ? F_IPV6 : type == 5 ? F_CNAME :
           type == 65536 ? F_NXDOMAIN : F_RR;
}

int main(int argc, char **argv)
{
    rand_init();
    read_opts(argc, argv, "cache-metrics-oracle");
    daemon->pipe_to_parent = -1;
    cache_init();
    blockdata_init();
    cache_reload();
    struct crec *ids[2048] = {0};
    unsigned count = 0;
    char *line = NULL;
    size_t capacity = 0;
    while (getline(&line, &capacity, stdin) >= 0) {
        char op = line[0], name[504];
        unsigned type, ttl, value, negative;
        long long now;
        if (op == 'B') { cache_start_insert(); printf("B"); }
        else if (op == 'C') { cache_end_insert(); printf("C %d", !insert_error); }
        else if (op == 'S') { cache_reload(); printf("S"); }
        else if (op == 'T') {
            /* Explicit equal initial state for the u32-wrap test only. */
            unsigned inserted, freed;
            assert(sscanf(line, "T %u %u", &inserted, &freed) == 2);
            daemon->metrics[METRIC_DNS_CACHE_INSERTED] = inserted;
            daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED] = freed;
            printf("T");
        } else if (op == 'I') {
            assert(sscanf(line, "I %503s %u %u %u %u %lld", name, &type, &ttl, &value, &negative, &now) == 6);
            union all_addr address = {0};
            if (type == 1 || type == 28) address.addr4.s_addr = value;
            else if (type != 5) { address.rrdata.rrtype = type; address.rrdata.data[0] = value; }
            struct crec *entry = cache_insert(name, type == 5 ? NULL : &address, C_IN, now, ttl,
                                             F_FORWARD | flags(type) | (negative ? F_NEG : 0));
            if (entry && type == 5) { entry->addr.cname.target.cache = NULL; entry->addr.cname.is_name_ptr = 0; }
            assert(count < 2048); ids[count++] = entry;
            printf("I %d", entry != NULL);
        } else if (op == 'L') {
            unsigned a, b;
            assert(sscanf(line, "L %u %u", &a, &b) == 2 && a < count && b < count);
            int ok = ids[a] && ids[b] && (ids[a]->flags & F_CNAME);
            if (ok) { next_uid(ids[b]); ids[a]->addr.cname.target.cache = ids[b]; ids[a]->addr.cname.uid = ids[b]->uid; }
            printf("L %d", ok);
        } else if (op == 'Q') {
            assert(sscanf(line, "Q %503s %u %lld", name, &type, &now) == 3);
            struct crec *entry = NULL;
            printf("Q");
            while ((entry = cache_find_by_name(entry, name, now, flags(type) | F_NO_RR))) {
                unsigned value = type == 5 ? 0 : type == 1 || type == 28 ? entry->addr.addr4.s_addr : (unsigned char)entry->addr.rrdata.data[0];
                printf(" %u:%lld", value, (long long)entry->ttd);
            }
        } else abort();
        printf(" | %u %u\n", daemon->metrics[METRIC_DNS_CACHE_INSERTED], daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
    }
    free(line);
    return 0;
}
