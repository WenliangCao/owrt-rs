/* Read-only control for libiwinfo f5dd57a8's caller-owned freqlist buffer.
 * Compile against the exact image's iwinfo.h with its musl SDK, dynamically:
 * $CC -Os -Wall -Wextra -Werror -I$EXACT_HEADERS r92_iwinfo_flags.c -ldl -o PROBE
 * Only backend selection and GET_WIPHY are used; no scan or radio mutation.
 * Keep the extracted header, binary and observations outside Git. */
#include <dlfcn.h>
/* iwinfo.h also includes internal utility declarations. This control uses
 * only its public structs, so do not require unrelated UCI/ubus headers. */
#define __IWINFO_UTILS_H_
#include <iwinfo.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end;
    unsigned long preset = strtoul(argv[2], &end, 10);
    unsigned int known = (1U << IWINFO_FREQ_FLAG_COUNT) - 1;
    if (*end || (preset != 0 && preset != known)) return 2;
    void *library = dlopen("libiwinfo.so.20230701", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    const struct iwinfo_ops *(*backend)(const char *) = dlsym(library, "iwinfo_backend");
    if (!backend) return 1;
    const struct iwinfo_ops *ops = backend(argv[1]);
    if (!ops || !ops->freqlist) return 1;
    char *buffer = calloc(1, IWINFO_BUFSIZE);
    if (!buffer) return 1;
    for (size_t i = 0; i + sizeof(struct iwinfo_freqlist_entry) <= IWINFO_BUFSIZE;
         i += sizeof(struct iwinfo_freqlist_entry))
        ((struct iwinfo_freqlist_entry *)(buffer + i))->flags = (unsigned int)preset;
    int length = 0;
    if (ops->freqlist(argv[1], buffer, &length) || length <= 0 ||
        length > IWINFO_BUFSIZE || length % sizeof(struct iwinfo_freqlist_entry)) return 1;
    printf("{\"preset\":%lu,\"known_mask\":%u,\"entry_bytes\":%zu,\"entries\":[",
           preset, known, sizeof(struct iwinfo_freqlist_entry));
    for (size_t i = 0; i < (size_t)length; i += sizeof(struct iwinfo_freqlist_entry)) {
        const struct iwinfo_freqlist_entry *entry = (void *)(buffer + i);
        printf("%s{\"band_mask\":%u,\"channel\":%u,\"mhz\":%u,\"restricted\":%s,\"flags_mask\":%u}",
               i ? "," : "", entry->band, entry->channel, entry->mhz,
               entry->restricted ? "true" : "false", entry->flags);
    }
    puts("]}");
    if (ops->close) ops->close();
    free(buffer);
    dlclose(library);
    return 0;
}
