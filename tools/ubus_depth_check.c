/* Link with the image's matching libubox sources, not a system libubox. */
#include <stdio.h>
#include <stdlib.h>
#include "blobmsg.h"
#include "blobmsg_json.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int depth = atoi(argv[1]);
    struct blob_buf b = {};
    void **cookies = calloc(depth, sizeof(*cookies));
    blob_buf_init(&b, 0);
    for (int i = 0; i < depth; i++) cookies[i] = blobmsg_open_table(&b, "a");
    blobmsg_add_u32(&b, "value", 7);
    for (int i = depth - 1; i >= 0; i--) blobmsg_close_table(&b, cookies[i]);
    char *json = blobmsg_format_json(b.head, true);
    if (!json) return 2;
    puts(json);
    free(json);
    free(cookies);
    blob_buf_free(&b);
    return 0;
}
