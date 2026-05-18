/* list_bucket -- walk a bucket prefix one level deep (like `ls`).
 * Usage: list_bucket <s3://bucket/prefix/> [profile] */
#include "libs3.h"
#include <stdio.h>
#include <stdlib.h>

static bool on_page(void *ud, const s3_list_result *p) {
    (void)ud;
    for (size_t i = 0; i < p->prefix_count; i++)
        printf("  DIR  %s\n", p->prefixes[i]);
    for (size_t i = 0; i < p->object_count; i++)
        printf("  %10llu  %s\n",
               (unsigned long long)p->objects[i].size,
               p->objects[i].key);
    return true;   /* keep paginating */
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <s3://bucket/prefix/> [profile]\n",
                argv[0]);
        return 2;
    }
    s3_config cfg = {0};
    s3_credentials creds = {0};
    if (s3_credentials_load(argc >= 3 ? argv[2] : NULL, &creds) == S3_OK)
        cfg.creds = creds;
    s3_client *c = s3_client_new(&cfg);
    s3_credentials_free(&creds);
    if (!c) { fprintf(stderr, "client init failed\n"); return 1; }

    s3_status rc = s3_list_all(c, argv[1], "/", on_page, NULL);
    if (rc != S3_OK)
        fprintf(stderr, "list failed: %s (%s)\n",
                s3_status_str(rc), s3_client_last_error(c));
    s3_client_free(c);
    return rc == S3_OK ? 0 : 1;
}
