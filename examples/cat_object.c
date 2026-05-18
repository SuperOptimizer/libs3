/* cat_object -- fetch an s3:// or https:// URL and write it to stdout.
 * Usage: cat_object <url> [profile]
 * With no profile and no credentials it fetches anonymously. */
#include "libs3.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <url> [aws-profile]\n", argv[0]);
        return 2;
    }
    s3_config cfg = {0};
    s3_credentials creds = {0};
    if (argc >= 3) {
        if (s3_credentials_load(argv[2], &creds) == S3_OK)
            cfg.creds = creds;
    } else {
        /* best-effort: sign if anything is resolvable, else anonymous */
        if (s3_credentials_load(NULL, &creds) == S3_OK)
            cfg.creds = creds;
    }
    s3_client *c = s3_client_new(&cfg);
    s3_credentials_free(&creds);
    if (!c) { fprintf(stderr, "client init failed\n"); return 1; }

    s3_response r = {0};
    s3_status rc = s3_get(c, argv[1], &r);
    int ret = 0;
    if (rc != S3_OK || !s3_response_ok(&r)) {
        fprintf(stderr, "fetch failed: rc=%s http=%ld (%s)\n",
                s3_status_str(rc), r.status, s3_client_last_error(c));
        ret = 1;
    } else {
        fwrite(r.body, 1, r.body_len, stdout);
    }
    s3_response_free(&r);
    s3_client_free(c);
    return ret;
}
