/* Opt-in live test against the public Vesuvius open-data bucket.
 * Skipped unless LIBS3_LIVE=1 in the environment. Anonymous (unsigned). */
#include "libs3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define URL "s3://vesuvius-challenge-open-data/PHerc0172/volumes/" \
            "20241024131838-7.910um-53keV-masked.zarr/.zgroup"

int main(void) {
    if (!getenv("LIBS3_LIVE")) {
        printf("test_live_s3: SKIPPED (set LIBS3_LIVE=1 to run)\n");
        return 0;
    }
    int fails = 0;
    s3_client *c = s3_client_new(NULL);   /* anonymous */
    if (!c) { printf("client_new failed\n"); return 1; }

    /* HEAD */
    s3_response r = {0};
    s3_status rc = s3_head(c, URL, &r);
    printf("HEAD rc=%d status=%ld len=%llu\n", rc, r.status,
           (unsigned long long)r.content_length);
    if (!s3_response_ok(&r)) fails++;
    s3_response_free(&r);

    /* GET */
    rc = s3_get(c, URL, &r);
    printf("GET  rc=%d status=%ld bytes=%zu\n", rc, r.status, r.body_len);
    if (!s3_response_ok(&r) || r.body_len == 0) fails++;
    s3_response_free(&r);

    /* GET range: first 16 bytes */
    rc = s3_get_range(c, URL, 0, 16, &r);
    printf("RANGE rc=%d status=%ld bytes=%zu\n", rc, r.status, r.body_len);
    if (r.body_len != 16) fails++;
    s3_response_free(&r);

    /* LIST one level under the volume dir */
    s3_list_result lr;
    rc = s3_list(c,
        "s3://vesuvius-challenge-open-data/PHerc0172/volumes/",
        "/", NULL, &lr);
    printf("LIST rc=%d prefixes=%zu objects=%zu\n", rc,
           lr.prefix_count, lr.object_count);
    if (rc != S3_OK || (lr.prefix_count == 0 && lr.object_count == 0))
        fails++;
    s3_list_result_free(&lr);

    /* Paginated recursive list: the chunk dir has >1000 keys, so this
       exercises continuation-token round-tripping (regression: tokens
       contain '+' '/' '=' and must be query-encoded). */
    rc = s3_list(c,
        "s3://vesuvius-challenge-open-data/PHerc0172/volumes/"
        "20241024131838-7.910um-53keV-masked.zarr/0/",
        NULL, NULL, &lr);
    bool truncated = lr.is_truncated && lr.next_continuation_token;
    if (rc == S3_OK && truncated) {
        s3_list_result lr2;
        s3_status rc2 = s3_list(c,
            "s3://vesuvius-challenge-open-data/PHerc0172/volumes/"
            "20241024131838-7.910um-53keV-masked.zarr/0/",
            NULL, lr.next_continuation_token, &lr2);
        printf("PAGE2 rc=%d objects=%zu\n", rc2, lr2.object_count);
        if (rc2 != S3_OK || lr2.object_count == 0) fails++;
        s3_list_result_free(&lr2);
    } else {
        printf("PAGE2 skipped (rc=%d truncated=%d)\n", rc, truncated);
        if (rc != S3_OK) fails++;
    }
    s3_list_result_free(&lr);

#define VOLBASE "s3://vesuvius-challenge-open-data/PHerc0172/volumes/" \
                "20241024131838-7.910um-53keV-masked.zarr/"

    /* Batched ranged GET: 3 objects concurrently, mixed full + ranged. */
    s3_range_req rq[3] = {
        { VOLBASE ".zgroup",       0, 0, 0  },   /* whole object */
        { VOLBASE ".zattrs",       0, 32, 0 },   /* ranged */
        { VOLBASE "metadata.json", 0, 0, 0  },
    };
    s3_response br[3] = {0};
    rc = s3_get_batch(c, rq, 3, 3, br);
    printf("BATCH rc=%d s0=%ld/%zu s1=%ld/%zu s2=%ld/%zu\n", rc,
           br[0].status, br[0].body_len, br[1].status, br[1].body_len,
           br[2].status, br[2].body_len);
    if (rc != S3_OK || !s3_response_ok(&br[0]) ||
        br[1].status != 206 || br[1].body_len != 32 ||
        !s3_response_ok(&br[2]))
        fails++;
    char *etag = br[0].etag ? strdup(br[0].etag) : NULL;
    for (int i = 0; i < 3; i++) s3_response_free(&br[i]);

    /* Batch with a missing key mixed in: transport completes for all, so
       rc maps to S3_ERR_HTTP and the bad slot carries a 404 while the
       good slot still succeeds (per-object error reporting). */
    s3_range_req rqm[2] = {
        { VOLBASE ".zgroup",            0, 0, 0 },
        { VOLBASE "nope-does-not.exist", 0, 0, 0 },
    };
    s3_response bm[2] = {0};
    rc = s3_get_batch(c, rqm, 2, 2, bm);
    printf("BATCHMISS rc=%d s0=%ld s1=%ld\n", rc, bm[0].status,
           bm[1].status);
    if (rc != S3_ERR_HTTP || !s3_response_ok(&bm[0]) ||
        bm[1].status != 404)
        fails++;
    for (int i = 0; i < 2; i++) s3_response_free(&bm[i]);

    /* Conditional GET: known ETag -> 304 Not Modified, empty body. */
    if (etag) {
        rc = s3_get_conditional(c, VOLBASE ".zgroup", etag, &r);
        printf("COND rc=%d status=%ld (expect 304) body=%zu\n",
               rc, r.status, r.body_len);
        if (rc != S3_OK || r.status != 304 || r.body_len != 0) fails++;
        s3_response_free(&r);
    } else {
        printf("COND skipped (no ETag)\n");
        fails++;
    }
    free(etag);

    /* list_ex: max_keys caps the page; is_truncated must be set. */
    s3_list_params lp = { .max_keys = 2 };
    rc = s3_list_ex(c, VOLBASE "0/", &lp, &lr);
    printf("LISTEX rc=%d objs=%zu trunc=%d\n",
           rc, lr.object_count, lr.is_truncated);
    if (rc != S3_OK || lr.object_count != 2 || !lr.is_truncated) fails++;
    s3_list_result_free(&lr);

    /* Error path: missing key -> S3_ERR_HTTP + 404, resp still populated. */
    rc = s3_get(c, VOLBASE "definitely-not-here.xyz", &r);
    printf("MISS rc=%d status=%ld\n", rc, r.status);
    if (rc != S3_ERR_HTTP || r.status != 404 ||
        !s3_response_not_found(&r)) fails++;
    s3_response_free(&r);

    /* Bad URL -> S3_ERR_INVALID_ARG, no crash. */
    rc = s3_get(c, "not-a-url://x", &r);
    if (rc != S3_ERR_INVALID_ARG && rc != S3_ERR_HTTP &&
        rc != S3_ERR_CURL) fails++;
    s3_response_free(&r);

    s3_client_free(c);
    printf(fails ? "test_live_s3: %d FAILED\n" : "test_live_s3: OK\n",
           fails);
    return fails ? 1 : 0;
}
