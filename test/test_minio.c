/* End-to-end write/multipart test against a local MinIO.
 *
 * Skipped unless LIBS3_MINIO=1. Bring MinIO up first:
 *   docker compose -f test/docker-compose.minio.yml up -d
 *   LIBS3_MINIO=1 ./build/test_minio
 *
 * Exercises the paths the open-data (read-only) bucket cannot:
 * PUT, streamed PUT-from-file, HEAD, conditional GET, server-side COPY,
 * DELETE, multipart upload (streamed parts) + completion, and list.
 */
#include "libs3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUCKET   "s3://libs3-test/"
#define KEY_OBJ  BUCKET "hello.txt"
#define KEY_FILE BUCKET "fromfile.bin"
#define KEY_COPY BUCKET "hello-copy.txt"
#define KEY_MP   BUCKET "multipart.bin"
#define KEY_CAS  BUCKET "ifmatch.txt"

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* Refresh-aware credential provider: returns freshly-owned copies each
 * call (libs3 frees them), mimicking a cache-backed STS resolver. */
s3_status mp_provider(void *ud, s3_credentials *out) {
    (void)ud;
    out->access_key   = strdup("libs3test");
    out->secret_key   = strdup("libs3secret");
    out->session_token = strdup("");
    out->region       = strdup("us-east-1");
    return S3_OK;
}

int main(void) {
    if (!getenv("LIBS3_MINIO")) {
        printf("test_minio: SKIPPED (set LIBS3_MINIO=1 with MinIO up)\n");
        return 0;
    }
    s3_config cfg = {0};
    cfg.creds.access_key   = (char *)"libs3test";
    cfg.creds.secret_key   = (char *)"libs3secret";
    cfg.creds.region       = (char *)"us-east-1";
    cfg.endpoint           = "localhost:9000";
    cfg.endpoint_insecure  = true;
    s3_client *c = s3_client_new(&cfg);
    if (!c) { printf("client_new failed\n"); return 1; }

    s3_response r = {0};
    s3_status rc;

    /* PUT */
    const char *payload = "hello libs3 via minio\n";
    rc = s3_put(c, KEY_OBJ, payload, strlen(payload), "text/plain", &r);
    printf("PUT rc=%d status=%ld\n", rc, r.status);
    CHECK(rc == S3_OK && s3_response_ok(&r));
    char *etag = r.etag ? strdup(r.etag) : NULL;
    s3_response_free(&r);

    /* HEAD: size + etag visible */
    rc = s3_head(c, KEY_OBJ, &r);
    printf("HEAD rc=%d status=%ld len=%llu etag=%s\n", rc, r.status,
           (unsigned long long)r.content_length, r.etag ? r.etag : "(none)");
    CHECK(rc == S3_OK && r.content_length == strlen(payload));
    s3_response_free(&r);

    /* GET round-trips the bytes */
    rc = s3_get(c, KEY_OBJ, &r);
    CHECK(rc == S3_OK && r.body_len == strlen(payload) &&
          memcmp(r.body, payload, r.body_len) == 0);
    s3_response_free(&r);

    /* Conditional GET with the PUT etag -> 304 */
    if (etag) {
        rc = s3_get_conditional(c, KEY_OBJ, etag, &r);
        printf("COND rc=%d status=%ld\n", rc, r.status);
        CHECK(rc == S3_OK && r.status == 304 && r.body_len == 0);
        s3_response_free(&r);
    }

    free(etag);

    /* Optimistic-concurrency PUT (If-Match) on a dedicated key:
       - matching ETag  -> succeeds, object updated, new ETag returned
       - stale ETag      -> 412 Precondition Failed, object unchanged */
    {
        const char *v0 = "cas version 0\n";
        rc = s3_put(c, KEY_CAS, v0, strlen(v0), "text/plain", &r);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        char *e0 = r.etag ? strdup(r.etag) : NULL;
        s3_response_free(&r);
        CHECK(e0 != NULL);

        const char *v1 = "cas version 1 (via If-Match)\n";
        rc = s3_put_if_match(c, KEY_CAS, v1, strlen(v1),
                             "text/plain", e0, &r);
        printf("IFMATCH ok rc=%d status=%ld\n", rc, r.status);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        char *e1 = r.etag ? strdup(r.etag) : NULL;
        s3_response_free(&r);
        CHECK(e1 && e0 && strcmp(e1, e0) != 0);

        /* e0 is now stale -> 412, object must keep v1 */
        const char *boom = "should not be written\n";
        rc = s3_put_if_match(c, KEY_CAS, boom, strlen(boom),
                             "text/plain", e0, &r);
        printf("IFMATCH stale rc=%d status=%ld (expect 412)\n",
               rc, r.status);
        CHECK(rc == S3_ERR_HTTP && r.status == 412);
        s3_response_free(&r);

        rc = s3_get(c, KEY_CAS, &r);
        CHECK(rc == S3_OK && r.body_len == strlen(v1) &&
              memcmp(r.body, v1, r.body_len) == 0);
        s3_response_free(&r);

        rc = s3_delete(c, KEY_CAS, &r);
        CHECK(rc == S3_OK);
        s3_response_free(&r);
        free(e0); free(e1);
    }

    /* Streamed PUT from a temp file */
    char tmpl[] = "/tmp/libs3minioXXXXXX";
    int fd = mkstemp(tmpl);
    FILE *tf = fdopen(fd, "wb");
    for (int i = 0; i < 5000; i++) fputs("0123456789ABCDEF", tf); /* 80 KB */
    fclose(tf);
    rc = s3_put_file(c, KEY_FILE, tmpl, "application/octet-stream", &r);
    printf("PUTFILE rc=%d status=%ld\n", rc, r.status);
    CHECK(rc == S3_OK && s3_response_ok(&r));
    s3_response_free(&r);
    rc = s3_head(c, KEY_FILE, &r);
    CHECK(rc == S3_OK && r.content_length == 80000);
    s3_response_free(&r);

    /* Server-side COPY */
    rc = s3_copy(c, KEY_OBJ, KEY_COPY, &r);
    printf("COPY rc=%d status=%ld\n", rc, r.status);
    CHECK(rc == S3_OK && s3_response_ok(&r));
    s3_response_free(&r);
    rc = s3_get(c, KEY_COPY, &r);
    CHECK(rc == S3_OK && r.body_len == strlen(payload));
    s3_response_free(&r);

    /* Multipart: two streamed 5 MiB parts (S3 min part size). */
    s3_multipart *mp = NULL;
    rc = s3_multipart_create(c, KEY_MP, "application/octet-stream", &mp);
    printf("MP create rc=%d\n", rc);
    CHECK(rc == S3_OK && mp);
    if (mp) {
        const size_t PART = 5 * 1024 * 1024;
        char pth[] = "/tmp/libs3mppartXXXXXX";
        int pfd = mkstemp(pth);
        FILE *pf = fdopen(pfd, "wb");
        char *chunk = malloc(PART);
        memset(chunk, 'A', PART);
        fwrite(chunk, 1, PART, pf);
        fclose(pf);
        rc = s3_multipart_upload_part_file(mp, 1, pth);
        CHECK(rc == S3_OK);
        memset(chunk, 'B', PART);
        FILE *pf2 = fopen(pth, "wb");
        fwrite(chunk, 1, 1024, pf2);   /* small last part */
        fclose(pf2);
        rc = s3_multipart_upload_part_file(mp, 2, pth);
        CHECK(rc == S3_OK);
        free(chunk);
        rc = s3_multipart_complete(mp, &r);
        printf("MP complete rc=%d status=%ld\n", rc, r.status);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        s3_response_free(&r);
        remove(pth);

        rc = s3_head(c, KEY_MP, &r);
        printf("MP head len=%llu (expect %zu)\n",
               (unsigned long long)r.content_length, PART + 1024);
        CHECK(rc == S3_OK && r.content_length == PART + 1024);
        s3_response_free(&r);
    }
    remove(tmpl);

    /* Parallel multipart: mixed buffer + file sources, uploaded
       concurrently. Regression guard for the part-ordering bug --
       parts complete out of order, so s3_multipart_complete must sort
       by PartNumber before emitting the XML. */
    {
        s3_multipart *pmp = NULL;
        rc = s3_multipart_create(c, BUCKET "parallel.bin",
                                 "application/octet-stream", &pmp);
        CHECK(rc == S3_OK && pmp);
        if (pmp) {
            const size_t P = 5 * 1024 * 1024;
            char *b1 = malloc(P), *b2 = malloc(P);
            memset(b1, 'A', P);
            memset(b2, 'B', P);
            /* part 3 from a file, parts 1+2 from memory */
            char fp[] = "/tmp/libs3parpartXXXXXX";
            int pf = mkstemp(fp);
            char tail[2048];
            memset(tail, 'C', sizeof tail);
            CHECK(write(pf, tail, sizeof tail) == (ssize_t)sizeof tail);
            close(pf);
            s3_part_src parts[3] = {
                { 1, b1, P, NULL },
                { 2, b2, P, NULL },
                { 3, NULL, 0, fp },
            };
            rc = s3_multipart_upload_parts_parallel(pmp, parts, 3, 3);
            printf("PARALLEL upload rc=%d\n", rc);
            CHECK(rc == S3_OK);
            rc = s3_multipart_complete(pmp, &r);
            printf("PARALLEL complete rc=%d status=%ld\n", rc, r.status);
            CHECK(rc == S3_OK && s3_response_ok(&r));
            s3_response_free(&r);
            rc = s3_head(c, BUCKET "parallel.bin", &r);
            printf("PARALLEL head len=%llu (expect %zu)\n",
                   (unsigned long long)r.content_length,
                   2 * P + sizeof tail);
            CHECK(rc == S3_OK &&
                  r.content_length == 2 * P + sizeof tail);
            s3_response_free(&r);
            rc = s3_delete(c, BUCKET "parallel.bin", &r);
            CHECK(rc == S3_OK);
            s3_response_free(&r);
            free(b1); free(b2);
            remove(fp);
        }
    }

    /* Multipart abort path */
    s3_multipart *mp2 = NULL;
    rc = s3_multipart_create(c, BUCKET "aborted.bin", NULL, &mp2);
    CHECK(rc == S3_OK && mp2);
    if (mp2) {
        const size_t P = 5 * 1024 * 1024;
        char *b = malloc(P); memset(b, 'Z', P);
        CHECK(s3_multipart_upload_part(mp2, 1, b, P) == S3_OK);
        free(b);
        rc = s3_multipart_abort(mp2);
        printf("MP abort rc=%d\n", rc);
        CHECK(rc == S3_OK);
    }

    /* List the bucket */
    s3_list_result lr;
    rc = s3_list(c, BUCKET, "/", NULL, &lr);
    printf("LIST rc=%d objects=%zu\n", rc, lr.object_count);
    CHECK(rc == S3_OK && lr.object_count >= 4);
    s3_list_result_free(&lr);

    /* list_ex start_after: skip keys <= "hello.txt" lexicographically. */
    s3_list_params sp = { .start_after = "hello.txt" };
    rc = s3_list_ex(c, BUCKET, &sp, &lr);
    printf("LIST start_after rc=%d objects=%zu\n", rc, lr.object_count);
    CHECK(rc == S3_OK);
    for (size_t i = 0; i < lr.object_count; i++)
        CHECK(strcmp(lr.objects[i].key, "hello.txt") > 0);
    s3_list_result_free(&lr);

    /* Same operations through a refresh-aware cred_provider client --
       exercises the per-request provider path (rotated-STS use case). */
    extern s3_status mp_provider(void *, s3_credentials *);
    s3_config pcfg = cfg;
    pcfg.creds = (s3_credentials){0};
    pcfg.cred_provider = mp_provider;
    s3_client *pc = s3_client_new(&pcfg);
    CHECK(pc != NULL);
    rc = s3_put(pc, KEY_OBJ, payload, strlen(payload), "text/plain", &r);
    printf("PROVIDER put rc=%d status=%ld\n", rc, r.status);
    CHECK(rc == S3_OK && s3_response_ok(&r));
    s3_response_free(&r);
    rc = s3_get(pc, KEY_OBJ, &r);
    CHECK(rc == S3_OK && r.body_len == strlen(payload));
    s3_response_free(&r);
    s3_client_free(pc);

    /* Async batch + caller-buffer destinations: PUT a 1 MiB object, read
       it back as 16 x 64 KiB via (a) blocking get_batch with dst (also
       exercises the coalescing split-into-dst path: ranges are adjacent),
       (b) async submit/poll/take with dst, (c) async with cancellation,
       (d) s3_get_range_into. */
    {
        enum { ASZ = 1 << 20, NR = 16, PSZ = ASZ / NR };
        uint8_t *obj = malloc(ASZ), *got = malloc(ASZ);
        for (size_t i = 0; i < ASZ; i++) obj[i] = (uint8_t)(i * 2654435761u >> 13);
        rc = s3_put(c, BUCKET "async.bin", obj, ASZ,
                    "application/octet-stream", &r);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        s3_response_free(&r);

        s3_range_req rq[NR];
        s3_response  outs[NR];

        /* (a) blocking, coalesced, into caller memory */
        memset(got, 0, ASZ);
        for (int i = 0; i < NR; i++) {
            rq[i] = (s3_range_req){ .url = BUCKET "async.bin",
                                    .offset = (uint64_t)i * PSZ,
                                    .length = PSZ, .dst = got + i * PSZ };
            memset(&outs[i], 0, sizeof outs[i]);
        }
        rc = s3_get_batch(c, rq, NR, 0, outs);
        CHECK(rc == S3_OK);
        for (int i = 0; i < NR; i++) {
            CHECK(outs[i].status == 206 || outs[i].status == 200);
            CHECK(outs[i].body == NULL && outs[i].body_len == PSZ);
            s3_response_free(&outs[i]);
        }
        printf("BATCH dst+coalesce bytes %s\n",
               memcmp(got, obj, ASZ) ? "MISMATCH" : "OK");
        CHECK(memcmp(got, obj, ASZ) == 0);

        /* (b) async: submit, poll until done, take, verify */
        memset(got, 0, ASZ);
        s3_batch *b = NULL;
        rc = s3_batch_submit(c, rq, NR, 8, &b);
        CHECK(rc == S3_OK && b);
        int polls = 0, done = 0;
        while ((done = s3_batch_poll(b, 5)) < NR && polls < 10000) polls++;
        CHECK(done == NR);
        for (int i = 0; i < NR; i++) {
            CHECK(s3_batch_ready(b, i));
            s3_response br;
            CHECK(s3_batch_take(b, i, &br) == S3_OK);
            CHECK((br.status == 206 || br.status == 200) &&
                  br.body == NULL && br.body_len == PSZ);
            s3_response_free(&br);
            /* double take must fail */
            CHECK(s3_batch_take(b, i, &br) == S3_ERR_INVALID_ARG);
        }
        s3_batch_free(b);
        printf("ASYNC batch (%d polls) bytes %s\n", polls,
               memcmp(got, obj, ASZ) ? "MISMATCH" : "OK");
        CHECK(memcmp(got, obj, ASZ) == 0);

        /* (c) async with cancellation: cancel the odd requests */
        memset(got, 0, ASZ);
        b = NULL;
        rc = s3_batch_submit(c, rq, NR, 2, &b);   /* low conc: some pending */
        CHECK(rc == S3_OK && b);
        for (int i = 1; i < NR; i += 2) s3_batch_cancel(b, i);
        CHECK(s3_batch_wait(b) == S3_OK);
        int got_even = 0;
        for (int i = 0; i < NR; i++) {
            s3_response br;
            s3_status ts = s3_batch_take(b, i, &br);
            if (i % 2 == 1) {
                /* cancelled OR finished before cancel landed */
                CHECK(ts == S3_ERR_ABORTED || ts == S3_OK);
                if (ts == S3_OK) s3_response_free(&br);
            } else {
                CHECK(ts == S3_OK && br.body_len == PSZ);
                CHECK(memcmp(got + i * PSZ, obj + i * PSZ, PSZ) == 0);
                got_even++;
                s3_response_free(&br);
            }
        }
        CHECK(got_even == NR / 2);
        s3_batch_free(b);
        printf("ASYNC cancel: even halves OK\n");

        /* (d) zero-alloc single ranged GET */
        memset(got, 0, ASZ);
        rc = s3_get_range_into(c, BUCKET "async.bin", 12345, 4096, got, &r);
        CHECK(rc == S3_OK && (r.status == 206 || r.status == 200));
        CHECK(r.body == NULL && r.body_len == 4096);
        CHECK(memcmp(got, obj + 12345, 4096) == 0);
        s3_response_free(&r);
        printf("RANGE_INTO bytes OK\n");

        rc = s3_delete(c, BUCKET "async.bin", &r);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        s3_response_free(&r);
        free(obj); free(got);
    }

    /* DELETE everything we created */
    const char *keys[] = { KEY_OBJ, KEY_FILE, KEY_COPY, KEY_MP };
    for (size_t i = 0; i < 4; i++) {
        rc = s3_delete(c, keys[i], &r);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        s3_response_free(&r);
    }
    rc = s3_get(c, KEY_OBJ, &r);
    CHECK(rc == S3_ERR_HTTP && r.status == 404);
    s3_response_free(&r);

    s3_client_free(c);
    printf(fails ? "test_minio: %d FAILED\n" : "test_minio: OK\n", fails);
    return fails ? 1 : 0;
}
