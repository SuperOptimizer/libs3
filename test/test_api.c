/* API-contract tests: exercises argument validation, error mapping, the
 * free()/double-free guards, and the s3_list_all iterator. No network
 * except the LIBS3_LIVE-gated iterator section. Closes the cheap-to-test
 * coverage that the feature tests skip. */
#include "libs3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static s3_status failing_provider(void *ud, s3_credentials *out) {
    (void)ud; (void)out;
    return S3_ERR_NO_CREDS;
}

/* Returns creds with an EMPTY region so the client's configured region
 * fallback path in resolve_request_creds is exercised. */
static s3_status noregion_provider(void *ud, s3_credentials *out) {
    (void)ud;
    out->access_key    = strdup("AKIA");
    out->secret_key    = strdup("SECRET");
    out->session_token = strdup("");
    out->region        = strdup("");      /* empty -> client region used */
    return S3_OK;
}

static bool list_cb(void *ud, const s3_list_result *p) {
    (void)p;
    int *pages = ud;
    (*pages)++;
    return *pages < 3;   /* stop after 3 pages to bound a huge listing */
}

int main(void) {
    /* --- s3_status_str covers every enum value (+ unknown) ---------- */
    s3_status all[] = { S3_OK, S3_ERR_INVALID_ARG, S3_ERR_OOM, S3_ERR_CURL,
                        S3_ERR_HTTP, S3_ERR_NO_CREDS, S3_ERR_PARSE,
                        S3_ERR_IO, S3_ERR_ABORTED, (s3_status)999 };
    for (size_t i = 0; i < sizeof all / sizeof *all; i++) {
        const char *s = s3_status_str(all[i]);
        CHECK(s && s[0]);
    }

    /* --- NULL / invalid-arg guards on every public entry point ------ */
    CHECK(!s3_url_is_s3(NULL));
    s3_url u;
    CHECK(s3_url_parse(NULL, &u) == S3_ERR_INVALID_ARG);
    CHECK(s3_url_parse("s3://b/k", NULL) == S3_ERR_INVALID_ARG);
    CHECK(s3_url_to_https(NULL, NULL, 0) == S3_ERR_INVALID_ARG);
    s3_url_free(NULL);                 /* must be safe */
    s3_url_free(&(s3_url){0});         /* zero-init safe */

    s3_credentials_free(NULL);
    s3_credentials_free(&(s3_credentials){0});
    CHECK(s3_credentials_from_env(NULL) == S3_ERR_INVALID_ARG);
    CHECK(s3_credentials_load(NULL, NULL) == S3_ERR_INVALID_ARG);

    s3_response r = {0};
    s3_response_free(NULL);
    s3_response_free(&r);              /* zero-init safe */
    s3_response_free(&r);              /* double free safe */
    CHECK(!s3_response_ok(NULL));
    CHECK(!s3_response_not_found(NULL));

    s3_client *c = s3_client_new(NULL);   /* NULL cfg -> all defaults */
    CHECK(c != NULL);
    CHECK(s3_client_last_error(c) != NULL);
    CHECK(s3_client_last_error(NULL) != NULL);

    CHECK(s3_get(NULL, "s3://b/k", &r) == S3_ERR_INVALID_ARG);
    CHECK(s3_get(c, NULL, &r) == S3_ERR_INVALID_ARG);
    CHECK(s3_get(c, "s3://b/k", NULL) == S3_ERR_INVALID_ARG);

    /* zero-length range short-circuits to S3_OK with an empty response */
    CHECK(s3_get_range(c, "s3://b/k", 0, 0, &r) == S3_OK);
    s3_response_free(&r);

    /* conditional GET with no/empty etag == plain GET path (bad client
       arg still rejected) */
    CHECK(s3_get_conditional(NULL, "s3://b/k", NULL, &r)
          == S3_ERR_INVALID_ARG);

    CHECK(s3_get_batch(c, NULL, 1, 0, &r) == S3_ERR_INVALID_ARG);
    CHECK(s3_get_batch(c, NULL, 0, 0, NULL) == S3_OK);   /* n==0 no-op */

    CHECK(s3_put_file(c, "s3://b/k", NULL, NULL, &r) == S3_ERR_INVALID_ARG);
    CHECK(s3_put_file(c, "s3://b/k", "/no/such/file/here", NULL, &r)
          == S3_ERR_IO);

    CHECK(s3_copy(c, NULL, "s3://b/k", &r) == S3_ERR_INVALID_ARG);
    CHECK(s3_copy(c, "not-s3", "s3://b/k", &r) == S3_ERR_INVALID_ARG);

    s3_multipart *mp = NULL;
    CHECK(s3_multipart_create(NULL, "s3://b/k", NULL, &mp)
          == S3_ERR_INVALID_ARG);
    CHECK(s3_multipart_upload_part(NULL, 1, "x", 1) == S3_ERR_INVALID_ARG);
    CHECK(s3_multipart_upload_part_file(NULL, 1, NULL)
          == S3_ERR_INVALID_ARG);
    CHECK(s3_multipart_complete(NULL, &r) == S3_ERR_INVALID_ARG);
    CHECK(s3_multipart_abort(NULL) == S3_ERR_INVALID_ARG);

    s3_list_result lr;
    s3_list_result_free(NULL);
    s3_list_result_free(&(s3_list_result){0});
    CHECK(s3_list(NULL, "s3://b/", "/", NULL, &lr) == S3_ERR_INVALID_ARG);
    CHECK(s3_list_ex(c, NULL, NULL, &lr) == S3_ERR_INVALID_ARG);
    CHECK(s3_list(c, "not-an-s3-url", "/", NULL, &lr)
          == S3_ERR_INVALID_ARG);
    CHECK(s3_list_all(c, "s3://b/", "/", NULL, NULL)
          == S3_ERR_INVALID_ARG);

    /* abort flag round-trips */
    CHECK(!s3_global_is_aborted());
    s3_global_abort();
    CHECK(s3_global_is_aborted());
    /* a request while aborted returns promptly with S3_ERR_ABORTED */
    CHECK(s3_get(c, "s3://vesuvius-challenge-open-data/x", &r)
          == S3_ERR_ABORTED);
    s3_response_free(&r);
    s3_global_reset_abort();
    CHECK(!s3_global_is_aborted());

    /* --- auth-building paths (run before transport; dead host ok) --- */
    /* Bearer token: apply_auth adds "Authorization: Bearer ..." then the
       request fails to connect -- the auth code path is what we cover. */
    {
        s3_config bc = { .bearer_token = "test-token-123",
                         .connect_timeout_s = 1, .max_retries = 0 };
        s3_client *bcl = s3_client_new(&bc);
        s3_status rc = s3_get(bcl, "https://127.0.0.1:1/x", &r);
        CHECK(rc == S3_ERR_CURL);
        s3_response_free(&r);
        s3_client_free(bcl);
    }
    /* Basic auth path. */
    {
        s3_config ba = { .basic_user = "u", .basic_pass = "p",
                         .connect_timeout_s = 1, .max_retries = 0 };
        s3_client *bcl = s3_client_new(&ba);
        s3_status rc = s3_get(bcl, "https://127.0.0.1:1/x", &r);
        CHECK(rc == S3_ERR_CURL);
        s3_response_free(&r);
        s3_client_free(bcl);
    }
    /* cred_provider that fails -> error propagates from do_request. */
    {
        s3_config pc = { .cred_provider = failing_provider,
                         .connect_timeout_s = 1, .max_retries = 0 };
        s3_client *pcl = s3_client_new(&pc);
        s3_status rc = s3_get(pcl, "s3://b/k", &r);
        CHECK(rc == S3_ERR_NO_CREDS);
        s3_response_free(&r);
        /* batch path also propagates a failing provider */
        s3_range_req rq = { "s3://b/k", 0, 0 };
        s3_response br = {0};
        rc = s3_get_batch(pcl, &rq, 1, 1, &br);
        CHECK(rc == S3_ERR_NO_CREDS);
        s3_response_free(&br);
        s3_client_free(pcl);
    }
    /* provider returns empty region -> client's configured region is
       substituted (resolve_request_creds fallback path). */
    {
        s3_config nr = { .cred_provider = noregion_provider,
                         .region = "ap-southeast-2",
                         .connect_timeout_s = 1, .max_retries = 0 };
        s3_client *ncl = s3_client_new(&nr);
        s3_status rc = s3_get(ncl, "https://127.0.0.1:1/b/k", &r);
        CHECK(rc == S3_ERR_CURL);   /* auth built w/ fallback region, then
                                       transport fails on the dead host */
        s3_response_free(&r);
        s3_client_free(ncl);
    }
    /* Session-token path: SigV4 + x-amz-security-token header built. */
    {
        s3_config sc = { .creds = { .access_key = (char*)"AK",
                                    .secret_key = (char*)"SK",
                                    .session_token = (char*)"TOK",
                                    .region = (char*)"us-east-1" },
                         .connect_timeout_s = 1, .max_retries = 0 };
        s3_client *scl = s3_client_new(&sc);
        s3_status rc = s3_get(scl, "https://127.0.0.1:1/b/k", &r);
        CHECK(rc == S3_ERR_CURL);
        s3_response_free(&r);
        s3_client_free(scl);
    }

    /* --- s3_list_all iterator (live, gated) ------------------------- */
    if (getenv("LIBS3_LIVE")) {
        int pages = 0;
        s3_status rc = s3_list_all(c,
            "s3://vesuvius-challenge-open-data/PHerc0172/volumes/"
            "20241024131838-7.910um-53keV-masked.zarr/0/",
            NULL, list_cb, &pages);
        printf("list_all rc=%d pages=%d\n", rc, pages);
        /* list_cb stops at 3 pages; rc is still S3_OK on early stop */
        CHECK(rc == S3_OK && pages >= 1);
    }

    s3_client_free(c);
    s3_client_free(NULL);              /* safe */

    printf(fails ? "test_api: %d FAILED\n" : "test_api: OK\n", fails);
    return fails ? 1 : 0;
}
