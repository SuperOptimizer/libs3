#define _POSIX_C_SOURCE 200809L
#include "../s3.h"
#include "../src/s3_internal.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-60s ", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

#define ASSERT_EQ_STR(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL: expected \"%s\", got \"%s\"\n", (b), (a)); \
        return; \
    } \
} while(0)

#define ASSERT_EQ_INT(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL: expected %d, got %d\n", (int)(b), (int)(a)); \
        return; \
    } \
} while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: create a minimal s3_client on the stack for testing
 * ═══════════════════════════════════════════════════════════════════════════ */

static s3_client make_test_client(void) {
    s3_client c;
    memset(&c, 0, sizeof(c));
    c.access_key_id     = s3__strdup("AKIAIOSFODNN7EXAMPLE");
    c.secret_access_key = s3__strdup("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    c.region            = s3__strdup("us-east-1");
    c.use_https         = true;
    c.log_level         = S3_LOG_NONE;
    return c;
}

static void free_test_client(s3_client *c) {
    S3_FREE(c->access_key_id);
    S3_FREE(c->secret_access_key);
    S3_FREE(c->session_token);
    S3_FREE(c->region);
    S3_FREE(c->endpoint);
    S3_FREE(c->account_id);
    s3_buf_free(&c->response);
}

/* Helper to check if a string contains a substring */
static bool str_contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != nullptr;
}

/* Helper to check if a curl_slist contains a header starting with prefix */
static bool slist_has_prefix(struct curl_slist *list, const char *prefix) {
    for (struct curl_slist *h = list; h; h = h->next) {
        if (strncmp(h->data, prefix, strlen(prefix)) == 0)
            return true;
    }
    return false;
}

/* Helper to get header value from curl_slist by prefix */
static const char *slist_get_value(struct curl_slist *list, const char *prefix) {
    size_t plen = strlen(prefix);
    for (struct curl_slist *h = list; h; h = h->next) {
        if (strncmp(h->data, prefix, plen) == 0)
            return h->data + plen;
    }
    return nullptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. URL Building Tests (22 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_url_virtual_hosted(void) {
    TEST("URL: virtual-hosted style");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.us-east-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_path_style(void) {
    TEST("URL: path style");
    s3_client c = make_test_client();
    c.use_path_style = true;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://s3.us-east-1.amazonaws.com/my-bucket/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_custom_endpoint_path(void) {
    TEST("URL: custom endpoint, path style");
    s3_client c = make_test_client();
    c.endpoint = s3__strdup("minio.local:9000");
    c.use_path_style = true;
    c.use_https = false;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "http://minio.local:9000/my-bucket/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_custom_endpoint_virtual(void) {
    TEST("URL: custom endpoint, virtual-hosted style");
    s3_client c = make_test_client();
    c.endpoint = s3__strdup("minio.local:9000");
    c.use_path_style = false;
    c.use_https = false;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "http://my-bucket.minio.local:9000/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_with_query(void) {
    TEST("URL: with query string");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", nullptr, "versioning", false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.us-east-1.amazonaws.com/?versioning");
    PASS();
    free_test_client(&c);
}

static void test_url_no_bucket(void) {
    TEST("URL: no bucket (ListBuckets)");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, nullptr, nullptr, nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://s3.us-east-1.amazonaws.com/");
    PASS();
    free_test_client(&c);
}

static void test_url_no_key(void) {
    TEST("URL: no key (bucket root)");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", nullptr, nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.us-east-1.amazonaws.com/");
    PASS();
    free_test_client(&c);
}

static void test_url_key_with_slashes(void) {
    TEST("URL: key with slashes");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", "path/to/file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.us-east-1.amazonaws.com/path/to/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_key_with_spaces(void) {
    TEST("URL: key with spaces (URI encoded)");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", "my file.txt", nullptr, false, url, sizeof(url));
    /* spaces should be encoded as %20 */
    if (!str_contains(url, "my%20file.txt")) {
        FAIL("expected URI-encoded space (%20)");
        free_test_client(&c);
        return;
    }
    PASS();
    free_test_client(&c);
}

static void test_url_key_with_special_chars(void) {
    TEST("URL: key with special chars (URI encoded)");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", "test$file.txt", nullptr, false, url, sizeof(url));
    /* $ should be encoded as %24 */
    if (!str_contains(url, "test%24file.txt")) {
        FAIL("expected URI-encoded $ (%24)");
        free_test_client(&c);
        return;
    }
    PASS();
    free_test_client(&c);
}

static void test_url_transfer_acceleration(void) {
    TEST("URL: transfer acceleration");
    s3_client c = make_test_client();
    c.use_transfer_acceleration = true;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3-accelerate.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_dual_stack(void) {
    TEST("URL: dual stack");
    s3_client c = make_test_client();
    c.use_dual_stack = true;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.dualstack.us-east-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_fips(void) {
    TEST("URL: FIPS endpoint");
    s3_client c = make_test_client();
    c.use_fips = true;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3-fips.us-east-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_control_endpoint(void) {
    TEST("URL: control endpoint with account_id");
    s3_client c = make_test_client();
    c.account_id = s3__strdup("123456789012");
    char url[4096];
    s3__build_url(&c, nullptr, nullptr, nullptr, true, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://123456789012.s3-control.us-east-1.amazonaws.com/");
    PASS();
    free_test_client(&c);
}

static void test_url_http(void) {
    TEST("URL: HTTP (not HTTPS)");
    s3_client c = make_test_client();
    c.use_https = false;
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "http://my-bucket.s3.us-east-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_multiple_query_params(void) {
    TEST("URL: multiple query params");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", nullptr, "list-type=2&prefix=photos/", false, url, sizeof(url));
    if (!str_contains(url, "?list-type=2&prefix=photos/")) {
        FAIL("expected query string with multiple params");
        free_test_client(&c);
        return;
    }
    PASS();
    free_test_client(&c);
}

static void test_url_empty_query(void) {
    TEST("URL: empty query string");
    s3_client c = make_test_client();
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", "", false, url, sizeof(url));
    /* Empty query should not add a '?' */
    ASSERT_EQ_STR(url, "https://my-bucket.s3.us-east-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_very_long_key(void) {
    TEST("URL: very long key (1024 chars)");
    s3_client c = make_test_client();
    char long_key[1025];
    memset(long_key, 'a', 1024);
    long_key[1024] = '\0';
    char url[8192];
    s3__build_url(&c, "my-bucket", long_key, nullptr, false, url, sizeof(url));
    /* Should contain the full key */
    if (!str_contains(url, long_key)) {
        FAIL("expected long key in URL");
        free_test_client(&c);
        return;
    }
    PASS();
    free_test_client(&c);
}

static void test_url_key_with_unicode(void) {
    TEST("URL: key with unicode characters");
    s3_client c = make_test_client();
    char url[4096];
    /* UTF-8 encoded filename with accented chars */
    s3__build_url(&c, "my-bucket", "caf\xc3\xa9.txt", nullptr, false, url, sizeof(url));
    /* UTF-8 bytes should be percent-encoded */
    if (!str_contains(url, "caf%C3%A9.txt")) {
        FAIL("expected percent-encoded UTF-8");
        free_test_client(&c);
        return;
    }
    PASS();
    free_test_client(&c);
}

static void test_url_region_us_west_2(void) {
    TEST("URL: region us-west-2");
    s3_client c = make_test_client();
    S3_FREE(c.region);
    c.region = s3__strdup("us-west-2");
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.us-west-2.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_region_eu_west_1(void) {
    TEST("URL: region eu-west-1");
    s3_client c = make_test_client();
    S3_FREE(c.region);
    c.region = s3__strdup("eu-west-1");
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.eu-west-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_region_ap_southeast_1(void) {
    TEST("URL: region ap-southeast-1");
    s3_client c = make_test_client();
    S3_FREE(c.region);
    c.region = s3__strdup("ap-southeast-1");
    char url[4096];
    s3__build_url(&c, "my-bucket", "file.txt", nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "https://my-bucket.s3.ap-southeast-1.amazonaws.com/file.txt");
    PASS();
    free_test_client(&c);
}

static void test_url_no_bucket_custom_endpoint(void) {
    TEST("URL: no bucket with custom endpoint");
    s3_client c = make_test_client();
    c.endpoint = s3__strdup("minio.local:9000");
    c.use_https = false;
    char url[4096];
    s3__build_url(&c, nullptr, nullptr, nullptr, false, url, sizeof(url));
    ASSERT_EQ_STR(url, "http://minio.local:9000/");
    PASS();
    free_test_client(&c);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. SigV4 Signing Tests (16 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sigv4_authorization_header(void) {
    TEST("SigV4: Authorization header appended");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    int rc = s3__sign_request(&c, "GET", "/file.txt", nullptr, &headers, hash);
    ASSERT_EQ_INT(rc, 0);
    if (!slist_has_prefix(headers, "Authorization:")) {
        FAIL("missing Authorization header");
        curl_slist_free_all(headers);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_amz_date_header(void) {
    TEST("SigV4: x-amz-date header added");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &headers, hash);
    if (!slist_has_prefix(headers, "x-amz-date:")) {
        FAIL("missing x-amz-date header");
        curl_slist_free_all(headers);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_content_sha256_header(void) {
    TEST("SigV4: x-amz-content-sha256 header added");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &headers, hash);
    if (!slist_has_prefix(headers, "x-amz-content-sha256:")) {
        FAIL("missing x-amz-content-sha256 header");
        curl_slist_free_all(headers);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_session_token(void) {
    TEST("SigV4: x-amz-security-token with session_token");
    s3_client c = make_test_client();
    c.session_token = s3__strdup("FwoGZXIvYXdzEBYaDHka0example");
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &headers, hash);
    if (!slist_has_prefix(headers, "x-amz-security-token:")) {
        FAIL("missing x-amz-security-token header");
        curl_slist_free_all(headers);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_auth_starts_with_aws4(void) {
    TEST("SigV4: Authorization starts with AWS4-HMAC-SHA256");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &headers, hash);
    const char *auth = slist_get_value(headers, "Authorization: ");
    if (!auth || strncmp(auth, "AWS4-HMAC-SHA256", 16) != 0) {
        FAIL("Authorization doesn't start with AWS4-HMAC-SHA256");
        curl_slist_free_all(headers);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_credential_format(void) {
    TEST("SigV4: Credential contains access_key/date/region/s3/aws4_request");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &headers, hash);
    const char *auth = slist_get_value(headers, "Authorization: ");
    if (!auth) { FAIL("no Authorization header"); curl_slist_free_all(headers); free_test_client(&c); return; }
    if (!str_contains(auth, "Credential=AKIAIOSFODNN7EXAMPLE/")) {
        FAIL("missing access_key in Credential");
        curl_slist_free_all(headers); free_test_client(&c); return;
    }
    if (!str_contains(auth, "/us-east-1/s3/aws4_request")) {
        FAIL("missing region/s3/aws4_request in Credential");
        curl_slist_free_all(headers); free_test_client(&c); return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_different_payloads(void) {
    TEST("SigV4: different payloads produce different signatures");
    s3_client c = make_test_client();

    /* Sign with empty payload */
    struct curl_slist *h1 = nullptr;
    h1 = curl_slist_append(h1, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    h1 = curl_slist_append(h1, "x-amz-date: 20250101T000000Z");
    char hash1[65];
    s3__sha256_hex("", 0, hash1);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &h1, hash1);
    const char *auth1 = slist_get_value(h1, "Authorization: ");

    /* Sign with non-empty payload */
    struct curl_slist *h2 = nullptr;
    h2 = curl_slist_append(h2, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    h2 = curl_slist_append(h2, "x-amz-date: 20250101T000000Z");
    char hash2[65];
    s3__sha256_hex("hello world", 11, hash2);
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &h2, hash2);
    const char *auth2 = slist_get_value(h2, "Authorization: ");

    if (auth1 && auth2 && strcmp(auth1, auth2) == 0) {
        FAIL("same signature for different payloads");
        curl_slist_free_all(h1); curl_slist_free_all(h2);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(h1);
    curl_slist_free_all(h2);
    free_test_client(&c);
}

static void test_sigv4_same_request_same_sig(void) {
    TEST("SigV4: same request signed twice gives same signature");
    s3_client c = make_test_client();
    char hash[65];
    s3__sha256_hex("", 0, hash);

    /* Fix the timestamp to ensure same second */
    struct curl_slist *h1 = nullptr;
    h1 = curl_slist_append(h1, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    h1 = curl_slist_append(h1, "x-amz-date: 20250601T120000Z");
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &h1, hash);
    const char *auth1 = slist_get_value(h1, "Authorization: ");
    char auth1_copy[16384];
    if (auth1) snprintf(auth1_copy, sizeof(auth1_copy), "%s", auth1);

    struct curl_slist *h2 = nullptr;
    h2 = curl_slist_append(h2, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    h2 = curl_slist_append(h2, "x-amz-date: 20250601T120000Z");
    s3__sign_request(&c, "GET", "/file.txt", nullptr, &h2, hash);
    const char *auth2 = slist_get_value(h2, "Authorization: ");

    if (!auth1 || !auth2 || strcmp(auth1_copy, auth2) != 0) {
        FAIL("different signatures for identical requests");
        curl_slist_free_all(h1); curl_slist_free_all(h2);
        free_test_client(&c);
        return;
    }
    PASS();
    curl_slist_free_all(h1);
    curl_slist_free_all(h2);
    free_test_client(&c);
}

static void test_sigv4_no_session_token(void) {
    TEST("SigV4: no x-amz-security-token without session_token");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/", nullptr, &headers, hash);
    if (slist_has_prefix(headers, "x-amz-security-token:")) {
        FAIL("x-amz-security-token should not be present");
        curl_slist_free_all(headers); free_test_client(&c); return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_signed_headers_field(void) {
    TEST("SigV4: Authorization has SignedHeaders field");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/", nullptr, &headers, hash);
    const char *auth = slist_get_value(headers, "Authorization: ");
    if (!auth || !str_contains(auth, "SignedHeaders=")) {
        FAIL("missing SignedHeaders in Authorization");
        curl_slist_free_all(headers); free_test_client(&c); return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_sigv4_signature_field(void) {
    TEST("SigV4: Authorization has Signature field");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("", 0, hash);
    s3__sign_request(&c, "GET", "/", nullptr, &headers, hash);
    const char *auth = slist_get_value(headers, "Authorization: ");
    if (!auth || !str_contains(auth, "Signature=")) {
        FAIL("missing Signature in Authorization");
        curl_slist_free_all(headers); free_test_client(&c); return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

static void test_presign_url_algorithm(void) {
    TEST("Presign: URL contains X-Amz-Algorithm");
    s3_client c = make_test_client();
    char url[8192];
    int rc = s3__presign_url(&c, "GET", "my-bucket", "file.txt", 3600, nullptr, nullptr, url, sizeof(url));
    ASSERT_EQ_INT(rc, 0);
    if (!str_contains(url, "X-Amz-Algorithm=AWS4-HMAC-SHA256")) {
        FAIL("missing X-Amz-Algorithm");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_url_credential(void) {
    TEST("Presign: URL contains X-Amz-Credential");
    s3_client c = make_test_client();
    char url[8192];
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 3600, nullptr, nullptr, url, sizeof(url));
    if (!str_contains(url, "X-Amz-Credential=")) {
        FAIL("missing X-Amz-Credential");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_url_date(void) {
    TEST("Presign: URL contains X-Amz-Date");
    s3_client c = make_test_client();
    char url[8192];
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 3600, nullptr, nullptr, url, sizeof(url));
    if (!str_contains(url, "X-Amz-Date=")) {
        FAIL("missing X-Amz-Date");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_url_expires(void) {
    TEST("Presign: URL contains X-Amz-Expires");
    s3_client c = make_test_client();
    char url[8192];
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 3600, nullptr, nullptr, url, sizeof(url));
    if (!str_contains(url, "X-Amz-Expires=3600")) {
        FAIL("missing X-Amz-Expires=3600");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_url_signature(void) {
    TEST("Presign: URL contains X-Amz-Signature");
    s3_client c = make_test_client();
    char url[8192];
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 3600, nullptr, nullptr, url, sizeof(url));
    if (!str_contains(url, "X-Amz-Signature=")) {
        FAIL("missing X-Amz-Signature");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_different_expiry(void) {
    TEST("Presign: different expiry values");
    s3_client c = make_test_client();
    char url1[8192], url2[8192];
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 900, nullptr, nullptr, url1, sizeof(url1));
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 7200, nullptr, nullptr, url2, sizeof(url2));
    if (!str_contains(url1, "X-Amz-Expires=900")) {
        FAIL("missing X-Amz-Expires=900"); free_test_client(&c); return;
    }
    if (!str_contains(url2, "X-Amz-Expires=7200")) {
        FAIL("missing X-Amz-Expires=7200"); free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_with_content_type(void) {
    TEST("Presign: with content_type includes signed headers");
    s3_client c = make_test_client();
    char url[8192];
    s3__presign_url(&c, "PUT", "my-bucket", "file.txt", 3600, "application/json", nullptr, url, sizeof(url));
    /* signed headers should include content-type */
    if (!str_contains(url, "content-type")) {
        FAIL("expected content-type in presigned URL signed headers");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_presign_with_session_token(void) {
    TEST("Presign: session token adds X-Amz-Security-Token");
    s3_client c = make_test_client();
    c.session_token = s3__strdup("my-session-token-123");
    char url[8192];
    s3__presign_url(&c, "GET", "my-bucket", "file.txt", 3600, nullptr, nullptr, url, sizeof(url));
    if (!str_contains(url, "X-Amz-Security-Token=")) {
        FAIL("missing X-Amz-Security-Token");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_sigv4_put_method(void) {
    TEST("SigV4: PUT method signs correctly");
    s3_client c = make_test_client();
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Host: my-bucket.s3.us-east-1.amazonaws.com");
    char hash[65];
    s3__sha256_hex("file-data", 9, hash);
    int rc = s3__sign_request(&c, "PUT", "/file.txt", nullptr, &headers, hash);
    ASSERT_EQ_INT(rc, 0);
    if (!slist_has_prefix(headers, "Authorization:")) {
        FAIL("missing Authorization for PUT");
        curl_slist_free_all(headers); free_test_client(&c); return;
    }
    PASS();
    curl_slist_free_all(headers);
    free_test_client(&c);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. SSE Header Tests (15 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sse_none(void) {
    TEST("SSE: SSE_NONE returns same list unchanged");
    s3_encryption enc = { .mode = S3_SSE_NONE };
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    struct curl_slist *result = s3__apply_sse_headers(headers, &enc);
    /* Should be the same list */
    if (result != headers) {
        FAIL("expected same list pointer");
        curl_slist_free_all(result); return;
    }
    PASS();
    curl_slist_free_all(result);
}

static void test_sse_null_enc(void) {
    TEST("SSE: nullptr encryption returns same list");
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    struct curl_slist *result = s3__apply_sse_headers(headers, nullptr);
    if (result != headers) {
        FAIL("expected same list pointer");
        curl_slist_free_all(result); return;
    }
    PASS();
    curl_slist_free_all(result);
}

static void test_sse_s3(void) {
    TEST("SSE: SSE_S3 adds AES256 header");
    s3_encryption enc = { .mode = S3_SSE_S3 };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption: AES256")) {
        FAIL("missing AES256 header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_kms(void) {
    TEST("SSE: SSE_KMS adds aws:kms header");
    s3_encryption enc = { .mode = S3_SSE_KMS };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption: aws:kms")) {
        FAIL("missing aws:kms header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_kms_key_id(void) {
    TEST("SSE: SSE_KMS with key_id adds kms key id header");
    s3_encryption enc = {
        .mode = S3_SSE_KMS,
        .kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/my-key",
    };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-aws-kms-key-id:")) {
        FAIL("missing kms key id header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_kms_context(void) {
    TEST("SSE: SSE_KMS with context adds context header");
    s3_encryption enc = {
        .mode = S3_SSE_KMS,
        .kms_context = "eyJrZXkiOiAidmFsdWUifQ==",
    };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-context:")) {
        FAIL("missing context header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_kms_bucket_key(void) {
    TEST("SSE: SSE_KMS with bucket_key_enabled");
    s3_encryption enc = {
        .mode = S3_SSE_KMS,
        .bucket_key_enabled = true,
    };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-bucket-key-enabled:")) {
        FAIL("missing bucket-key-enabled header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_c(void) {
    TEST("SSE: SSE_C adds algorithm, key, key-MD5 headers");
    uint8_t key[32];
    memset(key, 0xAA, 32);
    uint8_t md5[16];
    memset(md5, 0xBB, 16);
    s3_encryption enc = {
        .mode = S3_SSE_C,
        .customer_key = key,
        .customer_key_md5 = md5,
    };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-customer-algorithm:")) {
        FAIL("missing customer algorithm header");
        curl_slist_free_all(headers); return;
    }
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-customer-key:")) {
        FAIL("missing customer key header");
        curl_slist_free_all(headers); return;
    }
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-customer-key-MD5:")) {
        FAIL("missing customer key MD5 header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_c_no_key(void) {
    TEST("SSE: SSE_C with nullptr key adds only algorithm");
    s3_encryption enc = {
        .mode = S3_SSE_C,
        .customer_key = nullptr,
        .customer_key_md5 = nullptr,
    };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption-customer-algorithm:")) {
        FAIL("missing customer algorithm header");
        curl_slist_free_all(headers); return;
    }
    /* Should NOT have the key or MD5 headers */
    if (slist_has_prefix(headers, "x-amz-server-side-encryption-customer-key:")) {
        FAIL("unexpected customer key header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_source_sse_c(void) {
    TEST("SSE: source SSE-C adds copy-source prefix headers");
    uint8_t key[32];
    memset(key, 0xCC, 32);
    uint8_t md5[16];
    memset(md5, 0xDD, 16);
    s3_encryption enc = {
        .mode = S3_SSE_C,
        .customer_key = key,
        .customer_key_md5 = md5,
    };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_source_sse_headers(headers, &enc);
    if (!slist_has_prefix(headers, "x-amz-copy-source-server-side-encryption-customer-algorithm:")) {
        FAIL("missing copy-source algorithm header");
        curl_slist_free_all(headers); return;
    }
    if (!slist_has_prefix(headers, "x-amz-copy-source-server-side-encryption-customer-key:")) {
        FAIL("missing copy-source key header");
        curl_slist_free_all(headers); return;
    }
    if (!slist_has_prefix(headers, "x-amz-copy-source-server-side-encryption-customer-key-MD5:")) {
        FAIL("missing copy-source key MD5 header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_source_sse_non_c(void) {
    TEST("SSE: source SSE non-C returns unchanged");
    s3_encryption enc = { .mode = S3_SSE_S3 };
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    struct curl_slist *result = s3__apply_source_sse_headers(headers, &enc);
    if (result != headers) {
        FAIL("expected same list pointer for non-SSE-C source");
        curl_slist_free_all(result); return;
    }
    PASS();
    curl_slist_free_all(result);
}

static void test_sse_apply_to_nullptr_list(void) {
    TEST("SSE: apply to nullptr list (create new)");
    s3_encryption enc = { .mode = S3_SSE_S3 };
    struct curl_slist *result = s3__apply_sse_headers(nullptr, &enc);
    if (!result) {
        FAIL("expected non-null list");
        return;
    }
    if (!slist_has_prefix(result, "x-amz-server-side-encryption: AES256")) {
        FAIL("missing AES256 header");
        curl_slist_free_all(result); return;
    }
    PASS();
    curl_slist_free_all(result);
}

static void test_sse_apply_to_existing_list(void) {
    TEST("SSE: apply to existing list (append)");
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    s3_encryption enc = { .mode = S3_SSE_S3 };
    headers = s3__apply_sse_headers(headers, &enc);
    /* Should have both the original and new headers */
    if (!slist_has_prefix(headers, "Content-Type:")) {
        FAIL("lost original header");
        curl_slist_free_all(headers); return;
    }
    if (!slist_has_prefix(headers, "x-amz-server-side-encryption: AES256")) {
        FAIL("missing AES256 header");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_sse_header_format(void) {
    TEST("SSE: verify header string format");
    s3_encryption enc = { .mode = S3_SSE_S3 };
    struct curl_slist *headers = nullptr;
    headers = s3__apply_sse_headers(headers, &enc);
    /* The exact header should be this string */
    if (!headers || strcmp(headers->data, "x-amz-server-side-encryption: AES256") != 0) {
        FAIL("unexpected header format");
        curl_slist_free_all(headers); return;
    }
    PASS();
    curl_slist_free_all(headers);
}

static void test_source_sse_null_enc(void) {
    TEST("SSE: source with nullptr enc returns unchanged");
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "X-Custom: value");
    struct curl_slist *result = s3__apply_source_sse_headers(headers, nullptr);
    if (result != headers) {
        FAIL("expected same list pointer");
        curl_slist_free_all(result); return;
    }
    PASS();
    curl_slist_free_all(result);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. Error Parsing Tests (10 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_error_parse_access_denied(void) {
    TEST("Error: parse AccessDenied XML");
    s3_client c = make_test_client();
    s3_buf_init(&c.response);
    const char *xml = "<Error><Code>AccessDenied</Code>"
                      "<Message>Access Denied</Message></Error>";
    s3_buf_append_str(&c.response, xml);
    s3_status st = s3__parse_error_response(&c, 403);
    ASSERT_EQ_INT(st, S3_STATUS_ACCESS_DENIED);
    ASSERT_EQ_STR(c.last_error.s3_code, "AccessDenied");
    PASS();
    free_test_client(&c);
}

static void test_error_parse_no_such_key(void) {
    TEST("Error: parse NoSuchKey XML");
    s3_client c = make_test_client();
    s3_buf_init(&c.response);
    const char *xml = "<Error><Code>NoSuchKey</Code>"
                      "<Message>The specified key does not exist.</Message></Error>";
    s3_buf_append_str(&c.response, xml);
    s3_status st = s3__parse_error_response(&c, 404);
    ASSERT_EQ_INT(st, S3_STATUS_NO_SUCH_KEY);
    PASS();
    free_test_client(&c);
}

static void test_error_parse_all_fields(void) {
    TEST("Error: parse all fields (Code, Message, RequestId, HostId)");
    s3_client c = make_test_client();
    s3_buf_init(&c.response);
    const char *xml = "<Error>"
                      "<Code>NoSuchBucket</Code>"
                      "<Message>The bucket does not exist</Message>"
                      "<RequestId>ABC123DEF456</RequestId>"
                      "<HostId>host-id-xyz</HostId>"
                      "</Error>";
    s3_buf_append_str(&c.response, xml);
    s3__parse_error_response(&c, 404);
    ASSERT_EQ_STR(c.last_error.s3_code, "NoSuchBucket");
    ASSERT_EQ_STR(c.last_error.s3_message, "The bucket does not exist");
    ASSERT_EQ_STR(c.last_error.s3_request_id, "ABC123DEF456");
    ASSERT_EQ_STR(c.last_error.s3_host_id, "host-id-xyz");
    PASS();
    free_test_client(&c);
}

static void test_error_parse_missing_fields(void) {
    TEST("Error: parse error with missing fields");
    s3_client c = make_test_client();
    s3_buf_init(&c.response);
    const char *xml = "<Error><Code>SlowDown</Code></Error>";
    s3_buf_append_str(&c.response, xml);
    s3_status st = s3__parse_error_response(&c, 503);
    ASSERT_EQ_INT(st, S3_STATUS_SLOW_DOWN);
    /* Message should be empty */
    ASSERT_EQ_STR(c.last_error.s3_message, "");
    PASS();
    free_test_client(&c);
}

static void test_error_empty_response(void) {
    TEST("Error: empty response body (fallback to HTTP status)");
    s3_client c = make_test_client();
    s3_buf_init(&c.response);
    /* No response body */
    s3_status st = s3__parse_error_response(&c, 404);
    ASSERT_EQ_INT(st, S3_STATUS_HTTP_NOT_FOUND);
    PASS();
    free_test_client(&c);
}

static void test_error_non_xml_response(void) {
    TEST("Error: non-XML response body");
    s3_client c = make_test_client();
    s3_buf_init(&c.response);
    s3_buf_append_str(&c.response, "This is not XML");
    s3_status st = s3__parse_error_response(&c, 500);
    /* No <Code> tag found, should fall back to HTTP status mapping */
    ASSERT_EQ_INT(st, S3_STATUS_HTTP_INTERNAL_SERVER_ERROR);
    PASS();
    free_test_client(&c);
}

static void test_set_error(void) {
    TEST("Error: s3__set_error sets fields");
    s3_client c = make_test_client();
    s3__set_error(&c, S3_STATUS_ACCESS_DENIED, 403, "AccessDenied", "Access Denied");
    ASSERT_EQ_INT(c.last_error.status, S3_STATUS_ACCESS_DENIED);
    ASSERT_EQ_INT(c.last_error.http_status, 403);
    ASSERT_EQ_STR(c.last_error.s3_code, "AccessDenied");
    ASSERT_EQ_STR(c.last_error.s3_message, "Access Denied");
    PASS();
    free_test_client(&c);
}

static void test_set_curl_error(void) {
    TEST("Error: s3__set_curl_error sets fields");
    s3_client c = make_test_client();
    c.curl_errbuf[0] = '\0';
    s3__set_curl_error(&c, 7); /* CURLE_COULDNT_CONNECT */
    ASSERT_EQ_INT(c.last_error.status, S3_STATUS_CURL_ERROR);
    ASSERT_EQ_INT((int)c.last_error.curl_code, 7);
    /* curl_error should have something */
    if (c.last_error.curl_error[0] == '\0') {
        FAIL("curl_error should have a message");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_clear_error(void) {
    TEST("Error: s3__clear_error zeros all fields");
    s3_client c = make_test_client();
    s3__set_error(&c, S3_STATUS_ACCESS_DENIED, 403, "AccessDenied", "msg");
    s3__clear_error(&c);
    ASSERT_EQ_INT(c.last_error.status, S3_STATUS_OK);
    ASSERT_EQ_INT(c.last_error.http_status, 0);
    ASSERT_EQ_STR(c.last_error.s3_code, "");
    ASSERT_EQ_STR(c.last_error.s3_message, "");
    ASSERT_EQ_INT((int)c.last_error.curl_code, 0);
    PASS();
    free_test_client(&c);
}

static void test_error_http_status_mapping(void) {
    TEST("Error: HTTP status mapping for various codes");
    ASSERT_EQ_INT(s3__map_http_status(400), S3_STATUS_HTTP_BAD_REQUEST);
    ASSERT_EQ_INT(s3__map_http_status(403), S3_STATUS_HTTP_FORBIDDEN);
    ASSERT_EQ_INT(s3__map_http_status(404), S3_STATUS_HTTP_NOT_FOUND);
    ASSERT_EQ_INT(s3__map_http_status(409), S3_STATUS_HTTP_CONFLICT);
    ASSERT_EQ_INT(s3__map_http_status(500), S3_STATUS_HTTP_INTERNAL_SERVER_ERROR);
    ASSERT_EQ_INT(s3__map_http_status(503), S3_STATUS_HTTP_SERVICE_UNAVAILABLE);
    ASSERT_EQ_INT(s3__map_http_status(999), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. Log Tests (5 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool g_log_called = false;
static s3_log_level g_log_level_received = S3_LOG_NONE;
static char g_log_message[4096] = "";

static void test_log_callback(s3_log_level level, const char *msg, void *userdata) {
    (void)userdata;
    g_log_called = true;
    g_log_level_received = level;
    snprintf(g_log_message, sizeof(g_log_message), "%s", msg);
}

static void test_log_with_callback(void) {
    TEST("Log: callback is called");
    s3_client c = make_test_client();
    c.log_fn = test_log_callback;
    c.log_userdata = nullptr;
    c.log_level = S3_LOG_TRACE;
    g_log_called = false;
    s3__log(&c, S3_LOG_INFO, "test message %d", 42);
    if (!g_log_called) {
        FAIL("log callback not called");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_log_below_threshold(void) {
    TEST("Log: level below threshold, callback not called");
    s3_client c = make_test_client();
    c.log_fn = test_log_callback;
    c.log_level = S3_LOG_WARN;
    g_log_called = false;
    s3__log(&c, S3_LOG_DEBUG, "should not appear");
    if (g_log_called) {
        FAIL("callback should not have been called");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_log_at_threshold(void) {
    TEST("Log: level at threshold, callback called");
    s3_client c = make_test_client();
    c.log_fn = test_log_callback;
    c.log_level = S3_LOG_WARN;
    g_log_called = false;
    s3__log(&c, S3_LOG_WARN, "warning message");
    if (!g_log_called) {
        FAIL("callback should have been called at threshold level");
        free_test_client(&c); return;
    }
    PASS();
    free_test_client(&c);
}

static void test_log_without_callback(void) {
    TEST("Log: no callback, no crash");
    s3_client c = make_test_client();
    c.log_fn = nullptr;
    c.log_level = S3_LOG_TRACE;
    /* Should not crash */
    s3__log(&c, S3_LOG_ERROR, "this should be a no-op");
    PASS();
    free_test_client(&c);
}

static void test_log_message_content(void) {
    TEST("Log: message content is correct");
    s3_client c = make_test_client();
    c.log_fn = test_log_callback;
    c.log_level = S3_LOG_TRACE;
    g_log_message[0] = '\0';
    s3__log(&c, S3_LOG_INFO, "hello %s %d", "world", 99);
    ASSERT_EQ_STR(g_log_message, "hello world 99");
    PASS();
    free_test_client(&c);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("\n=== libs3 HTTP / SigV4 / SSE / Error Tests ===\n\n");

    printf("[URL Building]\n");
    test_url_virtual_hosted();
    test_url_path_style();
    test_url_custom_endpoint_path();
    test_url_custom_endpoint_virtual();
    test_url_with_query();
    test_url_no_bucket();
    test_url_no_key();
    test_url_key_with_slashes();
    test_url_key_with_spaces();
    test_url_key_with_special_chars();
    test_url_transfer_acceleration();
    test_url_dual_stack();
    test_url_fips();
    test_url_control_endpoint();
    test_url_http();
    test_url_multiple_query_params();
    test_url_empty_query();
    test_url_very_long_key();
    test_url_key_with_unicode();
    test_url_region_us_west_2();
    test_url_region_eu_west_1();
    test_url_region_ap_southeast_1();
    test_url_no_bucket_custom_endpoint();

    printf("\n[SigV4 Signing]\n");
    test_sigv4_authorization_header();
    test_sigv4_amz_date_header();
    test_sigv4_content_sha256_header();
    test_sigv4_session_token();
    test_sigv4_auth_starts_with_aws4();
    test_sigv4_credential_format();
    test_sigv4_different_payloads();
    test_sigv4_same_request_same_sig();
    test_sigv4_no_session_token();
    test_sigv4_signed_headers_field();
    test_sigv4_signature_field();
    test_sigv4_put_method();
    test_presign_url_algorithm();
    test_presign_url_credential();
    test_presign_url_date();
    test_presign_url_expires();
    test_presign_url_signature();
    test_presign_different_expiry();
    test_presign_with_content_type();
    test_presign_with_session_token();

    printf("\n[SSE Headers]\n");
    test_sse_none();
    test_sse_null_enc();
    test_sse_s3();
    test_sse_kms();
    test_sse_kms_key_id();
    test_sse_kms_context();
    test_sse_kms_bucket_key();
    test_sse_c();
    test_sse_c_no_key();
    test_source_sse_c();
    test_source_sse_non_c();
    test_sse_apply_to_nullptr_list();
    test_sse_apply_to_existing_list();
    test_sse_header_format();
    test_source_sse_null_enc();

    printf("\n[Error Parsing]\n");
    test_error_parse_access_denied();
    test_error_parse_no_such_key();
    test_error_parse_all_fields();
    test_error_parse_missing_fields();
    test_error_empty_response();
    test_error_non_xml_response();
    test_set_error();
    test_set_curl_error();
    test_clear_error();
    test_error_http_status_mapping();

    printf("\n[Logging]\n");
    test_log_with_callback();
    test_log_below_threshold();
    test_log_at_threshold();
    test_log_without_callback();
    test_log_message_content();

    printf("\n%d/%d tests passed\n\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
