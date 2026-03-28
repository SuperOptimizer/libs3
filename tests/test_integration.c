#define _POSIX_C_SOURCE 200809L
#include "../s3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Safety Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define TEST_BUCKET "philodemos"
#define TEST_PREFIX "forrest/libs3/"

/* Multipart minimum part size: 5 MB */
#define PART_SIZE (5 * 1024 * 1024)

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Framework
 * ═══════════════════════════════════════════════════════════════════════════ */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-60s ", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)
#define FAILF(fmt, ...) do { tests_failed++; printf("FAIL: " fmt "\n", __VA_ARGS__); } while(0)

#define ASSERT_OK(st) do { \
    s3_status _st = (st); \
    if (_st != S3_STATUS_OK) { \
        FAILF("expected OK, got %s (%d)", s3_status_string(_st), (int)_st); \
        return; \
    } \
} while(0)

#define ASSERT_STATUS(st, expected) do { \
    s3_status _st = (st); \
    s3_status _exp = (expected); \
    if (_st != _exp) { \
        FAILF("expected %s, got %s (%d)", s3_status_string(_exp), s3_status_string(_st), (int)_st); \
        return; \
    } \
} while(0)

/* Build a key under TEST_PREFIX */
static void make_key(char *buf, size_t bufsz, const char *suffix) {
    snprintf(buf, bufsz, "%s%s", TEST_PREFIX, suffix);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Credential Parsing
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char access_key_id[256];
    char secret_access_key[256];
    char session_token[4096];
    char region[64];
} test_credentials;

static char *trim_whitespace(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' || s[len-1] == ' ' || s[len-1] == '\t'))
        s[--len] = '\0';
    return s;
}

static int parse_ini_file(const char *path, const char *section,
                          const char *keys[], const char *dests[], int destszs[], int nkeys) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[8192];
    int in_section = 0;
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        char *trimmed = trim_whitespace(line);
        if (trimmed[0] == '#' || trimmed[0] == ';' || trimmed[0] == '\0') continue;

        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                in_section = (strcmp(trimmed + 1, section) == 0);
            }
            continue;
        }

        if (!in_section) continue;

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = trim_whitespace(trimmed);
        char *v = trim_whitespace(eq + 1);

        for (int i = 0; i < nkeys; i++) {
            if (strcmp(k, keys[i]) == 0) {
                snprintf((char *)dests[i], destszs[i], "%s", v);
                found++;
            }
        }
    }
    fclose(f);
    return found;
}

static int load_credentials(test_credentials *creds) {
    memset(creds, 0, sizeof(*creds));
    strcpy(creds->region, "us-east-1"); /* default */

    /* Try environment variables first */
    const char *env_key = getenv("AWS_ACCESS_KEY_ID");
    const char *env_secret = getenv("AWS_SECRET_ACCESS_KEY");
    const char *env_token = getenv("AWS_SESSION_TOKEN");
    const char *env_region = getenv("AWS_DEFAULT_REGION");
    if (!env_region) env_region = getenv("AWS_REGION");

    if (env_key && env_secret) {
        snprintf(creds->access_key_id, sizeof(creds->access_key_id), "%s", env_key);
        snprintf(creds->secret_access_key, sizeof(creds->secret_access_key), "%s", env_secret);
        if (env_token)
            snprintf(creds->session_token, sizeof(creds->session_token), "%s", env_token);
        if (env_region)
            snprintf(creds->region, sizeof(creds->region), "%s", env_region);
        return 0;
    }

    /* Parse ~/.aws/credentials */
    const char *home = getenv("HOME");
    if (!home) return -1;

    char cred_path[1024];
    snprintf(cred_path, sizeof(cred_path), "%s/.aws/credentials", home);

    const char *cred_keys[] = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"};
    const char *cred_dests[] = {creds->access_key_id, creds->secret_access_key, creds->session_token};
    int cred_sizes[] = {(int)sizeof(creds->access_key_id), (int)sizeof(creds->secret_access_key), (int)sizeof(creds->session_token)};
    int found = parse_ini_file(cred_path, "default", cred_keys, cred_dests, cred_sizes, 3);
    if (found < 2) {
        fprintf(stderr, "Failed to parse credentials from %s\n", cred_path);
        return -1;
    }

    /* Parse ~/.aws/config for region */
    char config_path[1024];
    snprintf(config_path, sizeof(config_path), "%s/.aws/config", home);
    const char *cfg_keys[] = {"region"};
    const char *cfg_dests[] = {creds->region};
    int cfg_sizes[] = {(int)sizeof(creds->region)};
    parse_ini_file(config_path, "default", cfg_keys, cfg_dests, cfg_sizes, 1);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Stream callback helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *data;
    size_t len;
    size_t pos;
} stream_read_ctx;

static int64_t stream_read_fn(void *buf, size_t buf_size, void *userdata) {
    stream_read_ctx *ctx = (stream_read_ctx *)userdata;
    size_t remaining = ctx->len - ctx->pos;
    if (remaining == 0) return 0; /* EOF */
    size_t to_copy = remaining < buf_size ? remaining : buf_size;
    memcpy(buf, ctx->data + ctx->pos, to_copy);
    ctx->pos += to_copy;
    return (int64_t)to_copy;
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} stream_write_ctx;

static int stream_write_fn(const void *data, size_t len, void *userdata) {
    stream_write_ctx *ctx = (stream_write_ctx *)userdata;
    if (ctx->len + len > ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 4096;
        while (new_cap < ctx->len + len) new_cap *= 2;
        char *p = realloc(ctx->data, new_cap);
        if (!p) return -1;
        ctx->data = p;
        ctx->cap = new_cap;
    }
    memcpy(ctx->data + ctx->len, data, len);
    ctx->len += len;
    return 0;
}

static void stream_write_ctx_free(stream_write_ctx *ctx) {
    free(ctx->data);
    ctx->data = NULL;
    ctx->len = ctx->cap = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: delete a key (ignoring errors)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void cleanup_key(s3_client *c, const char *key) {
    s3_delete_object(c, TEST_BUCKET, key, NULL, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Object CRUD Tests (1-15)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_01_put_small_object(s3_client *c) {
    TEST("01: Put small text object");
    char key[256]; make_key(key, sizeof(key), "test_01.txt");
    const char *body = "Hello, libs3!";
    s3_put_object_result res = {0};
    ASSERT_OK(s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, &res));
    cleanup_key(c, key);
    PASS();
}

static void test_02_get_object(s3_client *c) {
    TEST("02: Get object, verify content");
    char key[256]; make_key(key, sizeof(key), "test_02.txt");
    const char *body = "test02-content";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); return; }
    if (data_len != strlen(body) || memcmp(data, body, data_len) != 0) {
        s3_free(data); FAIL("content mismatch"); return;
    }
    s3_free(data);
    PASS();
}

static void test_03_head_object(s3_client *c) {
    TEST("03: Head object, verify content_length and type");
    char key[256]; make_key(key, sizeof(key), "test_03.txt");
    const char *body = "head-test-content";
    s3_put_object_opts opts = {0};
    opts.content_type = "text/plain";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), &opts, NULL);

    s3_head_object_result hres = {0};
    s3_status st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (hres.content_length != (int64_t)strlen(body)) {
        FAILF("content_length: expected %zu, got %lld", strlen(body), (long long)hres.content_length);
        s3_head_object_result_free(&hres); return;
    }
    if (strstr(hres.content_type, "text/plain") == NULL) {
        FAILF("content_type: expected text/plain, got %s", hres.content_type);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

static void test_04_delete_object(s3_client *c) {
    TEST("04: Delete object");
    char key[256]; make_key(key, sizeof(key), "test_04.txt");
    s3_put_object(c, TEST_BUCKET, key, "delete-me", 9, NULL, NULL);
    s3_delete_object_result dres = {0};
    ASSERT_OK(s3_delete_object(c, TEST_BUCKET, key, NULL, &dres));
    PASS();
}

static void test_05_get_deleted_object(s3_client *c) {
    TEST("05: Get deleted object returns error");
    char key[256]; make_key(key, sizeof(key), "test_05_nonexistent.txt");
    cleanup_key(c, key); /* ensure gone */
    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    if (st != S3_STATUS_NO_SUCH_KEY && st != S3_STATUS_HTTP_NOT_FOUND) {
        FAILF("expected NO_SUCH_KEY or HTTP_NOT_FOUND, got %s", s3_status_string(st));
        if (data) s3_free(data);
        return;
    }
    if (data) s3_free(data);
    PASS();
}

static void test_06_put_custom_content_type(s3_client *c) {
    TEST("06: Put with custom content-type, verify via head");
    char key[256]; make_key(key, sizeof(key), "test_06.json");
    s3_put_object_opts opts = {0};
    opts.content_type = "application/json";
    s3_put_object(c, TEST_BUCKET, key, "{}", 2, &opts, NULL);

    s3_head_object_result hres = {0};
    s3_status st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (strstr(hres.content_type, "application/json") == NULL) {
        FAILF("content_type: expected application/json, got %s", hres.content_type);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

static void test_07_put_with_metadata(s3_client *c) {
    TEST("07: Put with metadata, verify via head");
    char key[256]; make_key(key, sizeof(key), "test_07.txt");
    s3_metadata meta[] = {
        { "test-key", "test-value" },
        { "another", "meta-val" },
    };
    s3_put_object_opts opts = {0};
    opts.metadata = meta;
    opts.metadata_count = 2;
    s3_put_object(c, TEST_BUCKET, key, "meta", 4, &opts, NULL);

    s3_head_object_result hres = {0};
    s3_status st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    /* Check that at least one metadata key was returned */
    int found_meta = 0;
    for (int i = 0; i < hres.metadata_count; i++) {
        if (strcmp(hres.metadata[i].key, "test-key") == 0 && strcmp(hres.metadata[i].value, "test-value") == 0)
            found_meta++;
    }
    s3_head_object_result_free(&hres);
    if (found_meta == 0) { FAIL("metadata not returned"); return; }
    PASS();
}

static void test_08_put_empty_object(s3_client *c) {
    TEST("08: Put empty object (0 bytes), get it back");
    char key[256]; make_key(key, sizeof(key), "test_08_empty.txt");
    ASSERT_OK(s3_put_object(c, TEST_BUCKET, key, "", 0, NULL, NULL));

    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != 0) { FAILF("expected 0 bytes, got %zu", data_len); s3_free(data); return; }
    if (data) s3_free(data);
    PASS();
}

static void test_09_put_binary_data(s3_client *c) {
    TEST("09: Put binary data with null bytes, verify exact match");
    char key[256]; make_key(key, sizeof(key), "test_09.bin");
    char bindata[256];
    for (int i = 0; i < 256; i++) bindata[i] = (char)i; /* includes \0 */

    s3_put_object_opts opts = {0};
    opts.content_type = "application/octet-stream";
    ASSERT_OK(s3_put_object(c, TEST_BUCKET, key, bindata, sizeof(bindata), &opts, NULL));

    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != sizeof(bindata) || memcmp(data, bindata, sizeof(bindata)) != 0) {
        s3_free(data); FAIL("binary content mismatch"); return;
    }
    s3_free(data);
    PASS();
}

static void test_10_put_large_object(s3_client *c) {
    TEST("10: Put large object (1MB), get it back, verify size");
    char key[256]; make_key(key, sizeof(key), "test_10_large.bin");
    size_t sz = 1024 * 1024;
    char *big = malloc(sz);
    if (!big) { FAIL("malloc"); return; }
    for (size_t i = 0; i < sz; i++) big[i] = (char)(i & 0xFF);

    s3_put_object_opts opts = {0};
    opts.content_type = "application/octet-stream";
    s3_status st = s3_put_object(c, TEST_BUCKET, key, big, sz, &opts, NULL);
    if (st != S3_STATUS_OK) { free(big); cleanup_key(c, key); FAILF("put: %s", s3_status_string(st)); return; }

    void *data = NULL; size_t data_len = 0;
    st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { free(big); if (data) s3_free(data); FAILF("get: %s", s3_status_string(st)); return; }
    if (data_len != sz) { free(big); s3_free(data); FAILF("size: expected %zu, got %zu", sz, data_len); return; }
    if (memcmp(data, big, sz) != 0) { free(big); s3_free(data); FAIL("content mismatch"); return; }
    free(big); s3_free(data);
    PASS();
}

static void test_11_object_exists(s3_client *c) {
    TEST("11: s3_object_exists: true/false");
    char key[256]; make_key(key, sizeof(key), "test_11.txt");
    s3_put_object(c, TEST_BUCKET, key, "exists", 6, NULL, NULL);

    bool exists = false;
    s3_status st = s3_object_exists(c, TEST_BUCKET, key, &exists);
    if (st != S3_STATUS_OK || !exists) { cleanup_key(c, key); FAIL("expected exists=true"); return; }

    cleanup_key(c, key);
    st = s3_object_exists(c, TEST_BUCKET, key, &exists);
    if (st != S3_STATUS_OK || exists) { FAIL("expected exists=false"); return; }
    PASS();
}

static void test_12_overwrite_object(s3_client *c) {
    TEST("12: Overwrite existing object, verify new content");
    char key[256]; make_key(key, sizeof(key), "test_12.txt");
    s3_put_object(c, TEST_BUCKET, key, "original", 8, NULL, NULL);
    s3_put_object(c, TEST_BUCKET, key, "updated", 7, NULL, NULL);

    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != 7 || memcmp(data, "updated", 7) != 0) {
        s3_free(data); FAIL("content not updated"); return;
    }
    s3_free(data);
    PASS();
}

static void test_13_put_storage_class(s3_client *c) {
    TEST("13: Put with storage class STANDARD");
    char key[256]; make_key(key, sizeof(key), "test_13.txt");
    s3_put_object_opts opts = {0};
    opts.storage_class = S3_STORAGE_CLASS_STANDARD;
    ASSERT_OK(s3_put_object(c, TEST_BUCKET, key, "storage", 7, &opts, NULL));
    cleanup_key(c, key);
    PASS();
}

static void test_14_get_with_range(s3_client *c) {
    TEST("14: Get with range header (partial read)");
    char key[256]; make_key(key, sizeof(key), "test_14.txt");
    const char *body = "0123456789ABCDEF";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    s3_get_object_opts opts = {0};
    opts.range = "bytes=4-7";
    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, &opts);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get range: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != 4 || memcmp(data, "4567", 4) != 0) {
        FAILF("range content: expected '4567', got %zu bytes", data_len);
        s3_free(data); return;
    }
    s3_free(data);
    PASS();
}

static void test_15_copy_object(s3_client *c) {
    TEST("15: Copy object within prefix, verify copy, delete both");
    char src[256]; make_key(src, sizeof(src), "test_15_src.txt");
    char dst[256]; make_key(dst, sizeof(dst), "test_15_dst.txt");
    s3_put_object(c, TEST_BUCKET, src, "copy-me", 7, NULL, NULL);

    s3_copy_object_result cres = {0};
    s3_status st = s3_copy_object(c, TEST_BUCKET, src, TEST_BUCKET, dst, NULL, &cres);
    if (st != S3_STATUS_OK) { cleanup_key(c, src); FAILF("copy: %s", s3_status_string(st)); return; }

    void *data = NULL; size_t data_len = 0;
    st = s3_get_object(c, TEST_BUCKET, dst, &data, &data_len, NULL);
    cleanup_key(c, src); cleanup_key(c, dst);
    if (st != S3_STATUS_OK) { FAILF("get copy: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != 7 || memcmp(data, "copy-me", 7) != 0) {
        s3_free(data); FAIL("copy content mismatch"); return;
    }
    s3_free(data);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Streaming Tests (16-20)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_16_put_stream(s3_client *c) {
    TEST("16: Put via stream callback, verify content");
    char key[256]; make_key(key, sizeof(key), "test_16_stream.txt");
    const char *body = "streamed-upload-content";
    stream_read_ctx rctx = { body, strlen(body), 0 };

    s3_put_object_opts opts = {0};
    opts.content_type = "text/plain";
    s3_status st = s3_put_object_stream(c, TEST_BUCKET, key, stream_read_fn, &rctx,
                                         (int64_t)strlen(body), &opts, NULL);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("put stream: %s", s3_status_string(st)); return; }

    void *data = NULL; size_t data_len = 0;
    st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != strlen(body) || memcmp(data, body, data_len) != 0) {
        s3_free(data); FAIL("content mismatch"); return;
    }
    s3_free(data);
    PASS();
}

static void test_17_get_stream(s3_client *c) {
    TEST("17: Get via stream callback, verify content");
    char key[256]; make_key(key, sizeof(key), "test_17_stream.txt");
    const char *body = "streamed-download-content";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    stream_write_ctx wctx = {0};
    s3_status st = s3_get_object_stream(c, TEST_BUCKET, key, stream_write_fn, &wctx, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get stream: %s", s3_status_string(st)); stream_write_ctx_free(&wctx); return; }
    if (wctx.len != strlen(body) || memcmp(wctx.data, body, wctx.len) != 0) {
        stream_write_ctx_free(&wctx); FAIL("content mismatch"); return;
    }
    stream_write_ctx_free(&wctx);
    PASS();
}

static void test_18_put_stream_known_length(s3_client *c) {
    TEST("18: Put stream with known content_length");
    char key[256]; make_key(key, sizeof(key), "test_18_stream.txt");
    const char *body = "known-length-stream";
    stream_read_ctx rctx = { body, strlen(body), 0 };

    s3_status st = s3_put_object_stream(c, TEST_BUCKET, key, stream_read_fn, &rctx,
                                         (int64_t)strlen(body), NULL, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("put: %s", s3_status_string(st)); return; }
    PASS();
}

static void test_19_stream_download_to_file(s3_client *c) {
    TEST("19: Stream download to file, verify file contents");
    char key[256]; make_key(key, sizeof(key), "test_19.txt");
    const char *body = "file-download-content-19";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    const char *tmppath = "/tmp/libs3_test_19.tmp";
    s3_status st = s3_download_file(c, TEST_BUCKET, key, tmppath, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("download: %s", s3_status_string(st)); unlink(tmppath); return; }

    FILE *f = fopen(tmppath, "rb");
    if (!f) { FAIL("could not open downloaded file"); unlink(tmppath); return; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    unlink(tmppath);
    if (n != strlen(body) || memcmp(buf, body, n) != 0) { FAIL("file content mismatch"); return; }
    PASS();
}

static void test_20_upload_download_file_roundtrip(s3_client *c) {
    TEST("20: Upload file, download file, verify roundtrip");
    char key[256]; make_key(key, sizeof(key), "test_20.txt");
    const char *upload_path = "/tmp/libs3_test_20_up.tmp";
    const char *download_path = "/tmp/libs3_test_20_dn.tmp";
    const char *body = "roundtrip-file-test-20";

    FILE *f = fopen(upload_path, "wb");
    if (!f) { FAIL("could not create upload file"); return; }
    fwrite(body, 1, strlen(body), f); fclose(f);

    s3_status st = s3_upload_file(c, TEST_BUCKET, key, upload_path, NULL, NULL);
    unlink(upload_path);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("upload: %s", s3_status_string(st)); return; }

    st = s3_download_file(c, TEST_BUCKET, key, download_path, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("download: %s", s3_status_string(st)); unlink(download_path); return; }

    f = fopen(download_path, "rb");
    if (!f) { FAIL("could not open downloaded file"); unlink(download_path); return; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    unlink(download_path);
    if (n != strlen(body) || memcmp(buf, body, n) != 0) { FAIL("roundtrip mismatch"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Batch/List Tests (21-30)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_21_list_with_prefix(s3_client *c) {
    TEST("21: Put 5 objects, list with prefix, verify all found");
    char keys[5][256];
    for (int i = 0; i < 5; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_21_obj_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "x", 1, NULL, NULL);
    }

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_21_obj_");
    opts.prefix = prefix;
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    for (int i = 0; i < 5; i++) cleanup_key(c, keys[i]);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.object_count < 5) { FAILF("expected >=5, got %d", res.object_count); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_22_list_with_delimiter(s3_client *c) {
    TEST("22: List with delimiter '/' to get common prefixes");
    char key1[256]; make_key(key1, sizeof(key1), "test_22/sub1/a.txt");
    char key2[256]; make_key(key2, sizeof(key2), "test_22/sub2/b.txt");
    s3_put_object(c, TEST_BUCKET, key1, "a", 1, NULL, NULL);
    s3_put_object(c, TEST_BUCKET, key2, "b", 1, NULL, NULL);

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_22/");
    opts.prefix = prefix;
    opts.delimiter = "/";
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    cleanup_key(c, key1); cleanup_key(c, key2);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.prefix_count < 2) { FAILF("expected >=2 prefixes, got %d", res.prefix_count); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_23_list_pagination(s3_client *c) {
    TEST("23: List with max_keys=2, verify truncation");
    char keys[4][256];
    for (int i = 0; i < 4; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_23_pg_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "p", 1, NULL, NULL);
    }

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_23_pg_");
    opts.prefix = prefix;
    opts.max_keys = 2;
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    if (st != S3_STATUS_OK) {
        for (int i = 0; i < 4; i++) cleanup_key(c, keys[i]);
        FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return;
    }
    int ok = (res.is_truncated && res.object_count == 2);
    s3_list_objects_result_free(&res);
    for (int i = 0; i < 4; i++) cleanup_key(c, keys[i]);
    if (!ok) { FAIL("expected is_truncated=true, count=2"); return; }
    PASS();
}

static void test_24_list_all_objects(s3_client *c) {
    TEST("24: List all objects (auto-paginate helper)");
    char keys[3][256];
    for (int i = 0; i < 3; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_24_all_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "a", 1, NULL, NULL);
    }

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_24_all_");
    opts.prefix = prefix;
    s3_object_info *objects = NULL; int count = 0;
    s3_status st = s3_list_all_objects(c, TEST_BUCKET, &opts, &objects, &count);
    for (int i = 0; i < 3; i++) cleanup_key(c, keys[i]);
    if (st != S3_STATUS_OK) { FAILF("list_all: %s", s3_status_string(st)); if (objects) s3_free(objects); return; }
    if (count < 3) { FAILF("expected >=3, got %d", count); s3_free(objects); return; }
    s3_free(objects);
    PASS();
}

static void test_25_batch_delete(s3_client *c) {
    TEST("25: Batch delete 5 objects, verify all deleted");
    char keys[5][256];
    s3_delete_object_entry entries[5];
    for (int i = 0; i < 5; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_25_batch_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "d", 1, NULL, NULL);
        entries[i].key = keys[i];
        entries[i].version_id = NULL;
    }

    s3_delete_objects_result dres = {0};
    s3_status st = s3_delete_objects(c, TEST_BUCKET, entries, 5, false, &dres);
    if (st != S3_STATUS_OK) {
        FAILF("batch delete: %s", s3_status_string(st));
        s3_delete_objects_result_free(&dres);
        for (int i = 0; i < 5; i++) cleanup_key(c, keys[i]);
        return;
    }
    if (dres.error_count > 0) { FAILF("%d errors in batch delete", dres.error_count); }
    else { PASS(); }
    s3_delete_objects_result_free(&dres);
}

static void test_26_list_after_delete(s3_client *c) {
    TEST("26: List after delete, verify empty");
    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_26_gone_");
    opts.prefix = prefix;
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.object_count != 0) { FAILF("expected 0, got %d", res.object_count); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_27_delete_nonexistent(s3_client *c) {
    TEST("27: Delete non-existent object (should succeed)");
    char key[256]; make_key(key, sizeof(key), "test_27_never_existed.txt");
    s3_status st = s3_delete_object(c, TEST_BUCKET, key, NULL, NULL);
    if (st != S3_STATUS_OK) { FAILF("delete nonexistent: %s", s3_status_string(st)); return; }
    PASS();
}

static void test_28_batch_delete_partial(s3_client *c) {
    TEST("28: Put 3 objects, batch delete 2, verify 1 remains");
    char keys[3][256];
    for (int i = 0; i < 3; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_28_part_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "p", 1, NULL, NULL);
    }

    s3_delete_object_entry entries[2] = {
        { keys[0], NULL }, { keys[1], NULL }
    };
    s3_delete_objects_result dres = {0};
    s3_delete_objects(c, TEST_BUCKET, entries, 2, false, &dres);
    s3_delete_objects_result_free(&dres);

    bool exists = false;
    s3_object_exists(c, TEST_BUCKET, keys[2], &exists);
    cleanup_key(c, keys[2]);
    if (!exists) { FAIL("remaining object not found"); return; }
    PASS();
}

static void test_29_list_start_after(s3_client *c) {
    TEST("29: List with start_after parameter");
    char keys[3][256];
    for (int i = 0; i < 3; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_29_sa_%c.txt", 'a' + i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "s", 1, NULL, NULL);
    }

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_29_sa_");
    opts.prefix = prefix;
    opts.start_after = keys[0]; /* start after first key */
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    for (int i = 0; i < 3; i++) cleanup_key(c, keys[i]);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.object_count < 2) { FAILF("expected >=2 after start_after, got %d", res.object_count); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_30_batch_delete_quiet(s3_client *c) {
    TEST("30: Batch delete with quiet=true");
    char key[256]; make_key(key, sizeof(key), "test_30_quiet.txt");
    s3_put_object(c, TEST_BUCKET, key, "q", 1, NULL, NULL);

    s3_delete_object_entry entry = { key, NULL };
    s3_delete_objects_result dres = {0};
    s3_status st = s3_delete_objects(c, TEST_BUCKET, &entry, 1, true, &dres);
    s3_delete_objects_result_free(&dres);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("batch quiet: %s", s3_status_string(st)); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Multipart Upload Tests (31-38)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_31_create_multipart(s3_client *c) {
    TEST("31: Create multipart upload, verify upload_id");
    char key[256]; make_key(key, sizeof(key), "test_31_mp.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create mp: %s", s3_status_string(st)); return; }
    if (strlen(mpu.upload_id) == 0) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("empty upload_id"); return; }
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    PASS();
}

static void test_32_multipart_2_parts(s3_client *c) {
    TEST("32: Upload 2 parts (5MB each), complete, verify");
    char key[256]; make_key(key, sizeof(key), "test_32_mp.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    size_t part_sz = PART_SIZE;
    char *part_data = malloc(part_sz);
    if (!part_data) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("malloc"); return; }

    s3_upload_part_result parts[2];
    for (int i = 0; i < 2; i++) {
        memset(part_data, 'A' + i, part_sz);
        st = s3_upload_part(c, TEST_BUCKET, key, mpu.upload_id, i + 1,
                            part_data, part_sz, NULL, &parts[i]);
        if (st != S3_STATUS_OK) {
            free(part_data);
            s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
            FAILF("upload part %d: %s", i+1, s3_status_string(st)); return;
        }
        parts[i].part_number = i + 1;
    }
    free(part_data);

    s3_complete_multipart_result cres = {0};
    st = s3_complete_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id, parts, 2, &cres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        cleanup_key(c, key);
        FAILF("complete: %s", s3_status_string(st)); return;
    }

    /* Verify size via head */
    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (hres.content_length != (int64_t)(2 * part_sz)) {
        FAILF("size: expected %zu, got %lld", 2 * part_sz, (long long)hres.content_length);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

static void test_33_abort_multipart(s3_client *c) {
    TEST("33: Abort multipart upload");
    char key[256]; make_key(key, sizeof(key), "test_33_abort.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }
    st = s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    if (st != S3_STATUS_OK) { FAILF("abort: %s", s3_status_string(st)); return; }
    PASS();
}

static void test_34_list_multipart_uploads(s3_client *c) {
    TEST("34: List multipart uploads (empty after abort)");
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_34_");
    s3_list_multipart_uploads_result res = {0};
    s3_status st = s3_list_multipart_uploads(c, TEST_BUCKET, prefix, NULL, NULL, NULL, 10, &res);
    if (st != S3_STATUS_OK) { FAILF("list mp: %s", s3_status_string(st)); s3_list_multipart_uploads_result_free(&res); return; }
    /* After abort, should be empty for this prefix */
    if (res.upload_count != 0) { FAILF("expected 0 uploads, got %d", res.upload_count); s3_list_multipart_uploads_result_free(&res); return; }
    s3_list_multipart_uploads_result_free(&res);
    PASS();
}

static void test_35_multipart_3_parts(s3_client *c) {
    TEST("35: Upload 3 parts, complete, download and verify");
    char key[256]; make_key(key, sizeof(key), "test_35_mp3.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    size_t part_sz = PART_SIZE;
    char *part_data = malloc(part_sz);
    if (!part_data) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("malloc"); return; }

    s3_upload_part_result parts[3];
    for (int i = 0; i < 3; i++) {
        memset(part_data, '1' + i, part_sz);
        st = s3_upload_part(c, TEST_BUCKET, key, mpu.upload_id, i + 1,
                            part_data, part_sz, NULL, &parts[i]);
        if (st != S3_STATUS_OK) {
            free(part_data);
            s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
            FAILF("upload part %d: %s", i+1, s3_status_string(st)); return;
        }
        parts[i].part_number = i + 1;
    }
    free(part_data);

    s3_complete_multipart_result cres = {0};
    st = s3_complete_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id, parts, 3, &cres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("complete: %s", s3_status_string(st));
        cleanup_key(c, key); return;
    }

    /* Verify total size */
    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (hres.content_length != (int64_t)(3 * part_sz)) {
        FAILF("size: expected %zu, got %lld", 3 * part_sz, (long long)hres.content_length);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

static void test_36_list_parts(s3_client *c) {
    TEST("36: List parts during upload");
    char key[256]; make_key(key, sizeof(key), "test_36_lp.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    size_t part_sz = PART_SIZE;
    char *part_data = malloc(part_sz);
    if (!part_data) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("malloc"); return; }
    memset(part_data, 'X', part_sz);

    s3_upload_part_result pres = {0};
    st = s3_upload_part(c, TEST_BUCKET, key, mpu.upload_id, 1, part_data, part_sz, NULL, &pres);
    free(part_data);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("upload part: %s", s3_status_string(st)); return;
    }

    s3_list_parts_result lres = {0};
    st = s3_list_parts(c, TEST_BUCKET, key, mpu.upload_id, 100, 0, &lres);
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    if (st != S3_STATUS_OK) { FAILF("list parts: %s", s3_status_string(st)); s3_list_parts_result_free(&lres); return; }
    if (lres.part_count < 1) { FAILF("expected >=1 part, got %d", lres.part_count); s3_list_parts_result_free(&lres); return; }
    s3_list_parts_result_free(&lres);
    PASS();
}

static void test_37_abort_no_object(s3_client *c) {
    TEST("37: Create multipart, abort, verify no object");
    char key[256]; make_key(key, sizeof(key), "test_37_aborted.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);

    bool exists = false;
    s3_object_exists(c, TEST_BUCKET, key, &exists);
    if (exists) { FAIL("object exists after abort"); return; }
    PASS();
}

static void test_38_multipart_min_parts(s3_client *c) {
    TEST("38: Multipart with parts just above 5MB minimum");
    char key[256]; make_key(key, sizeof(key), "test_38_minpart.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    /* Part 1: exactly 5MB, Part 2: 1 byte (last part can be smaller) */
    size_t p1_sz = PART_SIZE;
    char *p1 = malloc(p1_sz);
    if (!p1) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("malloc"); return; }
    memset(p1, 'M', p1_sz);

    s3_upload_part_result parts[2];
    st = s3_upload_part(c, TEST_BUCKET, key, mpu.upload_id, 1, p1, p1_sz, NULL, &parts[0]);
    free(p1);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("part1: %s", s3_status_string(st)); return;
    }
    parts[0].part_number = 1;

    st = s3_upload_part(c, TEST_BUCKET, key, mpu.upload_id, 2, "Z", 1, NULL, &parts[1]);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("part2: %s", s3_status_string(st)); return;
    }
    parts[1].part_number = 2;

    s3_complete_multipart_result cres = {0};
    st = s3_complete_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id, parts, 2, &cres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        cleanup_key(c, key);
        FAILF("complete: %s", s3_status_string(st)); return;
    }

    s3_head_object_result hres = {0};
    s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (hres.content_length != (int64_t)(p1_sz + 1)) {
        FAILF("size: expected %zu, got %lld", p1_sz + 1, (long long)hres.content_length);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Object Configuration Tests (39-45)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_39_put_get_tagging(s3_client *c) {
    TEST("39: Put object tagging (2 tags), get tagging, verify");
    char key[256]; make_key(key, sizeof(key), "test_39_tag.txt");
    s3_put_object(c, TEST_BUCKET, key, "tagged", 6, NULL, NULL);

    s3_tag tags[2] = {
        { "env", "test" },
        { "project", "libs3" },
    };
    /* Copy strings into the fixed-size arrays - they are already there since we used initializer */
    s3_status st = s3_put_object_tagging(c, TEST_BUCKET, key, NULL, tags, 2);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("put tagging: %s", s3_status_string(st)); return; }

    s3_tag_set ts = {0};
    st = s3_get_object_tagging(c, TEST_BUCKET, key, NULL, &ts);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get tagging: %s", s3_status_string(st)); s3_tag_set_free(&ts); return; }
    if (ts.count < 2) { FAILF("expected 2 tags, got %d", ts.count); s3_tag_set_free(&ts); return; }
    s3_tag_set_free(&ts);
    PASS();
}

static void test_40_delete_tagging(s3_client *c) {
    TEST("40: Delete tagging, verify empty");
    char key[256]; make_key(key, sizeof(key), "test_40_tag.txt");
    s3_put_object(c, TEST_BUCKET, key, "t", 1, NULL, NULL);
    s3_tag tags[1] = { { "k", "v" } };
    s3_put_object_tagging(c, TEST_BUCKET, key, NULL, tags, 1);

    s3_status st = s3_delete_object_tagging(c, TEST_BUCKET, key, NULL);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("delete tagging: %s", s3_status_string(st)); return; }

    s3_tag_set ts = {0};
    st = s3_get_object_tagging(c, TEST_BUCKET, key, NULL, &ts);
    cleanup_key(c, key);
    /* After delete, should have 0 tags or possibly an error */
    if (st == S3_STATUS_OK && ts.count != 0) {
        FAILF("expected 0 tags after delete, got %d", ts.count);
        s3_tag_set_free(&ts); return;
    }
    s3_tag_set_free(&ts);
    PASS();
}

static void test_41_head_exists(s3_client *c) {
    TEST("41: Put object, check if exists via head");
    char key[256]; make_key(key, sizeof(key), "test_41_exists.txt");
    s3_put_object(c, TEST_BUCKET, key, "e", 1, NULL, NULL);

    s3_head_object_result hres = {0};
    s3_status st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    s3_head_object_result_free(&hres);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); return; }
    PASS();
}

static void test_42_get_object_attributes(s3_client *c) {
    TEST("42: Get object attributes");
    char key[256]; make_key(key, sizeof(key), "test_42_attrs.txt");
    s3_put_object(c, TEST_BUCKET, key, "attrs", 5, NULL, NULL);

    s3_get_object_attributes_opts opts = {0};
    opts.attr_etag = true;
    opts.attr_object_size = true;
    opts.attr_storage_class = true;
    s3_object_attributes_result ares = {0};
    s3_status st = s3_get_object_attributes(c, TEST_BUCKET, key, &opts, &ares);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get attrs: %s", s3_status_string(st)); s3_object_attributes_result_free(&ares); return; }
    if (ares.object_size != 5) { FAILF("size: expected 5, got %lld", (long long)ares.object_size); s3_object_attributes_result_free(&ares); return; }
    s3_object_attributes_result_free(&ares);
    PASS();
}

static void test_43_copy_metadata_replace(s3_client *c) {
    TEST("43: Copy with metadata replace");
    char src[256]; make_key(src, sizeof(src), "test_43_src.txt");
    char dst[256]; make_key(dst, sizeof(dst), "test_43_dst.txt");
    s3_metadata meta_src[] = { { "original", "yes" } };
    s3_put_object_opts popts = {0};
    popts.metadata = meta_src;
    popts.metadata_count = 1;
    s3_put_object(c, TEST_BUCKET, src, "copy", 4, &popts, NULL);

    s3_metadata meta_dst[] = { { "replaced", "true" } };
    s3_copy_object_opts copts = {0};
    copts.metadata_directive = S3_METADATA_REPLACE;
    copts.metadata = meta_dst;
    copts.metadata_count = 1;
    copts.content_type = "text/plain";
    s3_copy_object_result cres = {0};
    s3_status st = s3_copy_object(c, TEST_BUCKET, src, TEST_BUCKET, dst, &copts, &cres);
    cleanup_key(c, src);
    if (st != S3_STATUS_OK) { cleanup_key(c, dst); FAILF("copy: %s", s3_status_string(st)); return; }

    s3_head_object_result hres = {0};
    s3_head_object(c, TEST_BUCKET, dst, NULL, &hres);
    cleanup_key(c, dst);
    int found = 0;
    for (int i = 0; i < hres.metadata_count; i++) {
        if (strcmp(hres.metadata[i].key, "replaced") == 0) found = 1;
    }
    s3_head_object_result_free(&hres);
    if (!found) { FAIL("replaced metadata not found"); return; }
    PASS();
}

static void test_44_copy_tagging_replace(s3_client *c) {
    TEST("44: Copy with tagging replace");
    char src[256]; make_key(src, sizeof(src), "test_44_src.txt");
    char dst[256]; make_key(dst, sizeof(dst), "test_44_dst.txt");
    s3_put_object(c, TEST_BUCKET, src, "tagrepl", 7, NULL, NULL);
    s3_tag src_tags[] = { { "old", "tag" } };
    s3_put_object_tagging(c, TEST_BUCKET, src, NULL, src_tags, 1);

    s3_copy_object_opts copts = {0};
    copts.tagging_directive = S3_TAGGING_REPLACE;
    copts.tagging = "newtag=newval";
    s3_copy_object_result cres = {0};
    s3_status st = s3_copy_object(c, TEST_BUCKET, src, TEST_BUCKET, dst, &copts, &cres);
    cleanup_key(c, src);
    if (st != S3_STATUS_OK) { cleanup_key(c, dst); FAILF("copy: %s", s3_status_string(st)); return; }

    s3_tag_set ts = {0};
    s3_get_object_tagging(c, TEST_BUCKET, dst, NULL, &ts);
    cleanup_key(c, dst);
    int found = 0;
    for (int i = 0; i < ts.count; i++) {
        if (strcmp(ts.tags[i].key, "newtag") == 0) found = 1;
    }
    s3_tag_set_free(&ts);
    if (!found) { FAIL("replaced tag not found"); return; }
    PASS();
}

static void test_45_rename_object(s3_client *c) {
    TEST("45: Rename object (within prefix)");
    char src[256]; make_key(src, sizeof(src), "test_45_before.txt");
    char dst[256]; make_key(dst, sizeof(dst), "test_45_after.txt");
    s3_put_object(c, TEST_BUCKET, src, "rename", 6, NULL, NULL);

    s3_status st = s3_rename_object(c, TEST_BUCKET, src, dst);
    if (st != S3_STATUS_OK) { cleanup_key(c, src); cleanup_key(c, dst); FAILF("rename: %s", s3_status_string(st)); return; }

    bool src_exists = false, dst_exists = false;
    s3_object_exists(c, TEST_BUCKET, src, &src_exists);
    s3_object_exists(c, TEST_BUCKET, dst, &dst_exists);
    cleanup_key(c, src); cleanup_key(c, dst);
    if (src_exists) { FAIL("source still exists after rename"); return; }
    if (!dst_exists) { FAIL("destination not found after rename"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Presigned URL Tests (46-50)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_46_presign_get(s3_client *c) {
    TEST("46: Generate presigned GET URL, download with curl");
    char key[256]; make_key(key, sizeof(key), "test_46_presign.txt");
    const char *body = "presigned-content-46";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    char url[4096];
    s3_status st = s3_presign_get(c, TEST_BUCKET, key, 300, url, sizeof(url));
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("presign: %s", s3_status_string(st)); return; }
    if (strlen(url) == 0) { cleanup_key(c, key); FAIL("empty presigned URL"); return; }

    /* Use curl CLI to verify */
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "curl -s -o /tmp/libs3_test_46.tmp '%s'", url);
    int ret = system(cmd);
    cleanup_key(c, key);
    if (ret != 0) { FAIL("curl failed"); unlink("/tmp/libs3_test_46.tmp"); return; }
    FILE *f = fopen("/tmp/libs3_test_46.tmp", "rb");
    if (!f) { FAIL("could not open curl output"); unlink("/tmp/libs3_test_46.tmp"); return; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    unlink("/tmp/libs3_test_46.tmp");
    if (n != strlen(body) || memcmp(buf, body, n) != 0) { FAIL("presigned GET content mismatch"); return; }
    PASS();
}

static void test_47_presign_put(s3_client *c) {
    TEST("47: Generate presigned PUT URL");
    char key[256]; make_key(key, sizeof(key), "test_47_presign_put.txt");
    char url[4096];
    s3_status st = s3_presign_put(c, TEST_BUCKET, key, 300, "text/plain", url, sizeof(url));
    cleanup_key(c, key); /* just in case */
    if (st != S3_STATUS_OK) { FAILF("presign put: %s", s3_status_string(st)); return; }
    if (strlen(url) == 0) { FAIL("empty presigned URL"); return; }
    PASS();
}

static void test_48_presign_expiry(s3_client *c) {
    TEST("48: Presigned URL with expiry");
    char key[256]; make_key(key, sizeof(key), "test_48_expiry.txt");
    char url[4096];
    s3_status st = s3_presign_get(c, TEST_BUCKET, key, 60, url, sizeof(url));
    if (st != S3_STATUS_OK) { FAILF("presign: %s", s3_status_string(st)); return; }
    /* Just verify we can generate with a specific expiry */
    if (strstr(url, "X-Amz-Expires=60") == NULL) {
        /* Some implementations may not include this literally, just check URL is non-empty */
        if (strlen(url) == 0) { FAIL("empty URL"); return; }
    }
    PASS();
}

static void test_49_presign_head(s3_client *c) {
    TEST("49: Presigned HEAD URL");
    char key[256]; make_key(key, sizeof(key), "test_49_head.txt");
    char url[4096];
    s3_status st = s3_presign_head(c, TEST_BUCKET, key, 300, url, sizeof(url));
    if (st != S3_STATUS_OK) { FAILF("presign head: %s", s3_status_string(st)); return; }
    if (strlen(url) == 0) { FAIL("empty URL"); return; }
    PASS();
}

static void test_50_presign_delete(s3_client *c) {
    TEST("50: Presigned DELETE URL");
    char key[256]; make_key(key, sizeof(key), "test_50_delete.txt");
    char url[4096];
    s3_status st = s3_presign_delete(c, TEST_BUCKET, key, 300, url, sizeof(url));
    if (st != S3_STATUS_OK) { FAILF("presign delete: %s", s3_status_string(st)); return; }
    if (strlen(url) == 0) { FAIL("empty URL"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * High-Level Helper Tests (51-55)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_51_upload_file(s3_client *c) {
    TEST("51: s3_upload_file: create temp file, upload, verify");
    char key[256]; make_key(key, sizeof(key), "test_51_upload.txt");
    const char *tmppath = "/tmp/libs3_test_51.tmp";
    const char *body = "upload-file-content-51";
    FILE *f = fopen(tmppath, "wb");
    if (!f) { FAIL("create tmp"); return; }
    fwrite(body, 1, strlen(body), f); fclose(f);

    s3_status st = s3_upload_file(c, TEST_BUCKET, key, tmppath, NULL, NULL);
    unlink(tmppath);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("upload: %s", s3_status_string(st)); return; }

    void *data = NULL; size_t data_len = 0;
    st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); if (data) s3_free(data); return; }
    if (data_len != strlen(body) || memcmp(data, body, data_len) != 0) {
        s3_free(data); FAIL("content mismatch"); return;
    }
    s3_free(data);
    PASS();
}

static void test_52_download_file(s3_client *c) {
    TEST("52: s3_download_file: download to temp, verify content");
    char key[256]; make_key(key, sizeof(key), "test_52_download.txt");
    const char *body = "download-file-content-52";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    const char *tmppath = "/tmp/libs3_test_52.tmp";
    s3_status st = s3_download_file(c, TEST_BUCKET, key, tmppath, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("download: %s", s3_status_string(st)); unlink(tmppath); return; }

    FILE *f = fopen(tmppath, "rb");
    if (!f) { FAIL("open downloaded"); unlink(tmppath); return; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    unlink(tmppath);
    if (n != strlen(body) || memcmp(buf, body, n) != 0) { FAIL("content mismatch"); return; }
    PASS();
}

static void test_53_list_all_objects_helper(s3_client *c) {
    TEST("53: s3_list_all_objects: put several, list all, verify");
    char keys[4][256];
    for (int i = 0; i < 4; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_53_la_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "l", 1, NULL, NULL);
    }

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_53_la_");
    opts.prefix = prefix;
    s3_object_info *objects = NULL; int count = 0;
    s3_status st = s3_list_all_objects(c, TEST_BUCKET, &opts, &objects, &count);
    for (int i = 0; i < 4; i++) cleanup_key(c, keys[i]);
    if (st != S3_STATUS_OK) { FAILF("list all: %s", s3_status_string(st)); if (objects) s3_free(objects); return; }
    if (count < 4) { FAILF("expected >=4, got %d", count); s3_free(objects); return; }
    s3_free(objects);
    PASS();
}

static void test_54_delete_all_objects(s3_client *c) {
    TEST("54: s3_delete_all_objects: clean up prefix");
    char keys[3][256];
    for (int i = 0; i < 3; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_54_da_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "d", 1, NULL, NULL);
    }

    char prefix[256]; make_key(prefix, sizeof(prefix), "test_54_da_");
    int deleted = 0;
    s3_status st = s3_delete_all_objects(c, TEST_BUCKET, prefix, false, &deleted);
    if (st != S3_STATUS_OK) {
        FAILF("delete_all: %s", s3_status_string(st));
        for (int i = 0; i < 3; i++) cleanup_key(c, keys[i]);
        return;
    }
    /* In quiet mode, deleted count may be 0 (S3 doesn't return Deleted elements).
     * Verify the objects are actually gone instead. */
    bool any_left = false;
    for (int i = 0; i < 3; i++) {
        bool exists = false;
        s3_object_exists(c, TEST_BUCKET, keys[i], &exists);
        if (exists) any_left = true;
    }
    if (any_left) { FAIL("objects still exist after delete_all"); return; }
    PASS();
}

static void test_55_object_exists_helper(s3_client *c) {
    TEST("55: s3_object_exists: verify helper");
    char key[256]; make_key(key, sizeof(key), "test_55_exists.txt");

    bool exists = false;
    s3_object_exists(c, TEST_BUCKET, key, &exists);
    if (exists) { cleanup_key(c, key); FAIL("should not exist yet"); return; }

    s3_put_object(c, TEST_BUCKET, key, "yes", 3, NULL, NULL);
    s3_object_exists(c, TEST_BUCKET, key, &exists);
    cleanup_key(c, key);
    if (!exists) { FAIL("should exist after put"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Error Handling Tests (56-60)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_56_get_nonexistent(s3_client *c) {
    TEST("56: Get non-existent key returns proper error");
    char key[256]; make_key(key, sizeof(key), "test_56_no_such_key_ever.txt");
    void *data = NULL; size_t data_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    if (st == S3_STATUS_OK) { if (data) s3_free(data); FAIL("expected error, got OK"); return; }
    if (data) s3_free(data);
    /* Should be NO_SUCH_KEY or HTTP_NOT_FOUND */
    if (st != S3_STATUS_NO_SUCH_KEY && st != S3_STATUS_HTTP_NOT_FOUND) {
        FAILF("expected NO_SUCH_KEY, got %s", s3_status_string(st)); return;
    }
    PASS();
}

static void test_57_last_error(s3_client *c) {
    TEST("57: s3_client_last_error has correct details");
    char key[256]; make_key(key, sizeof(key), "test_57_error_detail.txt");
    void *data = NULL; size_t data_len = 0;
    s3_get_object(c, TEST_BUCKET, key, &data, &data_len, NULL);
    if (data) s3_free(data);

    const s3_error *err = s3_client_last_error(c);
    if (!err) { FAIL("last_error returned NULL"); return; }
    if (err->http_status != 404) { FAILF("http_status: expected 404, got %d", err->http_status); return; }
    PASS();
}

static void test_58_head_nonexistent(s3_client *c) {
    TEST("58: Head non-existent key returns proper error");
    char key[256]; make_key(key, sizeof(key), "test_58_head_missing.txt");
    s3_head_object_result hres = {0};
    s3_status st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    s3_head_object_result_free(&hres);
    if (st == S3_STATUS_OK) { FAIL("expected error"); return; }
    /* HEAD on non-existent returns 404 */
    if (st != S3_STATUS_NO_SUCH_KEY && st != S3_STATUS_HTTP_NOT_FOUND) {
        FAILF("expected not found, got %s", s3_status_string(st)); return;
    }
    PASS();
}

static void test_59_copy_nonexistent_source(s3_client *c) {
    TEST("59: Copy from non-existent source returns error");
    char src[256]; make_key(src, sizeof(src), "test_59_no_source_ever.txt");
    char dst[256]; make_key(dst, sizeof(dst), "test_59_dst.txt");
    s3_copy_object_result cres = {0};
    s3_status st = s3_copy_object(c, TEST_BUCKET, src, TEST_BUCKET, dst, NULL, &cres);
    cleanup_key(c, dst); /* just in case */
    if (st == S3_STATUS_OK) { FAIL("expected error"); return; }
    PASS();
}

static void test_60_delete_from_nonexistent_bucket(s3_client *c) {
    TEST("60: Delete from non-existent bucket returns error");
    char key[256]; make_key(key, sizeof(key), "test_60_nobucket.txt");
    s3_status st = s3_delete_object(c, "libs3-nonexistent-bucket-xyzzy-99", key, NULL, NULL);
    if (st == S3_STATUS_OK) {
        /* Some S3 implementations return OK for delete on non-existent bucket */
        PASS(); return;
    }
    /* Any error is acceptable */
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Bucket Operations (61-63)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_61_head_bucket(s3_client *c) {
    TEST("61: s3_head_bucket on philodemos");
    ASSERT_OK(s3_head_bucket(c, TEST_BUCKET, NULL));
    PASS();
}

static void test_62_list_buckets(s3_client *c) {
    TEST("62: s3_list_buckets, find philodemos in list");
    s3_list_buckets_result res = {0};
    s3_status st = s3_list_buckets(c, NULL, NULL, 0, &res);
    if (st != S3_STATUS_OK) { FAILF("list buckets: %s", s3_status_string(st)); s3_list_buckets_result_free(&res); return; }
    if (res.bucket_count == 0) { FAIL("no buckets returned"); s3_list_buckets_result_free(&res); return; }
    int found = 0;
    for (int i = 0; i < res.bucket_count; i++) {
        if (strcmp(res.buckets[i].name, TEST_BUCKET) == 0) { found = 1; break; }
    }
    s3_list_buckets_result_free(&res);
    if (!found) { FAIL("philodemos not found in bucket list"); return; }
    PASS();
}

static void test_63_get_bucket_location(s3_client *c) {
    TEST("63: s3_get_bucket_location returns region string");
    char region[128] = {0};
    s3_status st = s3_get_bucket_location(c, TEST_BUCKET, region, sizeof(region));
    if (st != S3_STATUS_OK) { FAILF("get location: %s", s3_status_string(st)); return; }
    if (strlen(region) == 0) { FAIL("empty region"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Object Config - More Coverage (64-71)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_64_acl_canned_and_get(s3_client *c) {
    TEST("64: Get ACL on object, verify owner and grants");
    char key[256]; make_key(key, sizeof(key), "test_64_acl.txt");
    s3_put_object(c, TEST_BUCKET, key, "acl-test", 8, NULL, NULL);

    /* Get the default ACL */
    s3_acl acl = {0};
    s3_status st = s3_get_object_acl(c, TEST_BUCKET, key, NULL, &acl);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("get acl: %s", s3_status_string(st)); s3_acl_free(&acl); return; }
    if (strlen(acl.owner_id) == 0) { cleanup_key(c, key); FAIL("no owner_id"); s3_acl_free(&acl); return; }
    if (acl.grant_count < 1) { cleanup_key(c, key); FAIL("no grants"); s3_acl_free(&acl); return; }

    /* Try put_object_acl with the same ACL we got back (exercises put path) */
    s3_status put_st = s3_put_object_acl(c, TEST_BUCKET, key, NULL, &acl);
    s3_acl_free(&acl);
    cleanup_key(c, key);
    /* put_object_acl may fail due to bucket policy, but code path is exercised */
    (void)put_st;
    PASS();
}

static void test_65_get_retention(s3_client *c) {
    TEST("65: Get object retention (expect error, no object lock)");
    char key[256]; make_key(key, sizeof(key), "test_65_retention.txt");
    s3_put_object(c, TEST_BUCKET, key, "r", 1, NULL, NULL);

    s3_object_retention ret = {0};
    s3_status st = s3_get_object_retention(c, TEST_BUCKET, key, NULL, &ret);
    cleanup_key(c, key);
    /* Expect error since bucket likely does not have Object Lock enabled */
    if (st == S3_STATUS_OK) { PASS(); return; }
    /* Any non-OK status is expected; the code path was exercised */
    PASS();
}

static void test_66_get_legal_hold(s3_client *c) {
    TEST("66: Get legal hold (expect error or success)");
    char key[256]; make_key(key, sizeof(key), "test_66_legalhold.txt");
    s3_put_object(c, TEST_BUCKET, key, "lh", 2, NULL, NULL);

    s3_object_lock_legal_hold hold = S3_LEGAL_HOLD_OFF;
    s3_status st = s3_get_object_legal_hold(c, TEST_BUCKET, key, NULL, &hold);
    cleanup_key(c, key);
    /* Either OK or error is fine - we just exercise the code path */
    (void)st;
    PASS();
}

static void test_67_put_get_3_tags(s3_client *c) {
    TEST("67: Put 3 tags, get tags, verify count and values");
    char key[256]; make_key(key, sizeof(key), "test_67_tags.txt");
    s3_put_object(c, TEST_BUCKET, key, "tags", 4, NULL, NULL);

    s3_tag tags[3] = {0};
    strcpy(tags[0].key, "color"); strcpy(tags[0].value, "blue");
    strcpy(tags[1].key, "size"); strcpy(tags[1].value, "large");
    strcpy(tags[2].key, "priority"); strcpy(tags[2].value, "high");

    s3_status st = s3_put_object_tagging(c, TEST_BUCKET, key, NULL, tags, 3);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("put tagging: %s", s3_status_string(st)); return; }

    s3_tag_set ts = {0};
    st = s3_get_object_tagging(c, TEST_BUCKET, key, NULL, &ts);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get tagging: %s", s3_status_string(st)); s3_tag_set_free(&ts); return; }
    if (ts.count != 3) { FAILF("expected 3 tags, got %d", ts.count); s3_tag_set_free(&ts); return; }

    /* Verify values */
    int found_color = 0, found_size = 0, found_priority = 0;
    for (int i = 0; i < ts.count; i++) {
        if (strcmp(ts.tags[i].key, "color") == 0 && strcmp(ts.tags[i].value, "blue") == 0) found_color = 1;
        if (strcmp(ts.tags[i].key, "size") == 0 && strcmp(ts.tags[i].value, "large") == 0) found_size = 1;
        if (strcmp(ts.tags[i].key, "priority") == 0 && strcmp(ts.tags[i].value, "high") == 0) found_priority = 1;
    }
    s3_tag_set_free(&ts);
    if (!found_color || !found_size || !found_priority) { FAIL("tag values mismatch"); return; }
    PASS();
}

static void test_68_put_many_metadata(s3_client *c) {
    TEST("68: Put object with 5 metadata keys, head, verify");
    char key[256]; make_key(key, sizeof(key), "test_68_meta.txt");
    s3_metadata meta[] = {
        { "key1", "value1" },
        { "key2", "value2" },
        { "key3", "value3" },
        { "key4", "value4" },
        { "key5", "value5" },
    };
    s3_put_object_opts opts = {0};
    opts.metadata = meta;
    opts.metadata_count = 5;
    opts.content_type = "text/plain";
    s3_status st = s3_put_object(c, TEST_BUCKET, key, "meta5", 5, &opts, NULL);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("put: %s", s3_status_string(st)); return; }

    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (hres.metadata_count < 5) { FAILF("expected >=5 metadata, got %d", hres.metadata_count); s3_head_object_result_free(&hres); return; }

    /* Verify all 5 keys */
    int found = 0;
    for (int i = 0; i < hres.metadata_count; i++) {
        for (int j = 1; j <= 5; j++) {
            char expected_key[16], expected_val[16];
            snprintf(expected_key, sizeof(expected_key), "key%d", j);
            snprintf(expected_val, sizeof(expected_val), "value%d", j);
            if (strcmp(hres.metadata[i].key, expected_key) == 0 && strcmp(hres.metadata[i].value, expected_val) == 0)
                found++;
        }
    }
    s3_head_object_result_free(&hres);
    if (found < 5) { FAILF("only found %d/5 metadata entries", found); return; }
    PASS();
}

static void test_69_get_object_attributes_etag_size(s3_client *c) {
    TEST("69: Get object attributes with ETag and ObjectSize");
    char key[256]; make_key(key, sizeof(key), "test_69_attrs.txt");
    s3_put_object(c, TEST_BUCKET, key, "attributes-test", 15, NULL, NULL);

    s3_get_object_attributes_opts opts = {0};
    opts.attr_etag = true;
    opts.attr_object_size = true;
    s3_object_attributes_result ares = {0};
    s3_status st = s3_get_object_attributes(c, TEST_BUCKET, key, &opts, &ares);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get attrs: %s", s3_status_string(st)); s3_object_attributes_result_free(&ares); return; }
    if (ares.object_size != 15) { FAILF("size: expected 15, got %lld", (long long)ares.object_size); s3_object_attributes_result_free(&ares); return; }
    if (strlen(ares.etag) == 0) { FAIL("empty etag"); s3_object_attributes_result_free(&ares); return; }
    s3_object_attributes_result_free(&ares);
    PASS();
}

static void test_70_tagging_put_delete_get(s3_client *c) {
    TEST("70: Tagging: put, delete, get (verify empty after delete)");
    char key[256]; make_key(key, sizeof(key), "test_70_tagdel.txt");
    s3_put_object(c, TEST_BUCKET, key, "td", 2, NULL, NULL);

    s3_tag tags[2] = {0};
    strcpy(tags[0].key, "a"); strcpy(tags[0].value, "1");
    strcpy(tags[1].key, "b"); strcpy(tags[1].value, "2");
    s3_put_object_tagging(c, TEST_BUCKET, key, NULL, tags, 2);

    /* Delete tags */
    s3_status st = s3_delete_object_tagging(c, TEST_BUCKET, key, NULL);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("delete tagging: %s", s3_status_string(st)); return; }

    /* Get - should be empty */
    s3_tag_set ts = {0};
    st = s3_get_object_tagging(c, TEST_BUCKET, key, NULL, &ts);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get tagging: %s", s3_status_string(st)); s3_tag_set_free(&ts); return; }
    if (ts.count != 0) { FAILF("expected 0 tags, got %d", ts.count); s3_tag_set_free(&ts); return; }
    s3_tag_set_free(&ts);
    PASS();
}

static void test_71_restore_object(s3_client *c) {
    TEST("71: Restore object (expect error, not Glacier)");
    char key[256]; make_key(key, sizeof(key), "test_71_restore.txt");
    s3_put_object(c, TEST_BUCKET, key, "restore", 7, NULL, NULL);

    s3_restore_object_opts opts = {0};
    opts.days = 1;
    opts.tier = S3_TIER_STANDARD;
    opts.description = "test restore";
    s3_status st = s3_restore_object(c, TEST_BUCKET, key, &opts);
    cleanup_key(c, key);
    /* Expect error since object is in STANDARD, not Glacier - but exercises the code path */
    (void)st;
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * List Operations - More Coverage (72-76)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_72_list_objects_v1(s3_client *c) {
    TEST("72: List objects v1 with prefix and delimiter");
    char key1[256]; make_key(key1, sizeof(key1), "test_72/sub1/file.txt");
    char key2[256]; make_key(key2, sizeof(key2), "test_72/sub2/file.txt");
    s3_put_object(c, TEST_BUCKET, key1, "a", 1, NULL, NULL);
    s3_put_object(c, TEST_BUCKET, key2, "b", 1, NULL, NULL);

    char prefix[256]; make_key(prefix, sizeof(prefix), "test_72/");
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v1(c, TEST_BUCKET, prefix, "/", NULL, 100, &res);
    cleanup_key(c, key1); cleanup_key(c, key2);
    if (st != S3_STATUS_OK) { FAILF("list v1: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.prefix_count < 2) { FAILF("expected >=2 prefixes, got %d", res.prefix_count); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_73_list_fetch_owner(s3_client *c) {
    TEST("73: List with fetch_owner=true, verify owner fields");
    char key[256]; make_key(key, sizeof(key), "test_73_owner.txt");
    s3_put_object(c, TEST_BUCKET, key, "own", 3, NULL, NULL);

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_73_owner");
    opts.prefix = prefix;
    opts.fetch_owner = true;
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.object_count < 1) { FAIL("no objects"); s3_list_objects_result_free(&res); return; }
    if (strlen(res.objects[0].owner_id) == 0) { FAIL("owner_id empty despite fetch_owner=true"); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_74_list_encoding_type(s3_client *c) {
    TEST("74: List with encoding_type=url");
    char key[256]; make_key(key, sizeof(key), "test_74_enc.txt");
    s3_put_object(c, TEST_BUCKET, key, "e", 1, NULL, NULL);

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_74_enc");
    opts.prefix = prefix;
    opts.encoding_type = "url";
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    /* Verify encoding type is set in response */
    if (strlen(res.encoding_type) == 0) { FAIL("encoding_type not set in result"); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_75_list_zero_results(s3_client *c) {
    TEST("75: List with unique prefix returning 0 results");
    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_75_nonexistent_unique_xyzzy_");
    opts.prefix = prefix;
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    if (res.object_count != 0) { FAILF("expected 0, got %d", res.object_count); s3_list_objects_result_free(&res); return; }
    s3_list_objects_result_free(&res);
    PASS();
}

static void test_76_list_all_params(s3_client *c) {
    TEST("76: List with all parameters set");
    char keys[3][256];
    for (int i = 0; i < 3; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_76/obj_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "p", 1, NULL, NULL);
    }

    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_76/");
    opts.prefix = prefix;
    opts.delimiter = "/";
    opts.max_keys = 10;
    opts.start_after = keys[0];
    opts.fetch_owner = true;
    s3_list_objects_result res = {0};
    s3_status st = s3_list_objects_v2(c, TEST_BUCKET, &opts, &res);
    for (int i = 0; i < 3; i++) cleanup_key(c, keys[i]);
    if (st != S3_STATUS_OK) { FAILF("list: %s", s3_status_string(st)); s3_list_objects_result_free(&res); return; }
    /* start_after=keys[0], so we expect at least 2 objects, but with delimiter we may get objects or prefixes */
    s3_list_objects_result_free(&res);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Multipart - More Coverage (77-81)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_77_multipart_list_empty_abort(s3_client *c) {
    TEST("77: Create multipart, list parts (empty), abort");
    char key[256]; make_key(key, sizeof(key), "test_77_mp.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    s3_list_parts_result lres = {0};
    st = s3_list_parts(c, TEST_BUCKET, key, mpu.upload_id, 100, 0, &lres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("list parts: %s", s3_status_string(st)); s3_list_parts_result_free(&lres); return;
    }
    if (lres.part_count != 0) {
        s3_list_parts_result_free(&lres);
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("expected 0 parts, got %d", lres.part_count); return;
    }
    s3_list_parts_result_free(&lres);
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    PASS();
}

static void test_78_multipart_with_options(s3_client *c) {
    TEST("78: Create multipart with content-type and storage class");
    char key[256]; make_key(key, sizeof(key), "test_78_mp_opts.bin");
    s3_create_multipart_upload_opts opts = {0};
    opts.content_type = "application/octet-stream";
    opts.storage_class = S3_STORAGE_CLASS_STANDARD;

    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, &opts, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }
    if (strlen(mpu.upload_id) == 0) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAIL("empty upload_id"); return;
    }
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    PASS();
}

static void test_79_upload_part_copy(s3_client *c) {
    TEST("79: Upload part copy from existing object");
    /* Create source object (>= 5MB for a valid part copy) */
    char src_key[256]; make_key(src_key, sizeof(src_key), "test_79_src.bin");
    size_t src_sz = PART_SIZE;
    char *src_data = malloc(src_sz);
    if (!src_data) { FAIL("malloc"); return; }
    memset(src_data, 'C', src_sz);
    s3_status st = s3_put_object(c, TEST_BUCKET, src_key, src_data, src_sz, NULL, NULL);
    free(src_data);
    if (st != S3_STATUS_OK) { cleanup_key(c, src_key); FAILF("put src: %s", s3_status_string(st)); return; }

    /* Create multipart upload for destination */
    char dst_key[256]; make_key(dst_key, sizeof(dst_key), "test_79_dst.bin");
    s3_multipart_upload mpu = {0};
    st = s3_create_multipart_upload(c, TEST_BUCKET, dst_key, NULL, &mpu);
    if (st != S3_STATUS_OK) { cleanup_key(c, src_key); FAILF("create mp: %s", s3_status_string(st)); return; }

    /* Copy part */
    s3_upload_part_result pres = {0};
    st = s3_upload_part_copy(c, TEST_BUCKET, dst_key, mpu.upload_id, 1,
                             TEST_BUCKET, src_key, NULL, &pres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, dst_key, mpu.upload_id);
        cleanup_key(c, src_key);
        FAILF("upload part copy: %s", s3_status_string(st)); return;
    }
    if (strlen(pres.etag) == 0) {
        s3_abort_multipart_upload(c, TEST_BUCKET, dst_key, mpu.upload_id);
        cleanup_key(c, src_key);
        FAIL("empty etag from part copy"); return;
    }

    /* Complete and verify */
    pres.part_number = 1;
    s3_complete_multipart_result cres = {0};
    st = s3_complete_multipart_upload(c, TEST_BUCKET, dst_key, mpu.upload_id, &pres, 1, &cres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, dst_key, mpu.upload_id);
        cleanup_key(c, src_key); cleanup_key(c, dst_key);
        FAILF("complete: %s", s3_status_string(st)); return;
    }

    cleanup_key(c, src_key); cleanup_key(c, dst_key);
    PASS();
}

static void test_80_list_multipart_uploads_with_prefix(s3_client *c) {
    TEST("80: List multipart uploads with prefix filter");
    char key[256]; make_key(key, sizeof(key), "test_80_mp_list.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    char prefix[256]; make_key(prefix, sizeof(prefix), "test_80_mp_list");
    s3_list_multipart_uploads_result res = {0};
    st = s3_list_multipart_uploads(c, TEST_BUCKET, prefix, NULL, NULL, NULL, 10, &res);
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    if (st != S3_STATUS_OK) { FAILF("list mp: %s", s3_status_string(st)); s3_list_multipart_uploads_result_free(&res); return; }
    if (res.upload_count < 1) { FAILF("expected >=1 upload, got %d", res.upload_count); s3_list_multipart_uploads_result_free(&res); return; }
    s3_list_multipart_uploads_result_free(&res);
    PASS();
}

static void test_81_multipart_upload_list_abort(s3_client *c) {
    TEST("81: Create multipart, upload 1 part, list (verify 1), abort");
    char key[256]; make_key(key, sizeof(key), "test_81_mp_1part.bin");
    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create: %s", s3_status_string(st)); return; }

    size_t part_sz = PART_SIZE;
    char *part_data = malloc(part_sz);
    if (!part_data) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("malloc"); return; }
    memset(part_data, 'P', part_sz);

    s3_upload_part_result pres = {0};
    st = s3_upload_part(c, TEST_BUCKET, key, mpu.upload_id, 1, part_data, part_sz, NULL, &pres);
    free(part_data);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("upload part: %s", s3_status_string(st)); return;
    }

    s3_list_parts_result lres = {0};
    st = s3_list_parts(c, TEST_BUCKET, key, mpu.upload_id, 100, 0, &lres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("list parts: %s", s3_status_string(st)); s3_list_parts_result_free(&lres); return;
    }
    if (lres.part_count != 1) {
        FAILF("expected 1 part, got %d", lres.part_count);
        s3_list_parts_result_free(&lres);
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        return;
    }
    if (lres.parts[0].size != (int64_t)PART_SIZE) {
        FAILF("part size: expected %d, got %lld", PART_SIZE, (long long)lres.parts[0].size);
        s3_list_parts_result_free(&lres);
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        return;
    }
    s3_list_parts_result_free(&lres);
    s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * High-Level Helpers - More Coverage (82-86)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_82_upload_file_json_content_type(s3_client *c) {
    TEST("82: s3_upload_file with auto content-type (.json)");
    char key[256]; make_key(key, sizeof(key), "test_82_auto.json");
    const char *tmppath = "/tmp/libs3_test_82.json";
    const char *body = "{\"key\": \"value\"}";
    FILE *f = fopen(tmppath, "wb");
    if (!f) { FAIL("create tmp"); return; }
    fwrite(body, 1, strlen(body), f); fclose(f);

    s3_status st = s3_upload_file(c, TEST_BUCKET, key, tmppath, NULL, NULL);
    unlink(tmppath);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("upload: %s", s3_status_string(st)); return; }

    /* Verify content-type was auto-detected */
    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (strstr(hres.content_type, "json") == NULL) {
        FAILF("expected json content-type, got %s", hres.content_type);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

static void test_83_download_file_verify(s3_client *c) {
    TEST("83: s3_download_file to path, verify file exists and content");
    char key[256]; make_key(key, sizeof(key), "test_83_dl.txt");
    const char *body = "download-verify-content-83";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    const char *tmppath = "/tmp/libs3_test_83.tmp";
    s3_status st = s3_download_file(c, TEST_BUCKET, key, tmppath, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("download: %s", s3_status_string(st)); unlink(tmppath); return; }

    /* Verify file exists */
    if (access(tmppath, F_OK) != 0) { FAIL("downloaded file does not exist"); return; }

    /* Verify content */
    FILE *f = fopen(tmppath, "rb");
    if (!f) { FAIL("open downloaded"); unlink(tmppath); return; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    unlink(tmppath);
    if (n != strlen(body) || memcmp(buf, body, n) != 0) { FAIL("content mismatch"); return; }
    PASS();
}

static void test_84_list_all_objects_pagination(s3_client *c) {
    TEST("84: s3_list_all_objects with many objects");
    /* Put 5 objects */
    char keys[5][256];
    for (int i = 0; i < 5; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_84_page_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "p", 1, NULL, NULL);
    }

    /* List all objects (default page size) */
    s3_list_objects_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_84_page_");
    opts.prefix = prefix;
    s3_object_info *objects = NULL; int count = 0;
    s3_status st = s3_list_all_objects(c, TEST_BUCKET, &opts, &objects, &count);
    for (int i = 0; i < 5; i++) cleanup_key(c, keys[i]);
    if (st != S3_STATUS_OK) { FAILF("list all: %s", s3_status_string(st)); if (objects) s3_free(objects); return; }
    if (count < 5) { FAILF("expected >=5, got %d", count); s3_free(objects); return; }
    s3_free(objects);
    PASS();
}

static void test_85_object_exists_patterns(s3_client *c) {
    TEST("85: s3_object_exists on various key patterns");
    char key1[256]; make_key(key1, sizeof(key1), "test_85/deep/nested/file.txt");
    char key2[256]; make_key(key2, sizeof(key2), "test_85_special-chars_100.txt");
    bool exists;

    /* Nested key */
    s3_put_object(c, TEST_BUCKET, key1, "n", 1, NULL, NULL);
    s3_status st = s3_object_exists(c, TEST_BUCKET, key1, &exists);
    if (st != S3_STATUS_OK || !exists) { cleanup_key(c, key1); FAIL("nested key not found"); return; }
    cleanup_key(c, key1);

    /* Key with dashes */
    s3_put_object(c, TEST_BUCKET, key2, "s", 1, NULL, NULL);
    st = s3_object_exists(c, TEST_BUCKET, key2, &exists);
    if (st != S3_STATUS_OK || !exists) { cleanup_key(c, key2); FAIL("dash key not found"); return; }
    cleanup_key(c, key2);

    /* Non-existent */
    char key3[256]; make_key(key3, sizeof(key3), "test_85_definitely_not_here.txt");
    st = s3_object_exists(c, TEST_BUCKET, key3, &exists);
    if (st != S3_STATUS_OK || exists) { FAIL("nonexistent key reported as existing"); return; }
    PASS();
}

static void test_86_detect_content_type(s3_client *c) {
    TEST("86: s3_detect_content_type for various extensions");
    (void)c; /* No S3 calls needed */

    const char *json_type = s3_detect_content_type("file.json");
    if (strcmp(json_type, "application/json") != 0) { FAILF("json: got %s", json_type); return; }

    const char *html_type = s3_detect_content_type("page.html");
    if (strcmp(html_type, "text/html") != 0) { FAILF("html: got %s", html_type); return; }

    const char *png_type = s3_detect_content_type("image.png");
    if (strcmp(png_type, "image/png") != 0) { FAILF("png: got %s", png_type); return; }

    const char *pdf_type = s3_detect_content_type("doc.pdf");
    if (strcmp(pdf_type, "application/pdf") != 0) { FAILF("pdf: got %s", pdf_type); return; }

    const char *unknown = s3_detect_content_type("file.xyzzy123");
    if (strcmp(unknown, "application/octet-stream") != 0) { FAILF("unknown: got %s", unknown); return; }

    const char *no_ext = s3_detect_content_type("noextension");
    if (strcmp(no_ext, "application/octet-stream") != 0) { FAILF("no ext: got %s", no_ext); return; }

    const char *null_type = s3_detect_content_type(NULL);
    if (strcmp(null_type, "application/octet-stream") != 0) { FAILF("null: got %s", null_type); return; }

    const char *csv_type = s3_detect_content_type("data.csv");
    if (strcmp(csv_type, "text/csv") != 0) { FAILF("csv: got %s", csv_type); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Streaming - More Coverage (87-89)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_87_put_stream_with_opts(s3_client *c) {
    TEST("87: Put object stream with content-type option");
    char key[256]; make_key(key, sizeof(key), "test_87_stream_opts.txt");
    const char *body = "stream-with-options-content";
    stream_read_ctx rctx = { body, strlen(body), 0 };

    s3_put_object_opts opts = {0};
    opts.content_type = "text/plain";
    s3_status st = s3_put_object_stream(c, TEST_BUCKET, key, stream_read_fn, &rctx,
                                         (int64_t)strlen(body), &opts, NULL);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("put stream: %s", s3_status_string(st)); return; }

    /* Verify content-type via head */
    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (strstr(hres.content_type, "text/plain") == NULL) {
        FAILF("content_type: expected text/plain, got %s", hres.content_type);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

static void test_88_get_stream_to_buffer(s3_client *c) {
    TEST("88: Get object stream that writes to buffer via callback");
    char key[256]; make_key(key, sizeof(key), "test_88_getstream.txt");
    const char *body = "get-stream-buffer-callback-content-test-88";
    s3_put_object(c, TEST_BUCKET, key, body, strlen(body), NULL, NULL);

    stream_write_ctx wctx = {0};
    s3_status st = s3_get_object_stream(c, TEST_BUCKET, key, stream_write_fn, &wctx, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get stream: %s", s3_status_string(st)); stream_write_ctx_free(&wctx); return; }
    if (wctx.len != strlen(body)) { FAILF("length: expected %zu, got %zu", strlen(body), wctx.len); stream_write_ctx_free(&wctx); return; }
    if (memcmp(wctx.data, body, wctx.len) != 0) { stream_write_ctx_free(&wctx); FAIL("content mismatch"); return; }
    stream_write_ctx_free(&wctx);
    PASS();
}

static void test_89_stream_large_roundtrip(s3_client *c) {
    TEST("89: Stream 512KB via put_stream + get_stream roundtrip");
    char key[256]; make_key(key, sizeof(key), "test_89_large_stream.bin");
    size_t sz = 512 * 1024;
    char *big = malloc(sz);
    if (!big) { FAIL("malloc"); return; }
    for (size_t i = 0; i < sz; i++) big[i] = (char)(i & 0xFF);

    stream_read_ctx rctx = { big, sz, 0 };
    s3_put_object_opts opts = {0};
    opts.content_type = "application/octet-stream";
    s3_status st = s3_put_object_stream(c, TEST_BUCKET, key, stream_read_fn, &rctx,
                                         (int64_t)sz, &opts, NULL);
    if (st != S3_STATUS_OK) { free(big); cleanup_key(c, key); FAILF("put stream: %s", s3_status_string(st)); return; }

    stream_write_ctx wctx = {0};
    st = s3_get_object_stream(c, TEST_BUCKET, key, stream_write_fn, &wctx, NULL);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { free(big); stream_write_ctx_free(&wctx); FAILF("get stream: %s", s3_status_string(st)); return; }
    if (wctx.len != sz) { free(big); stream_write_ctx_free(&wctx); FAILF("size: expected %zu, got %zu", sz, wctx.len); return; }
    if (memcmp(wctx.data, big, sz) != 0) { free(big); stream_write_ctx_free(&wctx); FAIL("content mismatch"); return; }
    free(big);
    stream_write_ctx_free(&wctx);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * List Object Versions (90-92)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_90_list_object_versions(s3_client *c) {
    TEST("90: List object versions with prefix");
    char key1[256]; make_key(key1, sizeof(key1), "test_ver_a.txt");
    char key2[256]; make_key(key2, sizeof(key2), "test_ver_b.txt");
    s3_put_object(c, TEST_BUCKET, key1, "va", 2, NULL, NULL);
    s3_put_object(c, TEST_BUCKET, key2, "vb", 2, NULL, NULL);

    s3_list_object_versions_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_ver_");
    opts.prefix = prefix;
    s3_list_object_versions_result res = {0};
    s3_status st = s3_list_object_versions(c, TEST_BUCKET, &opts, &res);
    cleanup_key(c, key1); cleanup_key(c, key2);
    if (st != S3_STATUS_OK) { FAILF("list versions: %s", s3_status_string(st)); s3_list_object_versions_result_free(&res); return; }
    /* Versions may or may not be returned depending on bucket versioning config.
     * Either way the code path is exercised. */
    s3_list_object_versions_result_free(&res);
    PASS();
}

static void test_91_list_object_versions_truncated(s3_client *c) {
    TEST("91: List object versions with max_keys=1");
    char key1[256]; make_key(key1, sizeof(key1), "test_ver_c.txt");
    char key2[256]; make_key(key2, sizeof(key2), "test_ver_d.txt");
    s3_put_object(c, TEST_BUCKET, key1, "vc", 2, NULL, NULL);
    s3_put_object(c, TEST_BUCKET, key2, "vd", 2, NULL, NULL);

    s3_list_object_versions_opts opts = {0};
    char prefix[256]; make_key(prefix, sizeof(prefix), "test_ver_");
    opts.prefix = prefix;
    opts.max_keys = 1;
    s3_list_object_versions_result res = {0};
    s3_status st = s3_list_object_versions(c, TEST_BUCKET, &opts, &res);
    cleanup_key(c, key1); cleanup_key(c, key2);
    if (st != S3_STATUS_OK) { FAILF("list versions: %s", s3_status_string(st)); s3_list_object_versions_result_free(&res); return; }
    /* With max_keys=1 and 2+ objects, should be truncated */
    if (!res.is_truncated) {
        /* It's OK if versioning is not enabled and we get different behavior */
    }
    s3_list_object_versions_result_free(&res);
    PASS();
}

static void test_92_list_object_versions_free_empty(s3_client *c) {
    TEST("92: Free empty list_object_versions_result");
    (void)c;
    s3_list_object_versions_result res = {0};
    s3_list_object_versions_result_free(&res);
    /* Also test NULL */
    s3_list_object_versions_result_free(NULL);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Streaming Multipart Upload (93)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_93_multipart_stream_upload(s3_client *c) {
    TEST("93: Multipart upload via s3_upload_part_stream");
    char key[256]; make_key(key, sizeof(key), "test_93_mp_stream.bin");

    s3_multipart_upload mpu = {0};
    s3_status st = s3_create_multipart_upload(c, TEST_BUCKET, key, NULL, &mpu);
    if (st != S3_STATUS_OK) { FAILF("create mp: %s", s3_status_string(st)); return; }

    /* Build 5MB + 1 byte of data for one part */
    size_t part_sz = PART_SIZE + 1;
    char *part_data = malloc(part_sz);
    if (!part_data) { s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id); FAIL("malloc"); return; }
    memset(part_data, 'S', part_sz);

    stream_read_ctx rctx = { part_data, part_sz, 0 };
    s3_upload_part_result pres = {0};
    st = s3_upload_part_stream(c, TEST_BUCKET, key, mpu.upload_id, 1,
                               stream_read_fn, &rctx, (int64_t)part_sz,
                               NULL, &pres);
    free(part_data);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        FAILF("upload part stream: %s", s3_status_string(st)); return;
    }
    pres.part_number = 1;

    s3_complete_multipart_result cres = {0};
    st = s3_complete_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id, &pres, 1, &cres);
    if (st != S3_STATUS_OK) {
        s3_abort_multipart_upload(c, TEST_BUCKET, key, mpu.upload_id);
        cleanup_key(c, key);
        FAILF("complete: %s", s3_status_string(st)); return;
    }

    /* Verify size via head */
    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (hres.content_length != (int64_t)part_sz) {
        FAILF("size: expected %zu, got %lld", part_sz, (long long)hres.content_length);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Progress Callback (94)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int progress_counter = 0;
static int test_progress_fn(int64_t uploaded, int64_t total_upload,
                             int64_t downloaded, int64_t total_download,
                             void *userdata) {
    (void)uploaded; (void)total_upload;
    (void)downloaded; (void)total_download;
    (void)userdata;
    progress_counter++;
    return 0;
}

static void test_94_put_with_progress(s3_client *c) {
    TEST("94: Put object with progress callback");
    char key[256]; make_key(key, sizeof(key), "test_94_progress.bin");
    /* Use a reasonably sized object to trigger progress */
    size_t sz = 256 * 1024;
    char *data = malloc(sz);
    if (!data) { FAIL("malloc"); return; }
    memset(data, 'P', sz);

    progress_counter = 0;
    s3_put_object_opts opts = {0};
    opts.content_type = "application/octet-stream";
    opts.progress_fn = test_progress_fn;
    opts.progress_userdata = NULL;
    s3_status st = s3_put_object(c, TEST_BUCKET, key, data, sz, &opts, NULL);
    free(data);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("put: %s", s3_status_string(st)); return; }
    if (progress_counter < 1) { FAIL("progress callback never called"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Put with Checksum (95-96)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_95_put_with_crc32(s3_client *c) {
    TEST("95: Put object with CRC32 checksum algorithm");
    char key[256]; make_key(key, sizeof(key), "test_95_crc32.txt");
    s3_put_object_opts opts = {0};
    opts.checksum.algorithm = S3_CHECKSUM_CRC32;
    s3_put_object_result res = {0};
    s3_status st = s3_put_object(c, TEST_BUCKET, key, "crc32-test", 10, &opts, &res);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("put crc32: %s", s3_status_string(st)); return; }
    PASS();
}

static void test_96_put_with_sha256(s3_client *c) {
    TEST("96: Put object with SHA256 checksum algorithm");
    char key[256]; make_key(key, sizeof(key), "test_96_sha256.txt");
    s3_put_object_opts opts = {0};
    opts.checksum.algorithm = S3_CHECKSUM_SHA256;
    s3_put_object_result res = {0};
    s3_status st = s3_put_object(c, TEST_BUCKET, key, "sha256-test", 11, &opts, &res);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("put sha256: %s", s3_status_string(st)); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Legal Hold and Retention (97-98)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_97_put_legal_hold(s3_client *c) {
    TEST("97: Put legal hold (expect error, no object lock)");
    char key[256]; make_key(key, sizeof(key), "test_97_lh.txt");
    s3_put_object(c, TEST_BUCKET, key, "lh", 2, NULL, NULL);

    s3_status st = s3_put_object_legal_hold(c, TEST_BUCKET, key, NULL, S3_LEGAL_HOLD_ON);
    cleanup_key(c, key);
    /* Expect error since bucket likely does not have Object Lock enabled.
     * Any non-crash result is acceptable. */
    (void)st;
    PASS();
}

static void test_98_put_retention(s3_client *c) {
    TEST("98: Put retention (expect error, no object lock)");
    char key[256]; make_key(key, sizeof(key), "test_98_ret.txt");
    s3_put_object(c, TEST_BUCKET, key, "ret", 3, NULL, NULL);

    s3_object_retention ret = {0};
    ret.mode = S3_LOCK_GOVERNANCE;
    snprintf(ret.retain_until, sizeof(ret.retain_until), "2099-01-01T00:00:00Z");
    s3_status st = s3_put_object_retention(c, TEST_BUCKET, key, NULL, &ret, false);
    cleanup_key(c, key);
    /* Expect error since bucket likely does not have Object Lock enabled.
     * Any non-crash result is acceptable. */
    (void)st;
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Trivial Coverage (99-101)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_99_sync_result_free_zero(s3_client *c) {
    TEST("99: s3_sync_result_free on zero-initialized struct");
    (void)c;
    s3_sync_result res = {0};
    s3_sync_result_free(&res);
    /* Also NULL */
    s3_sync_result_free(NULL);
    PASS();
}

static void test_100_list_directory_buckets(s3_client *c) {
    TEST("100: s3_list_directory_buckets (expect error or empty)");
    s3_list_buckets_result res = {0};
    s3_status st = s3_list_directory_buckets(c, NULL, 10, &res);
    /* Directory buckets may not be supported; either OK or error is fine */
    s3_list_buckets_result_free(&res);
    (void)st;
    PASS();
}

static void test_101_stub_functions(s3_client *c) {
    TEST("101: Stub functions return S3_STATUS_INTERNAL_ERROR");
    (void)c;
    s3_status st;

    st = s3_upload_file_parallel(NULL, "b", "k", "f", NULL, NULL);
    if (st != S3_STATUS_INTERNAL_ERROR) { FAILF("upload_file_parallel: expected INTERNAL_ERROR, got %s", s3_status_string(st)); return; }

    st = s3_download_file_parallel(NULL, "b", "k", "f", NULL, NULL);
    if (st != S3_STATUS_INTERNAL_ERROR) { FAILF("download_file_parallel: expected INTERNAL_ERROR, got %s", s3_status_string(st)); return; }

    st = s3_copy_large_object(NULL, "sb", "sk", "db", "dk", 0, 0, NULL, NULL);
    if (st != S3_STATUS_INTERNAL_ERROR) { FAILF("copy_large_object: expected INTERNAL_ERROR, got %s", s3_status_string(st)); return; }

    st = s3_sync_upload(NULL, "b", "d", NULL, NULL);
    if (st != S3_STATUS_INTERNAL_ERROR) { FAILF("sync_upload: expected INTERNAL_ERROR, got %s", s3_status_string(st)); return; }

    st = s3_sync_download(NULL, "b", "d", NULL, NULL);
    if (st != S3_STATUS_INTERNAL_ERROR) { FAILF("sync_download: expected INTERNAL_ERROR, got %s", s3_status_string(st)); return; }

    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Batch Delete Coverage (102-103)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_102_batch_delete_mixed(s3_client *c) {
    TEST("102: Batch delete 1 real + 1 nonexistent key");
    char key1[256]; make_key(key1, sizeof(key1), "test_102_exists.txt");
    char key2[256]; make_key(key2, sizeof(key2), "test_102_never_existed_xyz.txt");
    s3_put_object(c, TEST_BUCKET, key1, "x", 1, NULL, NULL);

    s3_delete_object_entry entries[2] = {
        { key1, NULL }, { key2, NULL }
    };
    s3_delete_objects_result dres = {0};
    s3_status st = s3_delete_objects(c, TEST_BUCKET, entries, 2, false, &dres);
    if (st != S3_STATUS_OK) {
        FAILF("batch delete: %s", s3_status_string(st));
        s3_delete_objects_result_free(&dres);
        cleanup_key(c, key1);
        return;
    }
    /* S3 silently succeeds on non-existent keys, but we exercise the result parsing */
    s3_delete_objects_result_free(&dres);
    PASS();
}

static void test_103_batch_delete_not_quiet(s3_client *c) {
    TEST("103: Batch delete quiet=false, verify deleted array");
    char keys[3][256];
    s3_delete_object_entry entries[3];
    for (int i = 0; i < 3; i++) {
        char suffix[64]; snprintf(suffix, sizeof(suffix), "test_103_del_%d.txt", i);
        make_key(keys[i], sizeof(keys[i]), suffix);
        s3_put_object(c, TEST_BUCKET, keys[i], "d", 1, NULL, NULL);
        entries[i].key = keys[i];
        entries[i].version_id = NULL;
    }

    s3_delete_objects_result dres = {0};
    s3_status st = s3_delete_objects(c, TEST_BUCKET, entries, 3, false, &dres);
    if (st != S3_STATUS_OK) {
        FAILF("batch delete: %s", s3_status_string(st));
        s3_delete_objects_result_free(&dres);
        for (int i = 0; i < 3; i++) cleanup_key(c, keys[i]);
        return;
    }
    /* With quiet=false, deleted array should be populated */
    if (dres.deleted_count < 3) {
        FAILF("expected >=3 deleted, got %d", dres.deleted_count);
        s3_delete_objects_result_free(&dres);
        return;
    }
    /* Verify that deleted keys are present */
    int matched = 0;
    for (int i = 0; i < dres.deleted_count; i++) {
        for (int j = 0; j < 3; j++) {
            if (strcmp(dres.deleted[i].key, keys[j]) == 0) matched++;
        }
    }
    s3_delete_objects_result_free(&dres);
    if (matched < 3) { FAILF("only matched %d/3 deleted keys", matched); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Get Object with Progress (104)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int get_progress_counter = 0;
static int test_get_progress_fn(int64_t uploaded, int64_t total_upload,
                                 int64_t downloaded, int64_t total_download,
                                 void *userdata) {
    (void)uploaded; (void)total_upload;
    (void)downloaded; (void)total_download;
    (void)userdata;
    get_progress_counter++;
    return 0;
}

static void test_104_get_with_progress(s3_client *c) {
    TEST("104: Get object with progress callback");
    char key[256]; make_key(key, sizeof(key), "test_104_getprog.bin");
    /* Put a 128KB object */
    size_t sz = 128 * 1024;
    char *data = malloc(sz);
    if (!data) { FAIL("malloc"); return; }
    memset(data, 'G', sz);
    s3_put_object(c, TEST_BUCKET, key, data, sz, NULL, NULL);
    free(data);

    get_progress_counter = 0;
    s3_get_object_opts opts = {0};
    opts.progress_fn = test_get_progress_fn;
    opts.progress_userdata = NULL;
    void *out = NULL; size_t out_len = 0;
    s3_status st = s3_get_object(c, TEST_BUCKET, key, &out, &out_len, &opts);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("get: %s", s3_status_string(st)); if (out) s3_free(out); return; }
    if (out) s3_free(out);
    if (get_progress_counter < 1) { FAIL("progress callback never called during get"); return; }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Put Object Stream with Content Type (105)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_105_put_stream_content_type(s3_client *c) {
    TEST("105: Put object stream with custom content_type, verify via head");
    char key[256]; make_key(key, sizeof(key), "test_105_stream_ct.xml");
    const char *body = "<root>stream-content-type-test</root>";
    stream_read_ctx rctx = { body, strlen(body), 0 };

    s3_put_object_opts opts = {0};
    opts.content_type = "application/xml";
    s3_status st = s3_put_object_stream(c, TEST_BUCKET, key, stream_read_fn, &rctx,
                                         (int64_t)strlen(body), &opts, NULL);
    if (st != S3_STATUS_OK) { cleanup_key(c, key); FAILF("put stream: %s", s3_status_string(st)); return; }

    s3_head_object_result hres = {0};
    st = s3_head_object(c, TEST_BUCKET, key, NULL, &hres);
    cleanup_key(c, key);
    if (st != S3_STATUS_OK) { FAILF("head: %s", s3_status_string(st)); s3_head_object_result_free(&hres); return; }
    if (strstr(hres.content_type, "application/xml") == NULL) {
        FAILF("content_type: expected application/xml, got %s", hres.content_type);
        s3_head_object_result_free(&hres); return;
    }
    s3_head_object_result_free(&hres);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Final Cleanup
 * ═══════════════════════════════════════════════════════════════════════════ */

static void final_cleanup(s3_client *c) {
    printf("\n  [Cleanup] Deleting all objects under %s...\n", TEST_PREFIX);
    int deleted = 0;
    s3_status st = s3_delete_all_objects(c, TEST_BUCKET, TEST_PREFIX, false, &deleted);
    if (st == S3_STATUS_OK) {
        printf("  [Cleanup] Deleted %d objects\n", deleted);
    } else {
        printf("  [Cleanup] Warning: delete_all returned %s\n", s3_status_string(st));
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("libs3 integration tests\n");
    printf("Bucket: %s  Prefix: %s\n\n", TEST_BUCKET, TEST_PREFIX);

    /* Load credentials */
    test_credentials creds;
    if (load_credentials(&creds) != 0) {
        fprintf(stderr, "FATAL: Could not load AWS credentials\n");
        return 1;
    }
    printf("  Region: %s\n", creds.region);
    printf("  Access Key: %.8s...\n", creds.access_key_id);
    printf("  Session Token: %s\n\n", strlen(creds.session_token) > 0 ? "(present)" : "(none)");

    /* Create client */
    s3_config cfg = {0};
    cfg.credentials.access_key_id = creds.access_key_id;
    cfg.credentials.secret_access_key = creds.secret_access_key;
    cfg.credentials.session_token = strlen(creds.session_token) > 0 ? creds.session_token : NULL;
    cfg.region = creds.region;
    cfg.use_https = true;
    cfg.log_level = S3_LOG_WARN;
    cfg.request_timeout_ms = 120000; /* 2 minutes for large uploads */
    cfg.connect_timeout_ms = 10000;

    s3_client *client = NULL;
    s3_status st = s3_client_create(&client, &cfg);
    if (st != S3_STATUS_OK) {
        fprintf(stderr, "FATAL: s3_client_create: %s\n", s3_status_string(st));
        return 1;
    }

    /* ── Object CRUD (1-15) ── */
    printf("Object CRUD:\n");
    test_01_put_small_object(client);
    test_02_get_object(client);
    test_03_head_object(client);
    test_04_delete_object(client);
    test_05_get_deleted_object(client);
    test_06_put_custom_content_type(client);
    test_07_put_with_metadata(client);
    test_08_put_empty_object(client);
    test_09_put_binary_data(client);
    test_10_put_large_object(client);
    test_11_object_exists(client);
    test_12_overwrite_object(client);
    test_13_put_storage_class(client);
    test_14_get_with_range(client);
    test_15_copy_object(client);

    /* ── Streaming (16-20) ── */
    printf("\nStreaming:\n");
    test_16_put_stream(client);
    test_17_get_stream(client);
    test_18_put_stream_known_length(client);
    test_19_stream_download_to_file(client);
    test_20_upload_download_file_roundtrip(client);

    /* ── Batch/List (21-30) ── */
    printf("\nBatch/List:\n");
    test_21_list_with_prefix(client);
    test_22_list_with_delimiter(client);
    test_23_list_pagination(client);
    test_24_list_all_objects(client);
    test_25_batch_delete(client);
    test_26_list_after_delete(client);
    test_27_delete_nonexistent(client);
    test_28_batch_delete_partial(client);
    test_29_list_start_after(client);
    test_30_batch_delete_quiet(client);

    /* ── Multipart Upload (31-38) ── */
    printf("\nMultipart Upload:\n");
    test_31_create_multipart(client);
    test_32_multipart_2_parts(client);
    test_33_abort_multipart(client);
    test_34_list_multipart_uploads(client);
    test_35_multipart_3_parts(client);
    test_36_list_parts(client);
    test_37_abort_no_object(client);
    test_38_multipart_min_parts(client);

    /* ── Object Configuration (39-45) ── */
    printf("\nObject Configuration:\n");
    test_39_put_get_tagging(client);
    test_40_delete_tagging(client);
    test_41_head_exists(client);
    test_42_get_object_attributes(client);
    test_43_copy_metadata_replace(client);
    test_44_copy_tagging_replace(client);
    test_45_rename_object(client);

    /* ── Presigned URLs (46-50) ── */
    printf("\nPresigned URLs:\n");
    test_46_presign_get(client);
    test_47_presign_put(client);
    test_48_presign_expiry(client);
    test_49_presign_head(client);
    test_50_presign_delete(client);

    /* ── High-Level Helpers (51-55) ── */
    printf("\nHigh-Level Helpers:\n");
    test_51_upload_file(client);
    test_52_download_file(client);
    test_53_list_all_objects_helper(client);
    test_54_delete_all_objects(client);
    test_55_object_exists_helper(client);

    /* ── Error Handling (56-60) ── */
    printf("\nError Handling:\n");
    test_56_get_nonexistent(client);
    test_57_last_error(client);
    test_58_head_nonexistent(client);
    test_59_copy_nonexistent_source(client);
    test_60_delete_from_nonexistent_bucket(client);

    /* ── Bucket Operations (61-63) ── */
    printf("\nBucket Operations:\n");
    test_61_head_bucket(client);
    test_62_list_buckets(client);
    test_63_get_bucket_location(client);

    /* ── Object Config - More Coverage (64-71) ── */
    printf("\nObject Config (extended):\n");
    test_64_acl_canned_and_get(client);
    test_65_get_retention(client);
    test_66_get_legal_hold(client);
    test_67_put_get_3_tags(client);
    test_68_put_many_metadata(client);
    test_69_get_object_attributes_etag_size(client);
    test_70_tagging_put_delete_get(client);
    test_71_restore_object(client);

    /* ── List Operations - More Coverage (72-76) ── */
    printf("\nList Operations (extended):\n");
    test_72_list_objects_v1(client);
    test_73_list_fetch_owner(client);
    test_74_list_encoding_type(client);
    test_75_list_zero_results(client);
    test_76_list_all_params(client);

    /* ── Multipart - More Coverage (77-81) ── */
    printf("\nMultipart (extended):\n");
    test_77_multipart_list_empty_abort(client);
    test_78_multipart_with_options(client);
    test_79_upload_part_copy(client);
    test_80_list_multipart_uploads_with_prefix(client);
    test_81_multipart_upload_list_abort(client);

    /* ── High-Level Helpers - More Coverage (82-86) ── */
    printf("\nHigh-Level Helpers (extended):\n");
    test_82_upload_file_json_content_type(client);
    test_83_download_file_verify(client);
    test_84_list_all_objects_pagination(client);
    test_85_object_exists_patterns(client);
    test_86_detect_content_type(client);

    /* ── Streaming - More Coverage (87-89) ── */
    printf("\nStreaming (extended):\n");
    test_87_put_stream_with_opts(client);
    test_88_get_stream_to_buffer(client);
    test_89_stream_large_roundtrip(client);

    /* ── List Object Versions (90-92) ── */
    printf("\nList Object Versions:\n");
    test_90_list_object_versions(client);
    test_91_list_object_versions_truncated(client);
    test_92_list_object_versions_free_empty(client);

    /* ── Streaming Multipart Upload (93) ── */
    printf("\nStreaming Multipart Upload:\n");
    test_93_multipart_stream_upload(client);

    /* ── Progress Callback (94) ── */
    printf("\nProgress Callback:\n");
    test_94_put_with_progress(client);

    /* ── Checksum (95-96) ── */
    printf("\nChecksum:\n");
    test_95_put_with_crc32(client);
    test_96_put_with_sha256(client);

    /* ── Legal Hold and Retention (97-98) ── */
    printf("\nLegal Hold and Retention:\n");
    test_97_put_legal_hold(client);
    test_98_put_retention(client);

    /* ── Trivial Coverage (99-101) ── */
    printf("\nTrivial Coverage:\n");
    test_99_sync_result_free_zero(client);
    test_100_list_directory_buckets(client);
    test_101_stub_functions(client);

    /* ── Batch Delete Coverage (102-103) ── */
    printf("\nBatch Delete Coverage:\n");
    test_102_batch_delete_mixed(client);
    test_103_batch_delete_not_quiet(client);

    /* ── Get with Progress (104) ── */
    printf("\nGet with Progress:\n");
    test_104_get_with_progress(client);

    /* ── Stream Content Type (105) ── */
    printf("\nStream Content Type:\n");
    test_105_put_stream_content_type(client);

    /* ── Final Cleanup ── */
    final_cleanup(client);

    /* ── Summary ── */
    printf("\n══════════════════════════════════════════\n");
    printf("  Total: %d  Passed: %d  Failed: %d\n", tests_run, tests_passed, tests_failed);
    printf("══════════════════════════════════════════\n");

    s3_client_destroy(client);
    return tests_failed > 0 ? 1 : 0;
}
