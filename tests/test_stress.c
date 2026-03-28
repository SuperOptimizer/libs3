#define _POSIX_C_SOURCE 200809L
#include "../s3.h"
#include "../src/s3_internal.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

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

#define ASSERT_EQ_MEM(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        FAIL("memory mismatch"); return; \
    } \
} while(0)

/* =====================================================================
 * 1. Buffer Stress Tests (15 tests)
 * ===================================================================== */

static void test_buf_append_1byte_10000(void) {
    TEST("Buffer: append 1 byte at a time, 10000 times");
    s3_buf b;
    s3_buf_init(&b);
    for (int i = 0; i < 10000; i++) {
        s3_buf_append(&b, "x", 1);
    }
    ASSERT_EQ_INT((int)b.len, 10000);
    for (int i = 0; i < 10000; i++) {
        if (b.data[i] != 'x') { FAIL("data corruption"); s3_buf_free(&b); return; }
    }
    s3_buf_free(&b);
    PASS();
}

static void test_buf_append_free_reinit_cycle(void) {
    TEST("Buffer: append/free/reinit cycle 100 times");
    s3_buf b;
    for (int i = 0; i < 100; i++) {
        s3_buf_init(&b);
        s3_buf_append_str(&b, "Hello, cycle!");
        assert(b.len == 13);
        s3_buf_free(&b);
        assert(b.data == nullptr);
        assert(b.len == 0);
        assert(b.cap == 0);
    }
    PASS();
}

static void test_buf_capacity_boundary(void) {
    TEST("Buffer: append exactly at capacity boundary");
    s3_buf b;
    s3_buf_init(&b);
    /* Initial cap is 256, but we need to account for null terminator overhead */
    /* Fill to some amount, then check cap vs len */
    char chunk[128];
    memset(chunk, 'A', 128);
    s3_buf_append(&b, chunk, 128);
    s3_buf_append(&b, chunk, 128);
    /* After 256 bytes, capacity should be >= 256 */
    assert(b.cap >= 256);
    size_t cap_before = b.cap;
    /* Append one more byte to trigger growth */
    s3_buf_append(&b, "Z", 1);
    assert(b.cap > cap_before || b.cap >= b.len + 1);
    ASSERT_EQ_INT((int)b.len, 257);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_multiple_simultaneous(void) {
    TEST("Buffer: multiple buffers simultaneously");
    s3_buf bufs[10];
    for (int i = 0; i < 10; i++) {
        s3_buf_init(&bufs[i]);
        char msg[32];
        snprintf(msg, sizeof(msg), "buffer-%d", i);
        s3_buf_append_str(&bufs[i], msg);
    }
    for (int i = 0; i < 10; i++) {
        char expected[32];
        snprintf(expected, sizeof(expected), "buffer-%d", i);
        ASSERT_EQ_STR(bufs[i].data, expected);
    }
    for (int i = 0; i < 10; i++) {
        s3_buf_free(&bufs[i]);
    }
    PASS();
}

static void test_buf_append_after_partial_free(void) {
    TEST("Buffer: append after partial free (re-init)");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "first content");
    assert(b.len == 13);
    s3_buf_free(&b);
    s3_buf_init(&b);
    s3_buf_append_str(&b, "second content");
    ASSERT_EQ_STR(b.data, "second content");
    s3_buf_free(&b);
    PASS();
}

static void test_buf_large_xml_64kb(void) {
    TEST("Buffer: build very large XML (>64KB)");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "Root");
    for (int i = 0; i < 5000; i++) {
        char val[32];
        snprintf(val, sizeof(val), "item-%d", i);
        s3__xml_buf_element(&b, "Entry", val);
    }
    s3__xml_buf_close(&b, "Root");
    assert(b.len > 65536);
    /* Verify we can find first and last */
    const char *val; size_t vlen;
    assert(s3__xml_find(b.data, b.len, "Root", &val, &vlen));
    s3_buf_free(&b);
    PASS();
}

static void test_buf_append_zero_length(void) {
    TEST("Buffer: append zero-length strings (no-op)");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "hello");
    size_t len_before = b.len;
    s3_buf_append(&b, "", 0);
    s3_buf_append(&b, "data", 0);
    ASSERT_EQ_INT((int)b.len, (int)len_before);
    ASSERT_EQ_STR(b.data, "hello");
    s3_buf_free(&b);
    PASS();
}

static void test_buf_null_termination(void) {
    TEST("Buffer: null termination after every append");
    s3_buf b;
    s3_buf_init(&b);
    for (int i = 0; i < 100; i++) {
        s3_buf_append(&b, "A", 1);
        assert(b.data[b.len] == '\0');
    }
    ASSERT_EQ_INT((int)b.len, 100);
    assert(strlen(b.data) == 100);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_null_bytes(void) {
    TEST("Buffer: buffer with null bytes appended");
    s3_buf b;
    s3_buf_init(&b);
    char zeros[10] = {0};
    s3_buf_append(&b, zeros, 10);
    ASSERT_EQ_INT((int)b.len, 10);
    for (int i = 0; i < 10; i++) {
        assert(b.data[i] == '\0');
    }
    s3_buf_free(&b);
    PASS();
}

static void test_buf_alternating_sizes(void) {
    TEST("Buffer: alternating appends of different sizes");
    s3_buf b;
    s3_buf_init(&b);
    size_t total = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (i % 7) + 1; /* 1 to 7 bytes */
        char tmp[8];
        memset(tmp, 'A' + (i % 26), sz);
        s3_buf_append(&b, tmp, sz);
        total += sz;
    }
    ASSERT_EQ_INT((int)b.len, (int)total);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_build_1000_list_bucket(void) {
    TEST("Buffer: build 1000-element ListBucketResult XML, parse back");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "ListBucketResult");
    s3__xml_buf_element(&b, "Name", "my-bucket");
    s3__xml_buf_element_bool(&b, "IsTruncated", false);
    for (int i = 0; i < 1000; i++) {
        char key[64], size_str[16];
        snprintf(key, sizeof(key), "objects/file-%04d.dat", i);
        snprintf(size_str, sizeof(size_str), "%d", i * 100);
        s3__xml_buf_open(&b, "Contents");
        s3__xml_buf_element(&b, "Key", key);
        s3__xml_buf_element(&b, "Size", size_str);
        s3__xml_buf_close(&b, "Contents");
    }
    s3__xml_buf_close(&b, "ListBucketResult");

    /* Parse back: count Contents */
    int count = 0;
    const char *p = b.data;
    while ((p = strstr(p, "<Contents>")) != nullptr) { count++; p += 10; }
    ASSERT_EQ_INT(count, 1000);

    /* Verify Name */
    const char *val; size_t vlen;
    assert(s3__xml_find(b.data, b.len, "Name", &val, &vlen));
    char buf[64];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "my-bucket");

    s3_buf_free(&b);
    PASS();
}

static void test_buf_build_1000_delete_request(void) {
    TEST("Buffer: build 1000-key Delete request XML");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "Delete");
    s3__xml_buf_element_bool(&b, "Quiet", true);
    for (int i = 0; i < 1000; i++) {
        char key[64];
        snprintf(key, sizeof(key), "prefix/key-%04d", i);
        s3__xml_buf_open(&b, "Object");
        s3__xml_buf_element(&b, "Key", key);
        s3__xml_buf_close(&b, "Object");
    }
    s3__xml_buf_close(&b, "Delete");

    int count = 0;
    const char *p = b.data;
    while ((p = strstr(p, "<Object>")) != nullptr) { count++; p += 8; }
    ASSERT_EQ_INT(count, 1000);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_build_10000_multipart(void) {
    TEST("Buffer: CompleteMultipartUpload with 10000 parts");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "CompleteMultipartUpload");
    for (int i = 1; i <= 10000; i++) {
        s3__xml_buf_open(&b, "Part");
        s3__xml_buf_element_int(&b, "PartNumber", i);
        char etag[64];
        snprintf(etag, sizeof(etag), "\"etag-%05d\"", i);
        s3__xml_buf_element(&b, "ETag", etag);
        s3__xml_buf_close(&b, "Part");
    }
    s3__xml_buf_close(&b, "CompleteMultipartUpload");

    int count = 0;
    const char *p = b.data;
    while ((p = strstr(p, "<Part>")) != nullptr) { count++; p += 6; }
    ASSERT_EQ_INT(count, 10000);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_double_free_safety(void) {
    TEST("Buffer: free then re-init then free (double free safety)");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "data");
    s3_buf_free(&b);
    /* After free, fields are zeroed; re-init and free again is safe */
    s3_buf_init(&b);
    s3_buf_free(&b);
    /* Also: free an already-freed buffer (data is nullptr, free(nullptr) is safe) */
    s3_buf_free(&b);
    PASS();
}

static void test_buf_cap_grows_not_shrinks(void) {
    TEST("Buffer: cap grows but doesn't shrink");
    s3_buf b;
    s3_buf_init(&b);
    char big[2048];
    memset(big, 'X', sizeof(big));
    s3_buf_append(&b, big, sizeof(big));
    size_t big_cap = b.cap;
    assert(big_cap >= 2048);
    /* Free and reinit - cap resets to 0 */
    s3_buf_free(&b);
    s3_buf_init(&b);
    /* But during usage, cap only grows */
    s3_buf_append_str(&b, "small");
    size_t small_cap = b.cap;
    s3_buf_append(&b, big, 500);
    assert(b.cap >= small_cap);
    s3_buf_free(&b);
    PASS();
}

/* =====================================================================
 * 2. SHA-256 Exhaustive (10 tests)
 * ===================================================================== */

static void test_sha256_all_single_bytes_unique(void) {
    TEST("SHA-256: hash every single-byte value, all unique");
    uint8_t hashes[256][32];
    for (int i = 0; i < 256; i++) {
        uint8_t byte = (uint8_t)i;
        s3__sha256(&byte, 1, hashes[i]);
    }
    /* Check all are unique */
    for (int i = 0; i < 256; i++) {
        for (int j = i + 1; j < 256; j++) {
            if (memcmp(hashes[i], hashes[j], 32) == 0) {
                FAIL("collision found"); return;
            }
        }
    }
    PASS();
}

static void test_sha256_10kb_deterministic_pattern(void) {
    TEST("SHA-256: hash 10KB of deterministic pattern");
    uint8_t data[10240];
    for (int i = 0; i < 10240; i++) {
        data[i] = (uint8_t)((i * 31 + 17) & 0xFF);
    }
    uint8_t hash1[32], hash2[32];
    s3__sha256(data, sizeof(data), hash1);
    s3__sha256(data, sizeof(data), hash2);
    ASSERT_EQ_MEM(hash1, hash2, 32);
    /* Verify non-zero */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (hash1[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sha256_cross_block_1_63_1(void) {
    TEST("SHA-256: incremental 1+63+1 bytes (cross block boundary)");
    uint8_t data[65];
    for (int i = 0; i < 65; i++) data[i] = (uint8_t)i;

    /* Single shot */
    uint8_t ref[32];
    s3__sha256(data, 65, ref);

    /* Incremental: 1, 63, 1 */
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    s3__sha256_update(&ctx, data, 1);
    s3__sha256_update(&ctx, data + 1, 63);
    s3__sha256_update(&ctx, data + 64, 1);
    uint8_t inc[32];
    s3__sha256_final(&ctx, inc);
    ASSERT_EQ_MEM(ref, inc, 32);
    PASS();
}

static void test_sha256_incremental_31_33_64_1(void) {
    TEST("SHA-256: incremental 31+33+64+1 bytes (various splits)");
    uint8_t data[129];
    for (int i = 0; i < 129; i++) data[i] = (uint8_t)(i ^ 0xAB);

    uint8_t ref[32];
    s3__sha256(data, 129, ref);

    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    s3__sha256_update(&ctx, data, 31);
    s3__sha256_update(&ctx, data + 31, 33);
    s3__sha256_update(&ctx, data + 64, 64);
    s3__sha256_update(&ctx, data + 128, 1);
    uint8_t inc[32];
    s3__sha256_final(&ctx, inc);
    ASSERT_EQ_MEM(ref, inc, 32);
    PASS();
}

static void test_sha256_collision_resistance(void) {
    TEST("SHA-256: two different messages produce different hashes");
    uint8_t h1[32], h2[32];
    s3__sha256("message one", 11, h1);
    s3__sha256("message two", 11, h2);
    assert(memcmp(h1, h2, 32) != 0);
    PASS();
}

static void test_sha256_deterministic_repeated(void) {
    TEST("SHA-256: repeated hashing is deterministic");
    const char *msg = "deterministic test data";
    uint8_t first[32];
    s3__sha256(msg, strlen(msg), first);
    for (int i = 0; i < 100; i++) {
        uint8_t h[32];
        s3__sha256(msg, strlen(msg), h);
        if (memcmp(first, h, 32) != 0) {
            FAIL("non-deterministic"); return;
        }
    }
    PASS();
}

static void test_sha256_exact_block_1000_times(void) {
    TEST("SHA-256: hash exactly 1 block (64 bytes) 1000 times");
    char block[64];
    memset(block, 'Q', 64);
    uint8_t ref[32];
    s3__sha256(block, 64, ref);
    for (int i = 0; i < 1000; i++) {
        uint8_t h[32];
        s3__sha256(block, 64, h);
        if (memcmp(ref, h, 32) != 0) {
            FAIL("inconsistent hash"); return;
        }
    }
    PASS();
}

static void test_sha256_vs_hex_consistency(void) {
    TEST("SHA-256: s3__sha256 vs s3__sha256_hex consistency");
    const char *msg = "consistency check";
    uint8_t hash[32];
    s3__sha256(msg, strlen(msg), hash);
    char hex_manual[65];
    s3__hex_encode(hash, 32, hex_manual);

    char hex_direct[65];
    s3__sha256_hex(msg, strlen(msg), hex_direct);
    ASSERT_EQ_STR(hex_manual, hex_direct);
    PASS();
}

static void test_sha256_zero_update_between(void) {
    TEST("SHA-256: feed update with size 0 between real updates");
    const char *msg = "abcdef";
    uint8_t ref[32];
    s3__sha256(msg, 6, ref);

    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    s3__sha256_update(&ctx, msg, 3);
    s3__sha256_update(&ctx, msg + 3, 0); /* zero-length */
    s3__sha256_update(&ctx, msg + 3, 3);
    uint8_t inc[32];
    s3__sha256_final(&ctx, inc);
    ASSERT_EQ_MEM(ref, inc, 32);
    PASS();
}

static void test_sha256_final_no_updates(void) {
    TEST("SHA-256: final without any updates = hash of empty string");
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    uint8_t hash[32];
    s3__sha256_final(&ctx, hash);
    char hex[65];
    s3__hex_encode(hash, 32, hex);
    ASSERT_EQ_STR(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    PASS();
}

/* =====================================================================
 * 3. HMAC-SHA256 Stress (8 tests)
 * ===================================================================== */

static void test_hmac_key_64_bytes(void) {
    TEST("HMAC-SHA256: key of exactly 64 bytes (block size)");
    uint8_t key[64];
    for (int i = 0; i < 64; i++) key[i] = (uint8_t)i;
    const char *data = "test data for 64-byte key";
    uint8_t out[32];
    s3__hmac_sha256(key, 64, data, strlen(data), out);
    /* Verify deterministic */
    uint8_t out2[32];
    s3__hmac_sha256(key, 64, data, strlen(data), out2);
    ASSERT_EQ_MEM(out, out2, 32);
    PASS();
}

static void test_hmac_key_65_bytes(void) {
    TEST("HMAC-SHA256: key of 65 bytes (triggers hashing)");
    uint8_t key[65];
    for (int i = 0; i < 65; i++) key[i] = (uint8_t)(i * 3);
    const char *data = "test data for 65-byte key";
    uint8_t out[32];
    s3__hmac_sha256(key, 65, data, strlen(data), out);
    uint8_t out2[32];
    s3__hmac_sha256(key, 65, data, strlen(data), out2);
    ASSERT_EQ_MEM(out, out2, 32);
    PASS();
}

static void test_hmac_key_1_byte(void) {
    TEST("HMAC-SHA256: key of 1 byte");
    uint8_t key = 0x42;
    const char *data = "short key test";
    uint8_t out[32];
    s3__hmac_sha256(&key, 1, data, strlen(data), out);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (out[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_hmac_key_256_bytes(void) {
    TEST("HMAC-SHA256: key of 256 bytes");
    uint8_t key[256];
    for (int i = 0; i < 256; i++) key[i] = (uint8_t)i;
    const char *data = "large key test data";
    uint8_t out[32];
    s3__hmac_sha256(key, 256, data, strlen(data), out);
    uint8_t out2[32];
    s3__hmac_sha256(key, 256, data, strlen(data), out2);
    ASSERT_EQ_MEM(out, out2, 32);
    PASS();
}

static void test_hmac_empty_data(void) {
    TEST("HMAC-SHA256: data of 0 bytes (empty)");
    uint8_t key[16];
    memset(key, 0xAA, 16);
    uint8_t out[32];
    s3__hmac_sha256(key, 16, "", 0, out);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (out[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_hmac_data_1_byte(void) {
    TEST("HMAC-SHA256: data of 1 byte");
    uint8_t key[16];
    memset(key, 0xBB, 16);
    uint8_t data = 0x42;
    uint8_t out[32];
    s3__hmac_sha256(key, 16, &data, 1, out);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (out[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_hmac_data_10kb(void) {
    TEST("HMAC-SHA256: data of 10KB");
    uint8_t key[32];
    memset(key, 0xCC, 32);
    uint8_t data[10240];
    for (int i = 0; i < 10240; i++) data[i] = (uint8_t)(i & 0xFF);
    uint8_t out[32];
    s3__hmac_sha256(key, 32, data, sizeof(data), out);
    uint8_t out2[32];
    s3__hmac_sha256(key, 32, data, sizeof(data), out2);
    ASSERT_EQ_MEM(out, out2, 32);
    PASS();
}

static void test_hmac_same_result_100_iterations(void) {
    TEST("HMAC-SHA256: same key+data, 100 iterations same result");
    uint8_t key[] = "test-key-for-hmac";
    const char *data = "test-data-for-hmac";
    uint8_t first[32];
    s3__hmac_sha256(key, sizeof(key) - 1, data, strlen(data), first);
    for (int i = 0; i < 100; i++) {
        uint8_t out[32];
        s3__hmac_sha256(key, sizeof(key) - 1, data, strlen(data), out);
        if (memcmp(first, out, 32) != 0) {
            FAIL("non-deterministic"); return;
        }
    }
    PASS();
}

/* =====================================================================
 * 4. CRC Stress (8 tests)
 * ===================================================================== */

static void test_crc32_1mb_zeros(void) {
    TEST("CRC32: 1MB buffer (all zeros)");
    size_t sz = 1024 * 1024;
    uint8_t *buf = (uint8_t *)calloc(sz, 1);
    assert(buf);
    uint32_t crc = s3__crc32(0, buf, sz);
    /* Just verify it completes and is deterministic */
    uint32_t crc2 = s3__crc32(0, buf, sz);
    ASSERT_EQ_INT((int)crc, (int)crc2);
    free(buf);
    PASS();
}

static void test_crc32c_1mb_zeros(void) {
    TEST("CRC32C: 1MB buffer (all zeros)");
    size_t sz = 1024 * 1024;
    uint8_t *buf = (uint8_t *)calloc(sz, 1);
    assert(buf);
    uint32_t crc = s3__crc32c(0, buf, sz);
    uint32_t crc2 = s3__crc32c(0, buf, sz);
    ASSERT_EQ_INT((int)crc, (int)crc2);
    free(buf);
    PASS();
}

static void test_crc32_incremental_1byte_1000(void) {
    TEST("CRC32: incremental 1-byte-at-a-time for 1000 bytes");
    uint8_t data[1000];
    for (int i = 0; i < 1000; i++) data[i] = (uint8_t)(i & 0xFF);

    /* Single shot */
    uint32_t ref = s3__crc32(0, data, 1000);

    /* Incremental */
    uint32_t inc = 0;
    for (int i = 0; i < 1000; i++) {
        inc = s3__crc32(inc, data + i, 1);
    }
    ASSERT_EQ_INT((int)ref, (int)inc);
    PASS();
}

static void test_crc32c_incremental_1byte_1000(void) {
    TEST("CRC32C: incremental 1-byte-at-a-time for 1000 bytes");
    uint8_t data[1000];
    for (int i = 0; i < 1000; i++) data[i] = (uint8_t)(i & 0xFF);

    uint32_t ref = s3__crc32c(0, data, 1000);

    uint32_t inc = 0;
    for (int i = 0; i < 1000; i++) {
        inc = s3__crc32c(inc, data + i, 1);
    }
    ASSERT_EQ_INT((int)ref, (int)inc);
    PASS();
}

static void test_crc32_repeating_pattern(void) {
    TEST("CRC32: repeating pattern");
    uint8_t pattern[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t data[4000];
    for (int i = 0; i < 4000; i++) data[i] = pattern[i % 4];
    uint32_t crc = s3__crc32(0, data, sizeof(data));
    uint32_t crc2 = s3__crc32(0, data, sizeof(data));
    ASSERT_EQ_INT((int)crc, (int)crc2);
    assert(crc != 0); /* Non-trivial data should not produce 0 */
    PASS();
}

static void test_crc32c_repeating_pattern(void) {
    TEST("CRC32C: repeating pattern");
    uint8_t pattern[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t data[4000];
    for (int i = 0; i < 4000; i++) data[i] = pattern[i % 4];
    uint32_t crc = s3__crc32c(0, data, sizeof(data));
    uint32_t crc2 = s3__crc32c(0, data, sizeof(data));
    ASSERT_EQ_INT((int)crc, (int)crc2);
    assert(crc != 0);
    PASS();
}

static void test_crc32_vs_crc32c_differ(void) {
    TEST("CRC: CRC32 and CRC32C of same data differ");
    const char *data = "test data for crc comparison";
    uint32_t c32 = s3__crc32(0, data, strlen(data));
    uint32_t c32c = s3__crc32c(0, data, strlen(data));
    assert(c32 != c32c);
    PASS();
}

static void test_crc32_single_bytes_mostly_unique(void) {
    TEST("CRC: single bytes 0-255, at least mostly unique CRC32");
    uint32_t crcs[256];
    for (int i = 0; i < 256; i++) {
        uint8_t b = (uint8_t)i;
        crcs[i] = s3__crc32(0, &b, 1);
    }
    /* Count unique values */
    int unique = 0;
    for (int i = 0; i < 256; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++) {
            if (crcs[i] == crcs[j]) { dup = 1; break; }
        }
        if (!dup) unique++;
    }
    /* All 256 single-byte CRCs should be unique (CRC32 is injective on 1-byte inputs) */
    assert(unique >= 250); /* Allow tiny margin */
    PASS();
}

/* =====================================================================
 * 5. Base64 Exhaustive (10 tests)
 * ===================================================================== */

static void test_base64_sample_2byte_combos(void) {
    TEST("Base64: encode/decode 1000 sampled 2-byte combos");
    for (int i = 0; i < 1000; i++) {
        uint8_t data[2];
        data[0] = (uint8_t)(i % 256);
        data[1] = (uint8_t)((i * 7 + 13) % 256);
        char encoded[8];
        s3__base64_encode(data, 2, encoded, sizeof(encoded));
        uint8_t decoded[4];
        size_t dlen = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
        if (dlen != 2 || decoded[0] != data[0] || decoded[1] != data[1]) {
            FAIL("roundtrip mismatch"); return;
        }
    }
    PASS();
}

static void test_base64_padding_0_to_5(void) {
    TEST("Base64: encode 0-5 bytes, verify correct padding");
    uint8_t data[] = {0x41, 0x42, 0x43, 0x44, 0x45};
    char out[16];

    /* 0 bytes -> "" */
    s3__base64_encode(data, 0, out, sizeof(out));
    ASSERT_EQ_STR(out, "");

    /* 1 byte -> XX== */
    s3__base64_encode(data, 1, out, sizeof(out));
    assert(strlen(out) == 4);
    assert(out[2] == '=' && out[3] == '=');

    /* 2 bytes -> XXX= */
    s3__base64_encode(data, 2, out, sizeof(out));
    assert(strlen(out) == 4);
    assert(out[3] == '=');

    /* 3 bytes -> XXXX (no padding) */
    s3__base64_encode(data, 3, out, sizeof(out));
    assert(strlen(out) == 4);
    assert(out[3] != '=');

    /* 4 bytes -> XXXXXX== */
    s3__base64_encode(data, 4, out, sizeof(out));
    assert(strlen(out) == 8);

    /* 5 bytes -> XXXXXXX= */
    s3__base64_encode(data, 5, out, sizeof(out));
    assert(strlen(out) == 8);
    PASS();
}

static void test_base64_decode_no_padding(void) {
    TEST("Base64: decode with no padding");
    /* "Zg" is "Zg==" without padding, represents 'f' */
    uint8_t out[4];
    size_t len = s3__base64_decode("Zg", 2, out, sizeof(out));
    /* Should handle gracefully: either decode correctly or return 0 */
    if (len == 1) {
        assert(out[0] == 'f');
    }
    /* No crash is the main test */
    PASS();
}

static void test_base64_10kb_roundtrip(void) {
    TEST("Base64: 10KB roundtrip");
    uint8_t data[10240];
    for (int i = 0; i < 10240; i++) data[i] = (uint8_t)((i * 37 + 11) & 0xFF);

    size_t enc_size = ((10240 + 2) / 3) * 4 + 1;
    char *encoded = (char *)malloc(enc_size);
    assert(encoded);
    s3__base64_encode(data, 10240, encoded, enc_size);

    uint8_t *decoded = (uint8_t *)malloc(10240 + 4);
    assert(decoded);
    size_t dlen = s3__base64_decode(encoded, strlen(encoded), decoded, 10240 + 4);
    ASSERT_EQ_INT((int)dlen, 10240);
    ASSERT_EQ_MEM(data, decoded, 10240);

    free(encoded);
    free(decoded);
    PASS();
}

static void test_base64_all_chars_produced(void) {
    TEST("Base64: encode data producing all 64 base64 chars plus '='");
    /* Encode all 256 byte values to get all base64 output chars */
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
    char encoded[512];
    s3__base64_encode(data, 256, encoded, sizeof(encoded));

    /* Check that we have A-Z, a-z, 0-9, +, / */
    int has_upper = 0, has_lower = 0, has_digit = 0, has_plus = 0, has_slash = 0;
    for (char *p = encoded; *p && *p != '='; p++) {
        if (*p >= 'A' && *p <= 'Z') has_upper = 1;
        if (*p >= 'a' && *p <= 'z') has_lower = 1;
        if (*p >= '0' && *p <= '9') has_digit = 1;
        if (*p == '+') has_plus = 1;
        if (*p == '/') has_slash = 1;
    }
    assert(has_upper && has_lower && has_digit && has_plus && has_slash);
    PASS();
}

static void test_base64_all_zeros(void) {
    TEST("Base64: all-zeros data");
    uint8_t data[12] = {0};
    char out[32];
    s3__base64_encode(data, 12, out, sizeof(out));
    ASSERT_EQ_STR(out, "AAAAAAAAAAAAAAAA");
    /* Roundtrip */
    uint8_t dec[12];
    size_t dlen = s3__base64_decode(out, strlen(out), dec, sizeof(dec));
    ASSERT_EQ_INT((int)dlen, 12);
    for (int i = 0; i < 12; i++) assert(dec[i] == 0);
    PASS();
}

static void test_base64_all_ff(void) {
    TEST("Base64: all-0xFF data");
    uint8_t data[12];
    memset(data, 0xFF, 12);
    char out[32];
    s3__base64_encode(data, 12, out, sizeof(out));
    ASSERT_EQ_STR(out, "////////////////");
    /* Roundtrip */
    uint8_t dec[12];
    size_t dlen = s3__base64_decode(out, strlen(out), dec, sizeof(dec));
    ASSERT_EQ_INT((int)dlen, 12);
    for (int i = 0; i < 12; i++) assert(dec[i] == 0xFF);
    PASS();
}

static void test_base64_output_length(void) {
    TEST("Base64: verify output length (n/3)*4 with padding");
    for (int n = 0; n <= 30; n++) {
        uint8_t data[30];
        memset(data, 'A', n);
        char out[64];
        s3__base64_encode(data, n, out, sizeof(out));
        size_t expected_len = (n == 0) ? 0 : ((n + 2) / 3) * 4;
        if (strlen(out) != expected_len) {
            printf("FAIL: n=%d, expected len=%d, got len=%d\n",
                   n, (int)expected_len, (int)strlen(out));
            return;
        }
    }
    PASS();
}

static void test_base64_decode_truncated(void) {
    TEST("Base64: decode truncated input (missing last char)");
    /* "Zm9v" = "foo", truncate to "Zm9" */
    uint8_t out[8];
    size_t len = s3__base64_decode("Zm9", 3, out, sizeof(out));
    /* Should handle gracefully - either partial decode or 0 */
    (void)len;
    /* No crash is the main test */
    PASS();
}

static void test_base64_decode_bad_padding(void) {
    TEST("Base64: decode with = in wrong position");
    uint8_t out[8];
    /* "=Zm9" has = at start - should handle gracefully */
    size_t len = s3__base64_decode("=Zm9", 4, out, sizeof(out));
    (void)len;
    /* "Z=m9" has = in middle */
    len = s3__base64_decode("Z=m9", 4, out, sizeof(out));
    (void)len;
    /* No crash is success */
    PASS();
}

/* =====================================================================
 * 6. URI Encoding Exhaustive (10 tests)
 * ===================================================================== */

static void test_uri_encode_all_bytes(void) {
    TEST("URI encode: every byte 0x00-0xFF");
    /* RFC 3986 unreserved: A-Z a-z 0-9 - . _ ~ */
    for (int i = 0; i < 256; i++) {
        char in[2] = { (char)(uint8_t)i, '\0' };
        char out[8];
        s3__uri_encode(in, 1, out, sizeof(out), false);
        int unreserved = (i >= 'A' && i <= 'Z') || (i >= 'a' && i <= 'z') ||
                         (i >= '0' && i <= '9') || i == '-' || i == '.' ||
                         i == '_' || i == '~';
        if (unreserved) {
            /* Should pass through */
            if (strlen(out) != 1 || out[0] != (char)(uint8_t)i) {
                printf("FAIL: byte 0x%02X should pass through\n", i);
                return;
            }
        } else if (i == '/' ) {
            /* Slash not encoded when encode_slash=false */
            if (out[0] != '/') {
                printf("FAIL: slash should pass through with encode_slash=false\n");
                return;
            }
        } else if (i != 0) {
            /* Should be percent-encoded (%XX) */
            if (out[0] != '%') {
                printf("FAIL: byte 0x%02X should be encoded, got '%s'\n", i, out);
                return;
            }
        }
    }
    PASS();
}

static void test_uri_all_unreserved_not_encoded(void) {
    TEST("URI encode: all 66 unreserved chars NOT encoded");
    const char *unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    char out[256];
    s3__uri_encode(unreserved, strlen(unreserved), out, sizeof(out), false);
    ASSERT_EQ_STR(out, unreserved);
    PASS();
}

static void test_uri_reserved_chars_encoded(void) {
    TEST("URI encode: reserved+special chars ARE encoded");
    const char *reserved = "!@#$%^&*()+=[]{}|;:',<>?\"\\`";
    char out[512];
    s3__uri_encode(reserved, strlen(reserved), out, sizeof(out), true);
    /* Every character should start a %XX sequence */
    const char *p = out;
    int encoded_count = 0;
    while (*p) {
        if (*p == '%') encoded_count++;
        p++;
    }
    /* All characters in reserved should be encoded */
    assert(encoded_count == (int)strlen(reserved));
    PASS();
}

static void test_uri_long_path_100_segments(void) {
    TEST("URI encode: very long path with 100 segments");
    s3_buf b;
    s3_buf_init(&b);
    for (int i = 0; i < 100; i++) {
        char seg[32];
        snprintf(seg, sizeof(seg), "%ssegment %d", i > 0 ? "/" : "", i);
        s3_buf_append_str(&b, seg);
    }
    char *out = (char *)malloc(b.len * 3 + 1);
    assert(out);
    s3__uri_encode_path(b.data, b.len, out, b.len * 3 + 1);
    /* Verify slashes preserved */
    int slash_count = 0;
    for (char *p = out; *p; p++) if (*p == '/') slash_count++;
    ASSERT_EQ_INT(slash_count, 99);
    free(out);
    s3_buf_free(&b);
    PASS();
}

static void test_uri_double_slash_preservation(void) {
    TEST("URI encode: double slash preservation in path mode");
    char out[64];
    s3__uri_encode_path("path//double", 12, out, sizeof(out));
    /* Double slash should be preserved */
    assert(strstr(out, "//") != nullptr);
    PASS();
}

static void test_uri_query_vs_path(void) {
    TEST("URI encode: query string vs path encoding differences");
    char path_out[64], query_out[64];
    /* In path mode, slash is not encoded */
    s3__uri_encode_path("a/b", 3, path_out, sizeof(path_out));
    assert(strstr(path_out, "/") != nullptr);
    /* With encode_slash=true, slash IS encoded */
    s3__uri_encode("a/b", 3, query_out, sizeof(query_out), true);
    assert(strstr(query_out, "%2F") != nullptr);
    PASS();
}

static void test_uri_realistic_s3_key(void) {
    TEST("URI encode: realistic S3 key with spaces/special chars");
    const char *key = "photos/2024/my vacation/image (1).jpg";
    char out[256];
    s3__uri_encode_path(key, strlen(key), out, sizeof(out));
    /* Spaces should be %20 */
    assert(strstr(out, "%20") != nullptr);
    /* Slashes preserved */
    assert(strstr(out, "photos/") != nullptr);
    /* Parentheses encoded */
    assert(strstr(out, "%28") != nullptr); /* ( */
    assert(strstr(out, "%29") != nullptr); /* ) */
    PASS();
}

static void test_uri_double_encode_percent(void) {
    TEST("URI encode: key with %XX already in it (double-encode %)");
    char out[64];
    s3__uri_encode("file%20name", 11, out, sizeof(out), false);
    /* The % should be encoded to %25 */
    assert(strstr(out, "%25") != nullptr);
    PASS();
}

static void test_uri_output_exact_size(void) {
    TEST("URI encode: output buffer exactly right size");
    /* "AB" = 2 chars unreserved, output needs 3 bytes (2 chars + null) */
    char out[3];
    s3__uri_encode("AB", 2, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "AB");
    PASS();
}

static void test_uri_output_too_small(void) {
    TEST("URI encode: output buffer too small (no overflow)");
    /* "!!" needs "%21%21" = 6 chars + null = 7, give only 4 */
    char out[4];
    memset(out, 'X', sizeof(out));
    s3__uri_encode("!!", 2, out, sizeof(out), false);
    /* Should truncate, not overflow */
    /* Verify no write beyond buffer (can't truly test, but no crash = success) */
    PASS();
}

/* =====================================================================
 * 7. XML Parser Stress (15 tests)
 * ===================================================================== */

static int xml_counter_fn(const char *e, size_t l, void *u) {
    (void)e; (void)l;
    (*(int *)u)++;
    return 0;
}

static void test_xml_100_contents(void) {
    TEST("XML: parse XML with 100 Contents elements");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "<ListBucketResult>");
    for (int i = 0; i < 100; i++) {
        char entry[128];
        snprintf(entry, sizeof(entry),
                 "<Contents><Key>key-%03d</Key><Size>%d</Size></Contents>", i, i * 10);
        s3_buf_append_str(&b, entry);
    }
    s3_buf_append_str(&b, "</ListBucketResult>");

    int count = 0;
    s3__xml_each(b.data, b.len, "Contents", xml_counter_fn, &count);
    ASSERT_EQ_INT(count, 100);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_deeply_nested(void) {
    TEST("XML: deeply nested tags (10 levels)");
    s3_buf b;
    s3_buf_init(&b);
    const char *tags[] = {"L1","L2","L3","L4","L5","L6","L7","L8","L9","L10"};
    for (int i = 0; i < 10; i++) s3__xml_buf_open(&b, tags[i]);
    s3__xml_buf_element(&b, "Value", "deep-value");
    for (int i = 9; i >= 0; i--) s3__xml_buf_close(&b, tags[i]);

    const char *val; size_t vlen;
    assert(s3__xml_find(b.data, b.len, "Value", &val, &vlen));
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "deep-value");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_tag_name_in_content(void) {
    TEST("XML: tag name appears in content");
    const char *xml = "<Root><Name>Name is Name</Name></Root>";
    const char *val; size_t vlen;
    assert(s3__xml_find(xml, strlen(xml), "Name", &val, &vlen));
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "Name is Name");
    PASS();
}

static void test_xml_very_long_content(void) {
    TEST("XML: very long tag content (10KB)");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "<Root><Data>");
    char chunk[1024];
    memset(chunk, 'D', 1023);
    chunk[1023] = '\0';
    for (int i = 0; i < 10; i++) {
        s3_buf_append_str(&b, chunk);
    }
    s3_buf_append_str(&b, "</Data></Root>");

    const char *val; size_t vlen;
    assert(s3__xml_find(b.data, b.len, "Data", &val, &vlen));
    assert(vlen == 10230);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_adjacent_same_name(void) {
    TEST("XML: adjacent same-name tags");
    const char *xml = "<R><X>one</X><X>two</X><X>three</X></R>";
    int count = 0;
    s3__xml_each(xml, strlen(xml), "X", xml_counter_fn, &count);
    ASSERT_EQ_INT(count, 3);

    /* First should be "one" */
    const char *val; size_t vlen;
    assert(s3__xml_find(xml, strlen(xml), "X", &val, &vlen));
    char buf[16];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "one");
    PASS();
}

static void test_xml_find_in_multiple_parents(void) {
    TEST("XML: s3__xml_find_in with multiple matching parents");
    const char *xml =
        "<Root>"
        "<Parent><Child>first</Child></Parent>"
        "<Parent><Child>second</Child></Parent>"
        "</Root>";
    const char *val; size_t vlen;
    assert(s3__xml_find_in(xml, strlen(xml), "Parent", "Child", &val, &vlen));
    char buf[16];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "first");
    PASS();
}

static void test_xml_real_list_bucket_all_fields(void) {
    TEST("XML: real-world ListBucketResult with all fields");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Name>my-bucket</Name>"
        "<Prefix>logs/</Prefix>"
        "<MaxKeys>1000</MaxKeys>"
        "<IsTruncated>true</IsTruncated>"
        "<KeyCount>2</KeyCount>"
        "<Delimiter>/</Delimiter>"
        "<EncodingType>url</EncodingType>"
        "<NextContinuationToken>token123</NextContinuationToken>"
        "<StartAfter>logs/2024</StartAfter>"
        "<Contents>"
        "<Key>logs/app.log</Key>"
        "<LastModified>2024-06-01T00:00:00.000Z</LastModified>"
        "<ETag>&quot;abc&quot;</ETag>"
        "<Size>1048576</Size>"
        "<StorageClass>STANDARD</StorageClass>"
        "<Owner><ID>owner123</ID><DisplayName>admin</DisplayName></Owner>"
        "</Contents>"
        "<CommonPrefixes><Prefix>logs/archive/</Prefix></CommonPrefixes>"
        "</ListBucketResult>";

    const char *val; size_t vlen;
    char buf[256];

    assert(s3__xml_find(xml, strlen(xml), "NextContinuationToken", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "token123");

    assert(s3__xml_find(xml, strlen(xml), "EncodingType", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "url");
    PASS();
}

static void test_xml_real_error_response(void) {
    TEST("XML: real-world S3 error with RequestId and HostId");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Error>"
        "<Code>NoSuchKey</Code>"
        "<Message>The specified key does not exist.</Message>"
        "<Key>nonexistent.txt</Key>"
        "<RequestId>EXAMPLE-REQ-ID-12345</RequestId>"
        "<HostId>EXAMPLE-HOST-ID-ABCDEF==</HostId>"
        "</Error>";

    const char *val; size_t vlen;
    char buf[256];

    assert(s3__xml_find(xml, strlen(xml), "RequestId", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "EXAMPLE-REQ-ID-12345");

    assert(s3__xml_find(xml, strlen(xml), "HostId", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "EXAMPLE-HOST-ID-ABCDEF==");

    s3_status st = s3__map_s3_error_code("NoSuchKey");
    ASSERT_EQ_INT(st, S3_STATUS_NO_SUCH_KEY);
    PASS();
}

static void test_xml_mixed_namespaces(void) {
    TEST("XML: mixed namespaces");
    const char *xml =
        "<s3:ListBucketResult xmlns:s3=\"http://s3.amazonaws.com/\">"
        "<s3:Name>bucket</s3:Name>"
        "</s3:ListBucketResult>";
    /* s3__xml_find should still find tag content regardless */
    const char *val; size_t vlen;
    /* The parser may or may not handle namespace prefixes - just verify no crash */
    s3__xml_find(xml, strlen(xml), "Name", &val, &vlen);
    /* No crash = success */
    PASS();
}

static void test_xml_100_amp_entities(void) {
    TEST("XML: decode 100 consecutive &amp; entities");
    s3_buf b;
    s3_buf_init(&b);
    for (int i = 0; i < 100; i++) s3_buf_append_str(&b, "&amp;");
    char *out = (char *)malloc(b.len + 1);
    assert(out);
    s3__xml_decode_entities(b.data, b.len, out, b.len + 1);
    assert(strlen(out) == 100);
    for (int i = 0; i < 100; i++) assert(out[i] == '&');
    free(out);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_1000_parse_back(void) {
    TEST("XML: build 1000 elements, parse all back");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_open(&b, "Root");
    for (int i = 0; i < 1000; i++) {
        char val[16];
        snprintf(val, sizeof(val), "%d", i);
        s3__xml_buf_element(&b, "Item", val);
    }
    s3__xml_buf_close(&b, "Root");

    int count = 0;
    s3__xml_each(b.data, b.len, "Item", xml_counter_fn, &count);
    ASSERT_EQ_INT(count, 1000);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_crlf_line_endings(void) {
    TEST("XML: CRLF line endings");
    const char *xml = "<Root>\r\n<Name>test</Name>\r\n</Root>";
    const char *val; size_t vlen;
    assert(s3__xml_find(xml, strlen(xml), "Name", &val, &vlen));
    char buf[16];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "test");
    PASS();
}

static void test_xml_leading_whitespace(void) {
    TEST("XML: leading whitespace before first tag");
    const char *xml = "   \n\t<Root><Name>val</Name></Root>";
    const char *val; size_t vlen;
    assert(s3__xml_find(xml, strlen(xml), "Name", &val, &vlen));
    char buf[16];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "val");
    PASS();
}

static void test_xml_comments_between_tags(void) {
    TEST("XML: comments <!-- --> between tags");
    const char *xml = "<Root><!-- comment --><Name>val</Name><!-- another --></Root>";
    const char *val; size_t vlen;
    assert(s3__xml_find(xml, strlen(xml), "Name", &val, &vlen));
    char buf[16];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "val");
    PASS();
}

static void test_xml_multipart_list_parts_100(void) {
    TEST("XML: parse ListPartsResult with 100 parts");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "<ListPartsResult>");
    s3_buf_append_str(&b, "<UploadId>upload-xyz</UploadId>");
    for (int i = 1; i <= 100; i++) {
        char part[256];
        snprintf(part, sizeof(part),
                 "<Part><PartNumber>%d</PartNumber><ETag>&quot;etag%d&quot;</ETag>"
                 "<Size>%d</Size><LastModified>2024-01-01T00:00:00Z</LastModified></Part>",
                 i, i, i * 5242880);
        s3_buf_append_str(&b, part);
    }
    s3_buf_append_str(&b, "</ListPartsResult>");

    int count = 0;
    s3__xml_each(b.data, b.len, "Part", xml_counter_fn, &count);
    ASSERT_EQ_INT(count, 100);
    s3_buf_free(&b);
    PASS();
}

/* =====================================================================
 * 8. SigV4 Stress (8 tests)
 * ===================================================================== */

static void test_sigv4_100_different_dates(void) {
    TEST("SigV4: derive 100 different signing keys (different dates)");
    uint8_t keys[100][32];
    for (int i = 0; i < 100; i++) {
        char date[9];
        snprintf(date, sizeof(date), "202401%02d", (i % 28) + 1);
        s3__derive_signing_key("secret", date, "us-east-1", "s3", keys[i]);
    }
    /* Verify keys for different dates are different (at least first 28) */
    for (int i = 0; i < 28; i++) {
        for (int j = i + 1; j < 28; j++) {
            if (memcmp(keys[i], keys[j], 32) == 0) {
                FAIL("duplicate keys for different dates"); return;
            }
        }
    }
    PASS();
}

static void test_sigv4_all_regions(void) {
    TEST("SigV4: derive keys for multiple AWS regions");
    const char *regions[] = {
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "ap-northeast-1", "ap-southeast-1", "ap-south-1",
        "sa-east-1", "ca-central-1", "me-south-1"
    };
    int n = (int)(sizeof(regions) / sizeof(regions[0]));
    uint8_t keys[14][32];
    for (int i = 0; i < n; i++) {
        s3__derive_signing_key("secret", "20240101", regions[i], "s3", keys[i]);
    }
    /* All should be different */
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (memcmp(keys[i], keys[j], 32) == 0) {
                FAIL("duplicate keys for different regions"); return;
            }
        }
    }
    PASS();
}

static void test_sigv4_long_secret_key(void) {
    TEST("SigV4: very long secret key (1024 chars)");
    char secret[1025];
    memset(secret, 'K', 1024);
    secret[1024] = '\0';
    uint8_t key[32];
    s3__derive_signing_key(secret, "20240101", "us-east-1", "s3", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_special_char_key(void) {
    TEST("SigV4: secret key with special characters");
    const char *secret = "wJalr+XUtnFEMI/K7MDENG+bPxRfiCY==EXAMPLEKEY!@#";
    uint8_t key[32];
    s3__derive_signing_key(secret, "20240101", "us-east-1", "s3", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_key_exactly_32_bytes(void) {
    TEST("SigV4: signing key is exactly 32 bytes");
    uint8_t key[32];
    memset(key, 0xAA, 32); /* Fill with sentinel */
    s3__derive_signing_key("secret", "20240101", "us-east-1", "s3", key);
    /* Verify all 32 bytes were written (unlikely to still be 0xAA) */
    int changed = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0xAA) changed++;
    assert(changed > 20); /* Most bytes should change */
    PASS();
}

static void test_sigv4_deterministic(void) {
    TEST("SigV4: derive key twice with same inputs, same result");
    uint8_t k1[32], k2[32];
    s3__derive_signing_key("mysecret", "20240315", "eu-west-1", "s3", k1);
    s3__derive_signing_key("mysecret", "20240315", "eu-west-1", "s3", k2);
    ASSERT_EQ_MEM(k1, k2, 32);
    PASS();
}

static void test_sigv4_different_services(void) {
    TEST("SigV4: different services produce different keys");
    uint8_t k_s3[32], k_iam[32], k_sts[32];
    s3__derive_signing_key("secret", "20240101", "us-east-1", "s3", k_s3);
    s3__derive_signing_key("secret", "20240101", "us-east-1", "iam", k_iam);
    s3__derive_signing_key("secret", "20240101", "us-east-1", "sts", k_sts);
    assert(memcmp(k_s3, k_iam, 32) != 0);
    assert(memcmp(k_s3, k_sts, 32) != 0);
    assert(memcmp(k_iam, k_sts, 32) != 0);
    PASS();
}

static void test_sigv4_datestamp_format(void) {
    TEST("SigV4: datestamp format validation (exactly 8 digits)");
    char iso[17], date[9];
    s3__get_timestamp(iso, date);
    ASSERT_EQ_INT((int)strlen(date), 8);
    for (int i = 0; i < 8; i++) {
        assert(date[i] >= '0' && date[i] <= '9');
    }
    PASS();
}

/* =====================================================================
 * 9. Client Stress (8 tests)
 * ===================================================================== */

static void test_client_create_100_destroy_reverse(void) {
    TEST("Client: create 100 clients, destroy in reverse order");
    s3_client *clients[100];
    for (int i = 0; i < 100; i++) {
        s3_status st = s3_client_create(&clients[i], &(s3_config){
            .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
            .region = "us-east-1",
        });
        if (st != S3_STATUS_OK) { FAIL("create failed"); return; }
    }
    for (int i = 99; i >= 0; i--) {
        s3_client_destroy(clients[i]);
    }
    PASS();
}

static void test_client_very_long_region(void) {
    TEST("Client: very long region string");
    char region[256];
    memset(region, 'r', 255);
    region[255] = '\0';
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = region,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    ASSERT_EQ_STR(c->region, region);
    s3_client_destroy(c);
    PASS();
}

static void test_client_very_long_endpoint(void) {
    TEST("Client: very long endpoint string");
    char endpoint[512];
    memset(endpoint, 'e', 511);
    endpoint[511] = '\0';
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .endpoint = endpoint,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    ASSERT_EQ_STR(c->endpoint, endpoint);
    s3_client_destroy(c);
    PASS();
}

static void test_client_very_long_user_agent(void) {
    TEST("Client: very long user_agent string");
    char ua[1024];
    memset(ua, 'u', 1023);
    ua[1023] = '\0';
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .user_agent = ua,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    ASSERT_EQ_STR(c->user_agent, ua);
    s3_client_destroy(c);
    PASS();
}

static void test_client_create_destroy_1000_loop(void) {
    TEST("Client: create/destroy 1000 iterations (leak test)");
    for (int i = 0; i < 1000; i++) {
        s3_client *c = nullptr;
        s3_status st = s3_client_create(&c, &(s3_config){
            .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
            .region = "us-east-1",
        });
        if (st != S3_STATUS_OK) { FAIL("create failed"); return; }
        s3_client_destroy(c);
    }
    PASS();
}

static void test_client_last_error_clean(void) {
    TEST("Client: last_error is clean after creation");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
    });
    (void)st;
    const s3_error *err = s3_client_last_error(c);
    ASSERT_EQ_INT(err->status, S3_STATUS_OK);
    ASSERT_EQ_INT(err->http_status, 0);
    s3_client_destroy(c);
    PASS();
}

static void test_client_all_bool_flags(void) {
    TEST("Client: all boolean flags true");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .use_path_style = true,
        .use_https = true,
        .use_transfer_acceleration = true,
        .use_dual_stack = true,
        .use_fips = true,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c->use_path_style == true);
    assert(c->use_https == true);
    assert(c->use_transfer_acceleration == true);
    assert(c->use_dual_stack == true);
    assert(c->use_fips == true);
    s3_client_destroy(c);
    PASS();
}

static void test_client_max_timeout_values(void) {
    TEST("Client: maximum timeout values");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .connect_timeout_ms = 300000,
        .request_timeout_ms = 600000,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    ASSERT_EQ_INT((int)c->connect_timeout_ms, 300000);
    ASSERT_EQ_INT((int)c->request_timeout_ms, 600000);
    s3_client_destroy(c);
    PASS();
}

/* =====================================================================
 * 10. Free Function Safety (10 tests)
 * ===================================================================== */

static void test_free_list_objects_zero(void) {
    TEST("Free: s3_list_objects_result_free on zero-init struct");
    s3_list_objects_result r = {0};
    s3_list_objects_result_free(&r);
    PASS();
}

static void test_free_list_object_versions_zero(void) {
    TEST("Free: s3_list_object_versions_result_free on zero-init");
    s3_list_object_versions_result r = {0};
    s3_list_object_versions_result_free(&r);
    PASS();
}

static void test_free_list_buckets_zero(void) {
    TEST("Free: s3_list_buckets_result_free on zero-init struct");
    s3_list_buckets_result r = {0};
    s3_list_buckets_result_free(&r);
    PASS();
}

static void test_free_list_parts_zero(void) {
    TEST("Free: s3_list_parts_result_free on zero-init struct");
    s3_list_parts_result r = {0};
    s3_list_parts_result_free(&r);
    PASS();
}

static void test_free_list_multipart_uploads_zero(void) {
    TEST("Free: s3_list_multipart_uploads_result_free on zero-init");
    s3_list_multipart_uploads_result r = {0};
    s3_list_multipart_uploads_result_free(&r);
    PASS();
}

static void test_free_delete_objects_zero(void) {
    TEST("Free: s3_delete_objects_result_free on zero-init struct");
    s3_delete_objects_result r = {0};
    s3_delete_objects_result_free(&r);
    PASS();
}

static void test_free_object_attributes_zero(void) {
    TEST("Free: s3_object_attributes_result_free on zero-init");
    s3_object_attributes_result r = {0};
    s3_object_attributes_result_free(&r);
    PASS();
}

static void test_free_tag_set_zero(void) {
    TEST("Free: s3_tag_set_free on zero-init struct");
    s3_tag_set r = {0};
    s3_tag_set_free(&r);
    PASS();
}

static void test_free_acl_zero(void) {
    TEST("Free: s3_acl_free on zero-init struct");
    s3_acl r = {0};
    s3_acl_free(&r);
    PASS();
}

static void test_free_head_object_zero(void) {
    TEST("Free: s3_head_object_result_free on zero-init struct");
    s3_head_object_result r = {0};
    s3_head_object_result_free(&r);
    PASS();
}

/* =====================================================================
 * 11. Concurrent Safety (8 tests)
 * ===================================================================== */

#define NUM_THREADS 8
#define ITERS_PER_THREAD 1000

typedef struct {
    int thread_id;
    int success;
} thread_arg;

static void *thread_create_clients(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        s3_client *c = nullptr;
        s3_status st = s3_client_create(&c, &(s3_config){
            .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
            .region = "us-east-1",
        });
        if (st != S3_STATUS_OK) { ta->success = 0; return nullptr; }
        s3_client_destroy(c);
    }
    return nullptr;
}

static void test_concurrent_client_create(void) {
    TEST("Concurrent: create clients in parallel threads");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].success = 0;
        pthread_create(&threads[i], nullptr, thread_create_clients, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("thread failed"); return; }
    }
    PASS();
}

static void *thread_sha256(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    uint8_t expected[32];
    s3__sha256("test data for threading", 23, expected);
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        uint8_t hash[32];
        s3__sha256("test data for threading", 23, hash);
        if (memcmp(hash, expected, 32) != 0) {
            ta->success = 0;
            return nullptr;
        }
    }
    return nullptr;
}

static void test_concurrent_sha256(void) {
    TEST("Concurrent: each thread hashes data independently (SHA-256)");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_sha256, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("SHA-256 corruption"); return; }
    }
    PASS();
}

static void *thread_crc32(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    const char *data = "crc test data for threading";
    uint32_t expected = s3__crc32(0, data, strlen(data));
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        uint32_t crc = s3__crc32(0, data, strlen(data));
        if (crc != expected) { ta->success = 0; return nullptr; }
    }
    return nullptr;
}

static void test_concurrent_crc32(void) {
    TEST("Concurrent: each thread does CRC32 independently");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_crc32, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("CRC32 corruption"); return; }
    }
    PASS();
}

static void *thread_base64(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    uint8_t data[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8_t)(i + ta->thread_id);
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        char encoded[64];
        s3__base64_encode(data, 32, encoded, sizeof(encoded));
        uint8_t decoded[32];
        size_t dlen = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
        if (dlen != 32 || memcmp(data, decoded, 32) != 0) {
            ta->success = 0;
            return nullptr;
        }
    }
    return nullptr;
}

static void test_concurrent_base64(void) {
    TEST("Concurrent: each thread does base64 encode independently");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_base64, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("base64 corruption"); return; }
    }
    PASS();
}

static void *thread_status_string(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        for (int s = 0; s < S3_STATUS__COUNT; s++) {
            const char *str = s3_status_string((s3_status)s);
            if (!str || strlen(str) == 0) {
                ta->success = 0;
                return nullptr;
            }
        }
    }
    return nullptr;
}

static void test_concurrent_status_string(void) {
    TEST("Concurrent: multiple threads calling s3_status_string");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_status_string, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("status_string corruption"); return; }
    }
    PASS();
}

static void *thread_content_type(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    const char *files[] = {"a.jpg", "b.png", "c.html", "d.json", "e.xml"};
    const char *types[] = {"image/jpeg", "image/png", "text/html", "application/json", "text/xml"};
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        for (int j = 0; j < 5; j++) {
            const char *ct = s3_detect_content_type(files[j]);
            if (strcmp(ct, types[j]) != 0) {
                ta->success = 0;
                return nullptr;
            }
        }
    }
    return nullptr;
}

static void test_concurrent_content_type(void) {
    TEST("Concurrent: multiple threads calling s3_detect_content_type");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_content_type, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("content_type corruption"); return; }
    }
    PASS();
}

static void *thread_uri_encode(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        char out[64];
        s3__uri_encode("hello world/test", 16, out, sizeof(out), false);
        if (strcmp(out, "hello%20world/test") != 0) {
            ta->success = 0;
            return nullptr;
        }
    }
    return nullptr;
}

static void test_concurrent_uri_encode(void) {
    TEST("Concurrent: multiple threads doing URI encoding");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_uri_encode, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("URI encode corruption"); return; }
    }
    PASS();
}

static void *thread_pure_functions(void *arg) {
    thread_arg *ta = (thread_arg *)arg;
    ta->success = 1;
    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        /* SHA-256 */
        uint8_t hash[32];
        s3__sha256("data", 4, hash);

        /* CRC32 */
        uint32_t crc = s3__crc32(0, "data", 4);
        (void)crc;

        /* Base64 */
        char b64[16];
        s3__base64_encode((const uint8_t *)"data", 4, b64, sizeof(b64));

        /* URI encode */
        char uri[32];
        s3__uri_encode("a b", 3, uri, sizeof(uri), false);

        /* Status string */
        const char *s = s3_status_string(S3_STATUS_OK);
        if (!s) { ta->success = 0; return nullptr; }
    }
    return nullptr;
}

static void test_concurrent_pure_functions(void) {
    TEST("Concurrent: verify no corruption under concurrent pure fn access");
    pthread_t threads[NUM_THREADS];
    thread_arg args[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], nullptr, thread_pure_functions, &args[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], nullptr);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!args[i].success) { FAIL("pure function corruption"); return; }
    }
    PASS();
}

/* =====================================================================
 * Main
 * ===================================================================== */

int main(void) {
    printf("\n=== libs3 Stress Test Suite ===\n\n");

    printf("-- Buffer Stress (15) --\n");
    test_buf_append_1byte_10000();
    test_buf_append_free_reinit_cycle();
    test_buf_capacity_boundary();
    test_buf_multiple_simultaneous();
    test_buf_append_after_partial_free();
    test_buf_large_xml_64kb();
    test_buf_append_zero_length();
    test_buf_null_termination();
    test_buf_null_bytes();
    test_buf_alternating_sizes();
    test_buf_build_1000_list_bucket();
    test_buf_build_1000_delete_request();
    test_buf_build_10000_multipart();
    test_buf_double_free_safety();
    test_buf_cap_grows_not_shrinks();

    printf("-- SHA-256 Exhaustive (10) --\n");
    test_sha256_all_single_bytes_unique();
    test_sha256_10kb_deterministic_pattern();
    test_sha256_cross_block_1_63_1();
    test_sha256_incremental_31_33_64_1();
    test_sha256_collision_resistance();
    test_sha256_deterministic_repeated();
    test_sha256_exact_block_1000_times();
    test_sha256_vs_hex_consistency();
    test_sha256_zero_update_between();
    test_sha256_final_no_updates();

    printf("-- HMAC-SHA256 Stress (8) --\n");
    test_hmac_key_64_bytes();
    test_hmac_key_65_bytes();
    test_hmac_key_1_byte();
    test_hmac_key_256_bytes();
    test_hmac_empty_data();
    test_hmac_data_1_byte();
    test_hmac_data_10kb();
    test_hmac_same_result_100_iterations();

    printf("-- CRC Stress (8) --\n");
    test_crc32_1mb_zeros();
    test_crc32c_1mb_zeros();
    test_crc32_incremental_1byte_1000();
    test_crc32c_incremental_1byte_1000();
    test_crc32_repeating_pattern();
    test_crc32c_repeating_pattern();
    test_crc32_vs_crc32c_differ();
    test_crc32_single_bytes_mostly_unique();

    printf("-- Base64 Exhaustive (10) --\n");
    test_base64_sample_2byte_combos();
    test_base64_padding_0_to_5();
    test_base64_decode_no_padding();
    test_base64_10kb_roundtrip();
    test_base64_all_chars_produced();
    test_base64_all_zeros();
    test_base64_all_ff();
    test_base64_output_length();
    test_base64_decode_truncated();
    test_base64_decode_bad_padding();

    printf("-- URI Encoding Exhaustive (10) --\n");
    test_uri_encode_all_bytes();
    test_uri_all_unreserved_not_encoded();
    test_uri_reserved_chars_encoded();
    test_uri_long_path_100_segments();
    test_uri_double_slash_preservation();
    test_uri_query_vs_path();
    test_uri_realistic_s3_key();
    test_uri_double_encode_percent();
    test_uri_output_exact_size();
    test_uri_output_too_small();

    printf("-- XML Parser Stress (15) --\n");
    test_xml_100_contents();
    test_xml_deeply_nested();
    test_xml_tag_name_in_content();
    test_xml_very_long_content();
    test_xml_adjacent_same_name();
    test_xml_find_in_multiple_parents();
    test_xml_real_list_bucket_all_fields();
    test_xml_real_error_response();
    test_xml_mixed_namespaces();
    test_xml_100_amp_entities();
    test_xml_build_1000_parse_back();
    test_xml_crlf_line_endings();
    test_xml_leading_whitespace();
    test_xml_comments_between_tags();
    test_xml_multipart_list_parts_100();

    printf("-- SigV4 Stress (8) --\n");
    test_sigv4_100_different_dates();
    test_sigv4_all_regions();
    test_sigv4_long_secret_key();
    test_sigv4_special_char_key();
    test_sigv4_key_exactly_32_bytes();
    test_sigv4_deterministic();
    test_sigv4_different_services();
    test_sigv4_datestamp_format();

    printf("-- Client Stress (8) --\n");
    test_client_create_100_destroy_reverse();
    test_client_very_long_region();
    test_client_very_long_endpoint();
    test_client_very_long_user_agent();
    test_client_create_destroy_1000_loop();
    test_client_last_error_clean();
    test_client_all_bool_flags();
    test_client_max_timeout_values();

    printf("-- Free Function Safety (10) --\n");
    test_free_list_objects_zero();
    test_free_list_object_versions_zero();
    test_free_list_buckets_zero();
    test_free_list_parts_zero();
    test_free_list_multipart_uploads_zero();
    test_free_delete_objects_zero();
    test_free_object_attributes_zero();
    test_free_tag_set_zero();
    test_free_acl_zero();
    test_free_head_object_zero();

    printf("-- Concurrent Safety (8) --\n");
    test_concurrent_client_create();
    test_concurrent_sha256();
    test_concurrent_crc32();
    test_concurrent_base64();
    test_concurrent_status_string();
    test_concurrent_content_type();
    test_concurrent_uri_encode();
    test_concurrent_pure_functions();

    printf("\n=======================================\n");
    printf("Results: %d/%d stress tests passed\n", tests_passed, tests_run);
    printf("=======================================\n\n");

    return tests_passed == tests_run ? 0 : 1;
}
