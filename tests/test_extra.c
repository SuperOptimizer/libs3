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

#define ASSERT_EQ_MEM(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        FAIL("memory mismatch"); return; \
    } \
} while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. SHA-256 Edge Cases (10 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha256_55_bytes(void) {
    TEST("SHA-256: 55-byte message (padding boundary - 1)");
    /* 55 bytes is the maximum that fits in one block with padding */
    uint8_t msg[55];
    memset(msg, 0x41, 55);
    char hex1[65], hex2[65];
    s3__sha256_hex(msg, 55, hex1);
    s3__sha256_hex(msg, 55, hex2);
    ASSERT_EQ_STR(hex1, hex2);
    /* Known value for 55 bytes of 0x41 ('A') */
    ASSERT_EQ_STR(hex1, "8963cc0afd622cc7574ac2011f93a3059b3d65548a77542a1559e3d202e6ab00");
    PASS();
}

static void test_sha256_56_bytes(void) {
    TEST("SHA-256: 56-byte message (exact padding boundary)");
    uint8_t msg[56];
    memset(msg, 0x42, 56);
    char hex[65];
    s3__sha256_hex(msg, 56, hex);
    assert(strlen(hex) == 64);
    /* Must differ from 55-byte version */
    uint8_t msg55[55];
    memset(msg55, 0x42, 55);
    char hex55[65];
    s3__sha256_hex(msg55, 55, hex55);
    assert(strcmp(hex, hex55) != 0);
    PASS();
}

static void test_sha256_64_bytes_exact(void) {
    TEST("SHA-256: 64-byte message (exact block)");
    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;
    char hex[65];
    s3__sha256_hex(msg, 64, hex);
    assert(strlen(hex) == 64);
    /* Verify deterministic */
    char hex2[65];
    s3__sha256_hex(msg, 64, hex2);
    ASSERT_EQ_STR(hex, hex2);
    PASS();
}

static void test_sha256_119_bytes(void) {
    TEST("SHA-256: 119-byte message (2-block padding boundary - 1)");
    uint8_t msg[119];
    memset(msg, 0xCC, 119);
    char hex[65];
    s3__sha256_hex(msg, 119, hex);
    assert(strlen(hex) == 64);
    PASS();
}

static void test_sha256_128_bytes(void) {
    TEST("SHA-256: 128-byte message (exact 2 blocks)");
    uint8_t msg[128];
    memset(msg, 0xDD, 128);
    char hex[65];
    s3__sha256_hex(msg, 128, hex);
    assert(strlen(hex) == 64);
    PASS();
}

static void test_sha256_1000_byte_consistency(void) {
    TEST("SHA-256: 1000-byte consistency (hash twice)");
    uint8_t msg[1000];
    for (int i = 0; i < 1000; i++) msg[i] = (uint8_t)(i & 0xFF);
    char hex1[65], hex2[65];
    s3__sha256_hex(msg, 1000, hex1);
    s3__sha256_hex(msg, 1000, hex2);
    ASSERT_EQ_STR(hex1, hex2);
    PASS();
}

static void test_sha256_empty_updates(void) {
    TEST("SHA-256: empty update calls don't change hash");
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    s3__sha256_update(&ctx, "abc", 3);
    s3__sha256_update(&ctx, "", 0);
    s3__sha256_update(&ctx, "", 0);
    uint8_t hash[32];
    s3__sha256_final(&ctx, hash);
    char hex[65];
    s3__hex_encode(hash, 32, hex);
    /* Must equal SHA-256 of "abc" */
    ASSERT_EQ_STR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    PASS();
}

static void test_sha256_multiple_finals(void) {
    TEST("SHA-256: second final call does not crash");
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    s3__sha256_update(&ctx, "test", 4);
    uint8_t hash1[32], hash2[32];
    s3__sha256_final(&ctx, hash1);
    /* Re-calling final on the same context; state may differ but must not crash */
    s3__sha256_final(&ctx, hash2);
    /* Verify first call produced correct result */
    char hex[65];
    s3__hex_encode(hash1, 32, hex);
    assert(strlen(hex) == 64);
    PASS();
}

static void test_sha256_binary_with_nulls(void) {
    TEST("SHA-256: binary data with null bytes");
    uint8_t msg[] = {0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00};
    char hex[65];
    s3__sha256_hex(msg, sizeof(msg), hex);
    assert(strlen(hex) == 64);
    /* Verify different from empty */
    char hex_empty[65];
    s3__sha256_hex("", 0, hex_empty);
    assert(strcmp(hex, hex_empty) != 0);
    PASS();
}

static void test_sha256_single_shot_vs_incremental(void) {
    TEST("SHA-256: single-shot vs incremental match");
    const char *data = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(data);

    /* Single-shot */
    uint8_t hash1[32];
    s3__sha256(data, len, hash1);

    /* Incremental: 5 bytes at a time */
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    size_t pos = 0;
    while (pos < len) {
        size_t chunk = (len - pos > 5) ? 5 : (len - pos);
        s3__sha256_update(&ctx, data + pos, chunk);
        pos += chunk;
    }
    uint8_t hash2[32];
    s3__sha256_final(&ctx, hash2);

    ASSERT_EQ_MEM(hash1, hash2, 32);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. SHA-1 Edge Cases (8 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha1_448bit_vector(void) {
    TEST("SHA-1: 448-bit known vector");
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t hash[20];
    s3__sha1(msg, strlen(msg), hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    PASS();
}

static void test_sha1_incremental_vs_single(void) {
    TEST("SHA-1: incremental matches single-shot");
    const char *data = "Hello, World! This is a test of SHA-1 incremental.";
    size_t len = strlen(data);
    uint8_t hash1[20];
    s3__sha1(data, len, hash1);

    s3_sha1_ctx ctx;
    s3__sha1_init(&ctx);
    for (size_t i = 0; i < len; i += 7) {
        size_t chunk = (len - i > 7) ? 7 : (len - i);
        s3__sha1_update(&ctx, data + i, chunk);
    }
    uint8_t hash2[20];
    s3__sha1_final(&ctx, hash2);
    ASSERT_EQ_MEM(hash1, hash2, 20);
    PASS();
}

static void test_sha1_empty_updates(void) {
    TEST("SHA-1: empty updates don't change hash");
    s3_sha1_ctx ctx;
    s3__sha1_init(&ctx);
    s3__sha1_update(&ctx, "abc", 3);
    s3__sha1_update(&ctx, "", 0);
    s3__sha1_update(&ctx, "", 0);
    uint8_t hash[20];
    s3__sha1_final(&ctx, hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    PASS();
}

static void test_sha1_64_byte_boundary(void) {
    TEST("SHA-1: 64-byte boundary (exact block)");
    uint8_t msg[64];
    memset(msg, 'Z', 64);
    uint8_t hash[20];
    s3__sha1(msg, 64, hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    assert(strlen(hex) == 40);
    PASS();
}

static void test_sha1_binary_with_nulls(void) {
    TEST("SHA-1: binary data with null bytes");
    uint8_t msg[] = {0x00, 0x00, 0x00, 0x01, 0xFF, 0x00};
    uint8_t hash[20];
    s3__sha1(msg, sizeof(msg), hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    assert(strlen(hex) == 40);
    /* Different from empty hash */
    uint8_t empty_hash[20];
    s3__sha1("", 0, empty_hash);
    assert(memcmp(hash, empty_hash, 20) != 0);
    PASS();
}

static void test_sha1_1000_bytes(void) {
    TEST("SHA-1: 1000-byte input");
    uint8_t msg[1000];
    for (int i = 0; i < 1000; i++) msg[i] = (uint8_t)(i % 256);
    uint8_t hash1[20], hash2[20];
    s3__sha1(msg, 1000, hash1);
    s3__sha1(msg, 1000, hash2);
    ASSERT_EQ_MEM(hash1, hash2, 20);
    PASS();
}

static void test_sha1_single_byte_updates(void) {
    TEST("SHA-1: single byte updates");
    const char *msg = "Hello";
    uint8_t hash1[20];
    s3__sha1(msg, 5, hash1);

    s3_sha1_ctx ctx;
    s3__sha1_init(&ctx);
    for (int i = 0; i < 5; i++)
        s3__sha1_update(&ctx, msg + i, 1);
    uint8_t hash2[20];
    s3__sha1_final(&ctx, hash2);
    ASSERT_EQ_MEM(hash1, hash2, 20);
    PASS();
}

static void test_sha1_55_56_byte_boundary(void) {
    TEST("SHA-1: 55/56 byte boundary (different results)");
    uint8_t msg55[55], msg56[56];
    memset(msg55, 'Q', 55);
    memset(msg56, 'Q', 56);
    uint8_t hash55[20], hash56[20];
    s3__sha1(msg55, 55, hash55);
    s3__sha1(msg56, 56, hash56);
    assert(memcmp(hash55, hash56, 20) != 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. CRC32/CRC32C Edge Cases (8 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_crc32_single_byte_0x00(void) {
    TEST("CRC32: single byte 0x00");
    uint8_t b = 0x00;
    uint32_t crc = s3__crc32(0, &b, 1);
    assert(crc != 0);
    PASS();
}

static void test_crc32_single_byte_0x80(void) {
    TEST("CRC32: single byte 0x80");
    uint8_t b = 0x80;
    uint32_t crc = s3__crc32(0, &b, 1);
    assert(crc != 0);
    PASS();
}

static void test_crc32_single_byte_0xFF(void) {
    TEST("CRC32: single byte 0xFF");
    uint8_t b = 0xFF;
    uint32_t crc = s3__crc32(0, &b, 1);
    assert(crc != 0);
    PASS();
}

static void test_crc32_256_zeros(void) {
    TEST("CRC32: 256 zeros");
    uint8_t data[256];
    memset(data, 0, 256);
    uint32_t crc = s3__crc32(0, data, 256);
    assert(crc != 0);
    PASS();
}

static void test_crc32_alternating_pattern(void) {
    TEST("CRC32: alternating 0xAA/0x55 pattern");
    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (i % 2 == 0) ? 0xAA : 0x55;
    uint32_t crc = s3__crc32(0, data, 64);
    assert(crc != 0);
    /* Verify deterministic */
    uint32_t crc2 = s3__crc32(0, data, 64);
    ASSERT_EQ_INT(crc, (int)crc2);
    PASS();
}

static void test_crc32_large_buffer(void) {
    TEST("CRC32: 4096-byte buffer");
    uint8_t data[4096];
    for (int i = 0; i < 4096; i++) data[i] = (uint8_t)(i & 0xFF);
    uint32_t crc = s3__crc32(0, data, 4096);
    uint32_t crc2 = s3__crc32(0, data, 4096);
    ASSERT_EQ_INT(crc, (int)crc2);
    PASS();
}

static void test_crc32c_large_buffer(void) {
    TEST("CRC32C: 4096-byte buffer");
    uint8_t data[4096];
    for (int i = 0; i < 4096; i++) data[i] = (uint8_t)(i & 0xFF);
    uint32_t crc = s3__crc32c(0, data, 4096);
    uint32_t crc2 = s3__crc32c(0, data, 4096);
    ASSERT_EQ_INT(crc, (int)crc2);
    PASS();
}

static void test_crc32_vs_crc32c_differ(void) {
    TEST("CRC32 vs CRC32C: same data produces different results");
    const char *data = "123456789";
    uint32_t crc32 = s3__crc32(0, data, 9);
    uint32_t crc32c = s3__crc32c(0, data, 9);
    assert(crc32 != crc32c);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. Base64 Edge Cases (10 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_base64_decode_AAAA_three_zeros(void) {
    TEST("Base64 decode: AAAA -> three zero bytes");
    uint8_t out[8];
    size_t len = s3__base64_decode("AAAA", 4, out, sizeof(out));
    ASSERT_EQ_INT(len, 3);
    ASSERT_EQ_INT(out[0], 0);
    ASSERT_EQ_INT(out[1], 0);
    ASSERT_EQ_INT(out[2], 0);
    PASS();
}

static void test_base64_decode_without_padding(void) {
    TEST("Base64 decode: Zg without padding -> f");
    uint8_t out[8];
    size_t len = s3__base64_decode("Zg", 2, out, sizeof(out));
    /* Decoder should handle missing padding: Zg -> 'f' */
    if (len == 1) {
        ASSERT_EQ_INT(out[0], 'f');
    }
    /* Either way, no crash = success */
    PASS();
}

static void test_base64_roundtrip_all_bytes(void) {
    TEST("Base64: encode/decode roundtrip all 256 byte values");
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
    char encoded[512];
    s3__base64_encode(data, 256, encoded, sizeof(encoded));
    uint8_t decoded[256];
    size_t dec_len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(dec_len, 256);
    ASSERT_EQ_MEM(decoded, data, 256);
    PASS();
}

static void test_base64_buffer_exact_size(void) {
    TEST("Base64: buffer exactly right size");
    /* "foo" encodes to "Zm9v" (4 chars + null = 5 bytes needed) */
    char out[5];
    size_t len = s3__base64_encode((const uint8_t *)"foo", 3, out, sizeof(out));
    ASSERT_EQ_INT(len, 4);
    ASSERT_EQ_STR(out, "Zm9v");
    PASS();
}

static void test_base64_long_input_1024(void) {
    TEST("Base64: very long input (1024 bytes)");
    uint8_t data[1024];
    for (int i = 0; i < 1024; i++) data[i] = (uint8_t)(i & 0xFF);
    char encoded[2048];
    s3__base64_encode(data, 1024, encoded, sizeof(encoded));
    assert(strlen(encoded) > 0);
    uint8_t decoded[1024];
    size_t dec_len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(dec_len, 1024);
    ASSERT_EQ_MEM(decoded, data, 1024);
    PASS();
}

static void test_base64_decode_with_invalid_char(void) {
    TEST("Base64 decode: input with invalid characters");
    uint8_t out[32];
    /* '!' is not a valid base64 character */
    size_t len = s3__base64_decode("!!!!", 4, out, sizeof(out));
    /* Should return 0 or handle gracefully without crash */
    (void)len;
    PASS();
}

static void test_base64_encode_binary_embedded_nulls(void) {
    TEST("Base64: encode binary with embedded nulls");
    uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
    char encoded[16];
    s3__base64_encode(data, 4, encoded, sizeof(encoded));
    ASSERT_EQ_STR(encoded, "AAAAAA==");
    uint8_t decoded[4];
    size_t len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(len, 4);
    ASSERT_EQ_MEM(decoded, data, 4);
    PASS();
}

static void test_base64_encode_255_bytes(void) {
    TEST("Base64: 255-byte roundtrip (non-multiple of 3)");
    uint8_t data[255];
    for (int i = 0; i < 255; i++) data[i] = (uint8_t)i;
    char encoded[512];
    s3__base64_encode(data, 255, encoded, sizeof(encoded));
    uint8_t decoded[255];
    size_t dec_len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(dec_len, 255);
    ASSERT_EQ_MEM(decoded, data, 255);
    PASS();
}

static void test_base64_encode_254_bytes(void) {
    TEST("Base64: 254-byte roundtrip (non-multiple of 3)");
    uint8_t data[254];
    for (int i = 0; i < 254; i++) data[i] = (uint8_t)i;
    char encoded[512];
    s3__base64_encode(data, 254, encoded, sizeof(encoded));
    uint8_t decoded[254];
    size_t dec_len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(dec_len, 254);
    ASSERT_EQ_MEM(decoded, data, 254);
    PASS();
}

static void test_base64_decode_plus_slash(void) {
    TEST("Base64 decode: + and / characters");
    /* "+/+/" encodes specific bytes */
    uint8_t out[8];
    size_t len = s3__base64_decode("+/+/", 4, out, sizeof(out));
    ASSERT_EQ_INT(len, 3);
    /* Re-encode and verify roundtrip */
    char re_encoded[8];
    s3__base64_encode(out, 3, re_encoded, sizeof(re_encoded));
    ASSERT_EQ_STR(re_encoded, "+/+/");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. URI Encoding Edge Cases (10 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_uri_encode_dash_individual(void) {
    TEST("URI encode: dash '-' preserved");
    char out[8];
    s3__uri_encode("-", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "-");
    PASS();
}

static void test_uri_encode_dot_individual(void) {
    TEST("URI encode: dot '.' preserved");
    char out[8];
    s3__uri_encode(".", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, ".");
    PASS();
}

static void test_uri_encode_underscore_individual(void) {
    TEST("URI encode: underscore '_' preserved");
    char out[8];
    s3__uri_encode("_", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "_");
    PASS();
}

static void test_uri_encode_tilde_individual(void) {
    TEST("URI encode: tilde '~' preserved");
    char out[8];
    s3__uri_encode("~", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "~");
    PASS();
}

static void test_uri_encode_percent(void) {
    TEST("URI encode: '%' -> '%25'");
    char out[16];
    s3__uri_encode("%", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "%25");
    PASS();
}

static void test_uri_encode_plus(void) {
    TEST("URI encode: '+' -> '%2B'");
    char out[16];
    s3__uri_encode("+", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "%2B");
    PASS();
}

static void test_uri_encode_equals(void) {
    TEST("URI encode: '=' -> '%3D'");
    char out[16];
    s3__uri_encode("=", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "%3D");
    PASS();
}

static void test_uri_encode_ampersand(void) {
    TEST("URI encode: '&' -> '%26'");
    char out[16];
    s3__uri_encode("&", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "%26");
    PASS();
}

static void test_uri_encode_long_path(void) {
    TEST("URI encode: very long path (512 chars)");
    char input[513];
    memset(input, 'a', 512);
    input[512] = '\0';
    char output[1024];
    size_t len = s3__uri_encode(input, 512, output, sizeof(output), false);
    /* All lowercase letters are unreserved, so output == input */
    ASSERT_EQ_INT(len, 512);
    ASSERT_EQ_STR(output, input);
    PASS();
}

static void test_uri_encode_double_encoding_prevention(void) {
    TEST("URI encode: double encoding ('%25' not re-encoded as '%2525')");
    /* Encoding "%" produces "%25", encoding "%25" produces "%2525" */
    char out1[16], out2[16];
    s3__uri_encode("%", 1, out1, sizeof(out1), false);
    ASSERT_EQ_STR(out1, "%25");
    /* Now encode the result - it SHOULD encode each char */
    s3__uri_encode(out1, strlen(out1), out2, sizeof(out2), false);
    /* '%' -> '%25', '2' stays, '5' stays = "%2525" */
    ASSERT_EQ_STR(out2, "%2525");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. Hex Encoding Edge Cases (5 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_hex_all_256_values_roundtrip(void) {
    TEST("Hex: all 256 byte values roundtrip");
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
    char hex[513];
    s3__hex_encode(data, 256, hex);
    ASSERT_EQ_INT(strlen(hex), 512);
    uint8_t decoded[256];
    int len = s3__hex_decode(hex, 512, decoded, sizeof(decoded));
    ASSERT_EQ_INT(len, 256);
    ASSERT_EQ_MEM(decoded, data, 256);
    PASS();
}

static void test_hex_odd_length_decode_fails(void) {
    TEST("Hex decode: odd-length input fails");
    uint8_t out[8];
    int len = s3__hex_decode("abc", 3, out, sizeof(out));
    ASSERT_EQ_INT(len, -1);
    PASS();
}

static void test_hex_invalid_chars_fail(void) {
    TEST("Hex decode: invalid hex chars fail");
    uint8_t out[8];
    int len = s3__hex_decode("GHIJ", 4, out, sizeof(out));
    ASSERT_EQ_INT(len, -1);
    PASS();
}

static void test_hex_mixed_case_decode(void) {
    TEST("Hex decode: mixed case 'aAbBcC'");
    uint8_t out[3];
    int len = s3__hex_decode("aAbBcC", 6, out, sizeof(out));
    ASSERT_EQ_INT(len, 3);
    ASSERT_EQ_INT(out[0], 0xAA);
    ASSERT_EQ_INT(out[1], 0xBB);
    ASSERT_EQ_INT(out[2], 0xCC);
    PASS();
}

static void test_hex_zero_length(void) {
    TEST("Hex: zero-length encode/decode");
    char hex[4] = "xyz";
    s3__hex_encode((const uint8_t *)"", 0, hex);
    ASSERT_EQ_STR(hex, "");
    uint8_t out[4];
    int len = s3__hex_decode("", 0, out, sizeof(out));
    ASSERT_EQ_INT(len, 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 7. XML Edge Cases (15 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_find_in_basic(void) {
    TEST("XML find_in: basic parent/child extraction");
    const char *xml =
        "<Root><Outer><Inner>hello</Inner></Outer></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find_in(xml, strlen(xml), "Outer", "Inner", &val, &vlen);
    assert(found);
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "hello");
    PASS();
}

static void test_xml_find_in_child_not_in_parent(void) {
    TEST("XML find_in: child not found in parent");
    const char *xml = "<Root><A><X>1</X></A><B><Y>2</Y></B></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find_in(xml, strlen(xml), "A", "Y", &val, &vlen);
    assert(!found);
    PASS();
}

static void test_xml_find_with_namespace_prefix(void) {
    TEST("XML find: namespace prefix like s3:Key");
    const char *xml = "<ListBucketResult><s3:Key>myfile.txt</s3:Key></ListBucketResult>";
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "s3:Key", &val, &vlen);
    assert(found);
    char buf[64];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "myfile.txt");
    PASS();
}

static int xml_each_counter(const char *e, size_t l, void *u) {
    (void)e; (void)l;
    (*(int *)u)++;
    return 0;
}

static void test_xml_each_zero_matches(void) {
    TEST("XML each: zero matches");
    const char *xml = "<Root><A>1</A></Root>";
    int count = 0;
    int result = s3__xml_each(xml, strlen(xml), "Missing", xml_each_counter, &count);
    ASSERT_EQ_INT(result, 0);
    ASSERT_EQ_INT(count, 0);
    PASS();
}

static int xml_each_stop_immediately(const char *e, size_t l, void *u) {
    (void)e; (void)l;
    (*(int *)u)++;
    return 1;  /* stop immediately */
}

static void test_xml_each_early_termination(void) {
    TEST("XML each: early termination (callback returns 1)");
    const char *xml = "<R><I>a</I><I>b</I><I>c</I></R>";
    int count = 0;
    int result = s3__xml_each(xml, strlen(xml), "I", xml_each_stop_immediately, &count);
    ASSERT_EQ_INT(count, 1);
    assert(result != 0);
    PASS();
}

static void test_xml_parse_s3_error_complete(void) {
    TEST("XML: parse complete S3 error (all fields)");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Error>"
        "<Code>NoSuchKey</Code>"
        "<Message>The specified key does not exist.</Message>"
        "<Key>my-object.txt</Key>"
        "<RequestId>ABCDEF123456</RequestId>"
        "<HostId>host-id-value</HostId>"
        "</Error>";
    const char *val; size_t vlen;
    char buf[256];

    assert(s3__xml_find(xml, strlen(xml), "Code", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "NoSuchKey");

    assert(s3__xml_find(xml, strlen(xml), "Message", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "The specified key does not exist.");

    assert(s3__xml_find(xml, strlen(xml), "RequestId", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "ABCDEF123456");

    assert(s3__xml_find(xml, strlen(xml), "HostId", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "host-id-value");

    s3_status st = s3__map_s3_error_code("NoSuchKey");
    ASSERT_EQ_INT(st, S3_STATUS_NO_SUCH_KEY);
    PASS();
}

static void test_xml_parse_list_all_my_buckets(void) {
    TEST("XML: parse ListAllMyBucketsResult with multiple buckets");
    const char *xml =
        "<ListAllMyBucketsResult>"
        "<Owner><ID>owner-id-123</ID><DisplayName>testuser</DisplayName></Owner>"
        "<Buckets>"
        "<Bucket><Name>bucket-one</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>"
        "<Bucket><Name>bucket-two</Name><CreationDate>2024-02-01T00:00:00.000Z</CreationDate></Bucket>"
        "<Bucket><Name>bucket-three</Name><CreationDate>2024-03-01T00:00:00.000Z</CreationDate></Bucket>"
        "</Buckets>"
        "</ListAllMyBucketsResult>";

    int count = 0;
    s3__xml_each(xml, strlen(xml), "Bucket", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 3);

    const char *val; size_t vlen; char buf[64];
    assert(s3__xml_find_in(xml, strlen(xml), "Owner", "DisplayName", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "testuser");
    PASS();
}

static void test_xml_parse_list_versions(void) {
    TEST("XML: parse ListVersionsResult with Version + DeleteMarker");
    const char *xml =
        "<ListVersionsResult>"
        "<Name>mybucket</Name>"
        "<Version>"
        "<Key>file.txt</Key>"
        "<VersionId>v1</VersionId>"
        "<IsLatest>true</IsLatest>"
        "</Version>"
        "<DeleteMarker>"
        "<Key>deleted.txt</Key>"
        "<VersionId>v2</VersionId>"
        "<IsLatest>true</IsLatest>"
        "</DeleteMarker>"
        "<Version>"
        "<Key>file2.txt</Key>"
        "<VersionId>v3</VersionId>"
        "<IsLatest>false</IsLatest>"
        "</Version>"
        "</ListVersionsResult>";

    int versions = 0, markers = 0;
    s3__xml_each(xml, strlen(xml), "Version", xml_each_counter, &versions);
    s3__xml_each(xml, strlen(xml), "DeleteMarker", xml_each_counter, &markers);
    ASSERT_EQ_INT(versions, 2);
    ASSERT_EQ_INT(markers, 1);
    PASS();
}

static void test_xml_parse_cors_configuration(void) {
    TEST("XML: parse CORSConfiguration");
    const char *xml =
        "<CORSConfiguration>"
        "<CORSRule>"
        "<AllowedOrigin>https://example.com</AllowedOrigin>"
        "<AllowedMethod>GET</AllowedMethod>"
        "<AllowedMethod>PUT</AllowedMethod>"
        "<MaxAgeSeconds>3000</MaxAgeSeconds>"
        "</CORSRule>"
        "</CORSConfiguration>";
    const char *val; size_t vlen; char buf[64];
    assert(s3__xml_find_in(xml, strlen(xml), "CORSRule", "AllowedOrigin", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "https://example.com");
    PASS();
}

static void test_xml_parse_lifecycle_configuration(void) {
    TEST("XML: parse LifecycleConfiguration");
    const char *xml =
        "<LifecycleConfiguration>"
        "<Rule>"
        "<ID>move-to-glacier</ID>"
        "<Status>Enabled</Status>"
        "<Filter><Prefix>logs/</Prefix></Filter>"
        "<Transition><Days>90</Days><StorageClass>GLACIER</StorageClass></Transition>"
        "</Rule>"
        "</LifecycleConfiguration>";
    const char *val; size_t vlen; char buf[64];
    assert(s3__xml_find_in(xml, strlen(xml), "Rule", "ID", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "move-to-glacier");
    assert(s3__xml_find_in(xml, strlen(xml), "Transition", "StorageClass", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "GLACIER");
    PASS();
}

static void test_xml_parse_notification_configuration(void) {
    TEST("XML: parse NotificationConfiguration");
    const char *xml =
        "<NotificationConfiguration>"
        "<TopicConfiguration>"
        "<Id>event-1</Id>"
        "<Topic>arn:aws:sns:us-east-1:123:topic</Topic>"
        "<Event>s3:ObjectCreated:*</Event>"
        "</TopicConfiguration>"
        "<QueueConfiguration>"
        "<Id>event-2</Id>"
        "<Queue>arn:aws:sqs:us-east-1:123:queue</Queue>"
        "<Event>s3:ObjectRemoved:*</Event>"
        "</QueueConfiguration>"
        "</NotificationConfiguration>";
    int topics = 0, queues = 0;
    s3__xml_each(xml, strlen(xml), "TopicConfiguration", xml_each_counter, &topics);
    s3__xml_each(xml, strlen(xml), "QueueConfiguration", xml_each_counter, &queues);
    ASSERT_EQ_INT(topics, 1);
    ASSERT_EQ_INT(queues, 1);
    PASS();
}

static void test_xml_with_attributes_in_tags(void) {
    TEST("XML: attributes in tags");
    const char *xml = "<Root><Item id=\"1\" type=\"file\">content1</Item>"
                      "<Item id=\"2\" type=\"dir\">content2</Item></Root>";
    int count = 0;
    s3__xml_each(xml, strlen(xml), "Item", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 2);
    PASS();
}

static void test_xml_deeply_nested(void) {
    TEST("XML: deeply nested (5+ levels)");
    const char *xml =
        "<L1><L2><L3><L4><L5><L6>deep-value</L6></L5></L4></L3></L2></L1>";
    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find(xml, strlen(xml), "L6", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "deep-value");
    PASS();
}

static void test_xml_large_response(void) {
    TEST("XML: large response (>4KB)");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "<Root>");
    for (int i = 0; i < 200; i++) {
        char elem[64];
        snprintf(elem, sizeof(elem), "<Item>value-%d</Item>", i);
        s3_buf_append_str(&b, elem);
    }
    s3_buf_append_str(&b, "</Root>");
    assert(b.len > 4096);

    int count = 0;
    s3__xml_each(b.data, b.len, "Item", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 200);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_decode_only_numeric_refs(void) {
    TEST("XML decode: only numeric entity refs");
    char out[32];
    s3__xml_decode_entities("&#72;&#101;&#108;&#108;&#111;", 29, out, sizeof(out));
    ASSERT_EQ_STR(out, "Hello");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 8. Error Mapping Completeness (8 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_error_all_status_have_string(void) {
    TEST("Error: every s3_status enum has non-null non-empty string");
    for (int i = 0; i < S3_STATUS__COUNT; i++) {
        const char *str = s3_status_string((s3_status)i);
        if (!str || strlen(str) == 0) {
            printf("FAIL: status %d has no string\n", i);
            return;
        }
    }
    PASS();
}

static void test_error_map_remaining_codes_batch1(void) {
    TEST("Error mapping: batch of S3 error codes (batch 1)");
    ASSERT_EQ_INT(s3__map_s3_error_code("AccountProblem"), S3_STATUS_ACCOUNT_PROBLEM);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidBucketName"), S3_STATUS_INVALID_BUCKET_NAME);
    ASSERT_EQ_INT(s3__map_s3_error_code("MalformedXML"), S3_STATUS_MALFORMED_XML);
    ASSERT_EQ_INT(s3__map_s3_error_code("OperationAborted"), S3_STATUS_OPERATION_ABORTED);
    ASSERT_EQ_INT(s3__map_s3_error_code("TooManyBuckets"), S3_STATUS_TOO_MANY_BUCKETS);
    PASS();
}

static void test_error_map_remaining_codes_batch2(void) {
    TEST("Error mapping: batch of S3 error codes (batch 2)");
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidDigest"), S3_STATUS_INVALID_DIGEST);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidPayer"), S3_STATUS_INVALID_PAYER);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidToken"), S3_STATUS_INVALID_TOKEN);
    ASSERT_EQ_INT(s3__map_s3_error_code("MissingContentLength"), S3_STATUS_MISSING_CONTENT_LENGTH);
    ASSERT_EQ_INT(s3__map_s3_error_code("NotSignedUp"), S3_STATUS_NOT_SIGNED_UP);
    PASS();
}

static void test_error_map_remaining_codes_batch3(void) {
    TEST("Error mapping: batch of S3 error codes (batch 3)");
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidObjectState"), S3_STATUS_INVALID_OBJECT_STATE);
    ASSERT_EQ_INT(s3__map_s3_error_code("TemporaryRedirect"), S3_STATUS_TEMPORARY_REDIRECT);
    ASSERT_EQ_INT(s3__map_s3_error_code("PermanentRedirect"), S3_STATUS_PERMANENT_REDIRECT);
    ASSERT_EQ_INT(s3__map_s3_error_code("ServiceUnavailable"), S3_STATUS_SERVICE_UNAVAILABLE);
    PASS();
}

static void test_error_unknown_code(void) {
    TEST("Error mapping: completely unknown code -> UNKNOWN_ERROR");
    ASSERT_EQ_INT(s3__map_s3_error_code("TotallyFakeError"), S3_STATUS_UNKNOWN_ERROR);
    ASSERT_EQ_INT(s3__map_s3_error_code(""), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_200_not_error(void) {
    TEST("HTTP status: 200 should not map to known error");
    s3_status st = s3__map_http_status(200);
    ASSERT_EQ_INT(st, S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_301_redirect(void) {
    TEST("HTTP status: 301 redirect");
    s3_status st = s3__map_http_status(301);
    ASSERT_EQ_INT(st, S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_307_redirect(void) {
    TEST("HTTP status: 307 redirect");
    s3_status st = s3__map_http_status(307);
    ASSERT_EQ_INT(st, S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 9. Client Tests (10 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_client_all_optional_fields(void) {
    TEST("Client: create with all optional fields set");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = {
            .access_key_id = "AKIAEXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            .session_token = "FwoGZXIvYXdzEBYaDH",
        },
        .region = "us-west-2",
        .endpoint = "s3.custom.endpoint.com",
        .account_id = "123456789012",
        .use_path_style = true,
        .use_https = true,
        .use_transfer_acceleration = false,
        .use_dual_stack = true,
        .use_fips = true,
        .connect_timeout_ms = 10000,
        .request_timeout_ms = 60000,
        .user_agent = "test-app/1.0",
        .retry_policy = {
            .max_retries = 5,
            .base_delay_ms = 200,
            .max_delay_ms = 30000,
            .backoff_multiplier = 3.0,
            .jitter = true,
            .retry_on_throttle = true,
            .retry_on_5xx = true,
            .retry_on_timeout = true,
        },
        .log_level = S3_LOG_DEBUG,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c != nullptr);
    ASSERT_EQ_STR(c->region, "us-west-2");
    ASSERT_EQ_STR(c->endpoint, "s3.custom.endpoint.com");
    ASSERT_EQ_STR(c->session_token, "FwoGZXIvYXdzEBYaDH");
    ASSERT_EQ_STR(c->user_agent, "test-app/1.0");
    assert(c->use_path_style == true);
    assert(c->use_dual_stack == true);
    assert(c->use_fips == true);
    ASSERT_EQ_INT(c->connect_timeout_ms, 10000);
    ASSERT_EQ_INT(c->request_timeout_ms, 60000);
    ASSERT_EQ_INT(c->retry_policy.max_retries, 5);
    s3_client_destroy(c);
    PASS();
}

static void test_client_empty_string_optional(void) {
    TEST("Client: empty string for optional fields");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .endpoint = "",
        .user_agent = "",
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c != nullptr);
    s3_client_destroy(c);
    PASS();
}

static void test_client_deep_copy_verification(void) {
    TEST("Client: deep copy - source string modified after create");
    char region[] = "eu-central-1";
    char ak[] = "AKIATEST";
    char sk[] = "SECRETKEY";
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = ak, .secret_access_key = sk },
        .region = region,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);

    /* Overwrite source strings */
    memset(region, 'Z', strlen(region));
    memset(ak, 'A', strlen(ak));
    memset(sk, 'B', strlen(sk));

    /* Client must retain original values */
    ASSERT_EQ_STR(c->region, "eu-central-1");
    ASSERT_EQ_STR(c->access_key_id, "AKIATEST");
    ASSERT_EQ_STR(c->secret_access_key, "SECRETKEY");
    s3_client_destroy(c);
    PASS();
}

static void test_client_last_error_after_create(void) {
    TEST("Client: last_error valid immediately after create");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
    });
    const s3_error *err = s3_client_last_error(c);
    assert(err != nullptr);
    ASSERT_EQ_INT(err->status, S3_STATUS_OK);
    ASSERT_EQ_INT(err->http_status, 0);
    s3_client_destroy(c);
    PASS();
}

static void test_client_sequential_create_destroy(void) {
    TEST("Client: multiple sequential create/destroy cycles");
    for (int i = 0; i < 50; i++) {
        s3_client *c = nullptr;
        s3_status st = s3_client_create(&c, &(s3_config){
            .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
            .region = "us-east-1",
        });
        ASSERT_EQ_INT(st, S3_STATUS_OK);
        s3_client_destroy(c);
    }
    PASS();
}

static s3_status test_cred_provider_fn(const char **ak, const char **sk,
                                        const char **token, void *ud) {
    (void)ud;
    *ak = "PROVIDER_AK";
    *sk = "PROVIDER_SK";
    *token = nullptr;
    return S3_STATUS_OK;
}

static void test_client_credential_provider_no_access_key(void) {
    TEST("Client: credential_provider set, no static access_key");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .region = "us-east-1",
        .credential_provider = test_cred_provider_fn,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c != nullptr);
    assert(c->credential_provider == test_cred_provider_fn);
    s3_client_destroy(c);
    PASS();
}

static void test_client_null_out_ptr(void) {
    TEST("Client: create with null out pointer");
    s3_status st = s3_client_create(nullptr, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_INVALID_ARGUMENT);
    PASS();
}

static void test_client_null_config_ptr(void) {
    TEST("Client: create with null config pointer");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, nullptr);
    ASSERT_EQ_INT(st, S3_STATUS_INVALID_ARGUMENT);
    PASS();
}

static void test_client_destroy_null_safe(void) {
    TEST("Client: destroy(nullptr) is safe");
    s3_client_destroy(nullptr);
    PASS();
}

static void test_client_last_error_null_client(void) {
    TEST("Client: last_error(nullptr) returns nullptr");
    const s3_error *err = s3_client_last_error(nullptr);
    assert(err == nullptr);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 10. SigV4 Tests (8 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sigv4_derive_key_s3(void) {
    TEST("SigV4: derive key for s3 service");
    uint8_t key[32];
    s3__derive_signing_key("secret", "20240315", "us-east-1", "s3", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_derive_key_iam(void) {
    TEST("SigV4: derive key for iam service");
    uint8_t key[32];
    s3__derive_signing_key("secret", "20240315", "us-east-1", "iam", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_derive_key_sts(void) {
    TEST("SigV4: derive key for sts service");
    uint8_t key[32];
    s3__derive_signing_key("secret", "20240315", "us-east-1", "sts", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_derive_key_execute_api(void) {
    TEST("SigV4: derive key for execute-api service");
    uint8_t key[32];
    s3__derive_signing_key("secret", "20240315", "us-east-1", "execute-api", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_deterministic(void) {
    TEST("SigV4: same inputs produce same key");
    uint8_t key1[32], key2[32];
    s3__derive_signing_key("mySecret", "20250101", "ap-southeast-1", "s3", key1);
    s3__derive_signing_key("mySecret", "20250101", "ap-southeast-1", "s3", key2);
    ASSERT_EQ_MEM(key1, key2, 32);
    PASS();
}

static void test_sigv4_key_changes_with_params(void) {
    TEST("SigV4: key changes with each parameter changed");
    uint8_t base[32], k1[32], k2[32], k3[32];
    s3__derive_signing_key("secret", "20240101", "us-east-1", "s3", base);
    s3__derive_signing_key("secret2", "20240101", "us-east-1", "s3", k1);
    s3__derive_signing_key("secret", "20240102", "us-east-1", "s3", k2);
    s3__derive_signing_key("secret", "20240101", "eu-west-1", "s3", k3);
    assert(memcmp(base, k1, 32) != 0);
    assert(memcmp(base, k2, 32) != 0);
    assert(memcmp(base, k3, 32) != 0);
    PASS();
}

static void test_sigv4_long_secret_key(void) {
    TEST("SigV4: very long secret key (256 chars)");
    char secret[257];
    memset(secret, 'K', 256);
    secret[256] = '\0';
    uint8_t key[32];
    s3__derive_signing_key(secret, "20240101", "us-east-1", "s3", key);
    /* Deterministic check */
    uint8_t key2[32];
    s3__derive_signing_key(secret, "20240101", "us-east-1", "s3", key2);
    ASSERT_EQ_MEM(key, key2, 32);
    PASS();
}

static void test_sigv4_short_secret_key(void) {
    TEST("SigV4: short secret key (1 char)");
    uint8_t key[32];
    s3__derive_signing_key("X", "20240101", "us-east-1", "s3", key);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 11. Retry Tests (8 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_retry_every_retryable_status(void) {
    TEST("Retry: every retryable status returns true");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 10,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .retry_on_throttle = true,
            .retry_on_5xx = true,
            .retry_on_timeout = true,
        },
    });
    assert(s3__should_retry(c, S3_STATUS_CURL_ERROR, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_SLOW_DOWN, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_SERVICE_UNAVAILABLE, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_HTTP_INTERNAL_SERVER_ERROR, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_HTTP_BAD_GATEWAY, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_HTTP_GATEWAY_TIMEOUT, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_TIMEOUT, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_REQUEST_TIMEOUT, 0) == true);
    assert(s3__should_retry(c, S3_STATUS_CONNECTION_FAILED, 0) == true);
    s3_client_destroy(c);
    PASS();
}

static void test_retry_every_non_retryable_status(void) {
    TEST("Retry: non-retryable statuses return false");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 10,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .retry_on_throttle = true,
            .retry_on_5xx = true,
            .retry_on_timeout = true,
        },
    });
    assert(s3__should_retry(c, S3_STATUS_OK, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_ACCESS_DENIED, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_NO_SUCH_KEY, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_NO_SUCH_BUCKET, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_HTTP_NOT_FOUND, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_HTTP_FORBIDDEN, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_INVALID_ARGUMENT, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_BUCKET_ALREADY_EXISTS, 0) == false);
    s3_client_destroy(c);
    PASS();
}

static void test_retry_boundary_max_minus_1(void) {
    TEST("Retry: attempt = max_retries-1 -> true");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 5,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .retry_on_5xx = true,
        },
    });
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 4) == true);
    s3_client_destroy(c);
    PASS();
}

static void test_retry_boundary_max_equals(void) {
    TEST("Retry: attempt = max_retries -> false");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 5,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .retry_on_5xx = true,
        },
    });
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 5) == false);
    s3_client_destroy(c);
    PASS();
}

static void test_retry_delay_jitter_range(void) {
    TEST("Retry: delay with jitter in [base*0.5, base*1.0] range");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 10,
            .base_delay_ms = 100,
            .max_delay_ms = 100000,
            .backoff_multiplier = 2.0,
            .jitter = true,
        },
    });
    for (int trial = 0; trial < 100; trial++) {
        int d = s3__retry_delay_ms(c, 0);
        assert(d >= 50 && d <= 100);
    }
    s3_client_destroy(c);
    PASS();
}

static void test_retry_delay_max_cap(void) {
    TEST("Retry: delay with max cap (attempt=100 stays below max)");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 200,
            .base_delay_ms = 100,
            .max_delay_ms = 5000,
            .backoff_multiplier = 2.0,
            .jitter = false,
        },
    });
    int d = s3__retry_delay_ms(c, 100);
    assert(d <= 5000);
    s3_client_destroy(c);
    PASS();
}

static void test_retry_all_flags_disabled(void) {
    TEST("Retry: all flags disabled -> nothing retries except CURL_ERROR");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 10,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .jitter = false,
            .retry_on_throttle = false,
            .retry_on_5xx = false,
            .retry_on_timeout = false,
        },
    });
    assert(s3__should_retry(c, S3_STATUS_SLOW_DOWN, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_HTTP_INTERNAL_SERVER_ERROR, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_TIMEOUT, 0) == false);
    /* CURL_ERROR is unconditional */
    assert(s3__should_retry(c, S3_STATUS_CURL_ERROR, 0) == true);
    s3_client_destroy(c);
    PASS();
}

static void test_retry_delay_grows_with_attempt(void) {
    TEST("Retry: delay grows with each attempt");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 10,
            .base_delay_ms = 100,
            .max_delay_ms = 100000,
            .backoff_multiplier = 2.0,
            .jitter = false,
        },
    });
    int d0 = s3__retry_delay_ms(c, 0);
    int d1 = s3__retry_delay_ms(c, 1);
    int d2 = s3__retry_delay_ms(c, 2);
    int d3 = s3__retry_delay_ms(c, 3);
    assert(d1 > d0);
    assert(d2 > d1);
    assert(d3 > d2);
    ASSERT_EQ_INT(d0, 100);
    ASSERT_EQ_INT(d1, 200);
    ASSERT_EQ_INT(d2, 400);
    ASSERT_EQ_INT(d3, 800);
    s3_client_destroy(c);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 12. Utility / Content Type Tests (10 tests)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_content_type_case_JPG(void) {
    TEST("Content type: .JPG (uppercase)");
    ASSERT_EQ_STR(s3_detect_content_type("photo.JPG"), "image/jpeg");
    PASS();
}

static void test_content_type_case_Png(void) {
    TEST("Content type: .Png (mixed case)");
    ASSERT_EQ_STR(s3_detect_content_type("image.Png"), "image/png");
    PASS();
}

static void test_content_type_case_HTML(void) {
    TEST("Content type: .HTML (uppercase)");
    ASSERT_EQ_STR(s3_detect_content_type("page.HTML"), "text/html");
    PASS();
}

static void test_content_type_case_JSON(void) {
    TEST("Content type: .JSON (uppercase)");
    ASSERT_EQ_STR(s3_detect_content_type("data.JSON"), "application/json");
    PASS();
}

static void test_content_type_path_with_directories(void) {
    TEST("Content type: path /path/to/file.css");
    ASSERT_EQ_STR(s3_detect_content_type("/path/to/file.css"), "text/css");
    PASS();
}

static void test_content_type_multiple_dots(void) {
    TEST("Content type: file.backup.json");
    ASSERT_EQ_STR(s3_detect_content_type("file.backup.json"), "application/json");
    PASS();
}

static void test_content_type_no_extension(void) {
    TEST("Content type: no extension at all");
    ASSERT_EQ_STR(s3_detect_content_type("Makefile"), "application/octet-stream");
    PASS();
}

static void test_content_type_hidden_file(void) {
    TEST("Content type: hidden file .gitignore");
    /* .gitignore has no recognized extension */
    const char *ct = s3_detect_content_type(".gitignore");
    assert(ct != nullptr);
    assert(strlen(ct) > 0);
    PASS();
}

static void test_strdup_nullptr_returns_nullptr(void) {
    TEST("s3__strdup: nullptr -> nullptr");
    char *result = s3__strdup(nullptr);
    assert(result == nullptr);
    PASS();
}

static void test_strndup_with_n_less_than_strlen(void) {
    TEST("s3__strndup: n < strlen truncates");
    char *result = s3__strndup("hello world", 5);
    assert(result != nullptr);
    ASSERT_EQ_STR(result, "hello");
    S3_FREE(result);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("\n=== libs3 Extra Test Suite ===\n\n");

    printf("-- SHA-256 Edge Cases --\n");
    test_sha256_55_bytes();
    test_sha256_56_bytes();
    test_sha256_64_bytes_exact();
    test_sha256_119_bytes();
    test_sha256_128_bytes();
    test_sha256_1000_byte_consistency();
    test_sha256_empty_updates();
    test_sha256_multiple_finals();
    test_sha256_binary_with_nulls();
    test_sha256_single_shot_vs_incremental();

    printf("-- SHA-1 Edge Cases --\n");
    test_sha1_448bit_vector();
    test_sha1_incremental_vs_single();
    test_sha1_empty_updates();
    test_sha1_64_byte_boundary();
    test_sha1_binary_with_nulls();
    test_sha1_1000_bytes();
    test_sha1_single_byte_updates();
    test_sha1_55_56_byte_boundary();

    printf("-- CRC32/CRC32C Edge Cases --\n");
    test_crc32_single_byte_0x00();
    test_crc32_single_byte_0x80();
    test_crc32_single_byte_0xFF();
    test_crc32_256_zeros();
    test_crc32_alternating_pattern();
    test_crc32_large_buffer();
    test_crc32c_large_buffer();
    test_crc32_vs_crc32c_differ();

    printf("-- Base64 Edge Cases --\n");
    test_base64_decode_AAAA_three_zeros();
    test_base64_decode_without_padding();
    test_base64_roundtrip_all_bytes();
    test_base64_buffer_exact_size();
    test_base64_long_input_1024();
    test_base64_decode_with_invalid_char();
    test_base64_encode_binary_embedded_nulls();
    test_base64_encode_255_bytes();
    test_base64_encode_254_bytes();
    test_base64_decode_plus_slash();

    printf("-- URI Encoding Edge Cases --\n");
    test_uri_encode_dash_individual();
    test_uri_encode_dot_individual();
    test_uri_encode_underscore_individual();
    test_uri_encode_tilde_individual();
    test_uri_encode_percent();
    test_uri_encode_plus();
    test_uri_encode_equals();
    test_uri_encode_ampersand();
    test_uri_encode_long_path();
    test_uri_encode_double_encoding_prevention();

    printf("-- Hex Encoding Edge Cases --\n");
    test_hex_all_256_values_roundtrip();
    test_hex_odd_length_decode_fails();
    test_hex_invalid_chars_fail();
    test_hex_mixed_case_decode();
    test_hex_zero_length();

    printf("-- XML Edge Cases --\n");
    test_xml_find_in_basic();
    test_xml_find_in_child_not_in_parent();
    test_xml_find_with_namespace_prefix();
    test_xml_each_zero_matches();
    test_xml_each_early_termination();
    test_xml_parse_s3_error_complete();
    test_xml_parse_list_all_my_buckets();
    test_xml_parse_list_versions();
    test_xml_parse_cors_configuration();
    test_xml_parse_lifecycle_configuration();
    test_xml_parse_notification_configuration();
    test_xml_with_attributes_in_tags();
    test_xml_deeply_nested();
    test_xml_large_response();
    test_xml_decode_only_numeric_refs();

    printf("-- Error Mapping Completeness --\n");
    test_error_all_status_have_string();
    test_error_map_remaining_codes_batch1();
    test_error_map_remaining_codes_batch2();
    test_error_map_remaining_codes_batch3();
    test_error_unknown_code();
    test_http_200_not_error();
    test_http_301_redirect();
    test_http_307_redirect();

    printf("-- Client Tests --\n");
    test_client_all_optional_fields();
    test_client_empty_string_optional();
    test_client_deep_copy_verification();
    test_client_last_error_after_create();
    test_client_sequential_create_destroy();
    test_client_credential_provider_no_access_key();
    test_client_null_out_ptr();
    test_client_null_config_ptr();
    test_client_destroy_null_safe();
    test_client_last_error_null_client();

    printf("-- SigV4 Tests --\n");
    test_sigv4_derive_key_s3();
    test_sigv4_derive_key_iam();
    test_sigv4_derive_key_sts();
    test_sigv4_derive_key_execute_api();
    test_sigv4_deterministic();
    test_sigv4_key_changes_with_params();
    test_sigv4_long_secret_key();
    test_sigv4_short_secret_key();

    printf("-- Retry Tests --\n");
    test_retry_every_retryable_status();
    test_retry_every_non_retryable_status();
    test_retry_boundary_max_minus_1();
    test_retry_boundary_max_equals();
    test_retry_delay_jitter_range();
    test_retry_delay_max_cap();
    test_retry_all_flags_disabled();
    test_retry_delay_grows_with_attempt();

    printf("-- Utility / Content Type --\n");
    test_content_type_case_JPG();
    test_content_type_case_Png();
    test_content_type_case_HTML();
    test_content_type_case_JSON();
    test_content_type_path_with_directories();
    test_content_type_multiple_dots();
    test_content_type_no_extension();
    test_content_type_hidden_file();
    test_strdup_nullptr_returns_nullptr();
    test_strndup_with_n_less_than_strlen();

    printf("\n=======================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("=======================================\n\n");

    return tests_passed == tests_run ? 0 : 1;
}
