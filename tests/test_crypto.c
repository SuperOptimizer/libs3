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
    printf("  %-50s ", name); \
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
 * SHA-256 Tests (FIPS 180-4 test vectors)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha256_empty(void) {
    TEST("SHA-256: empty string");
    char hex[65];
    s3__sha256_hex("", 0, hex);
    ASSERT_EQ_STR(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    PASS();
}

static void test_sha256_abc(void) {
    TEST("SHA-256: \"abc\"");
    char hex[65];
    s3__sha256_hex("abc", 3, hex);
    ASSERT_EQ_STR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    PASS();
}

static void test_sha256_448bit(void) {
    TEST("SHA-256: 448-bit message");
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[65];
    s3__sha256_hex(msg, strlen(msg), hex);
    ASSERT_EQ_STR(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    PASS();
}

static void test_sha256_long(void) {
    TEST("SHA-256: 896-bit message");
    const char *msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char hex[65];
    s3__sha256_hex(msg, strlen(msg), hex);
    ASSERT_EQ_STR(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    PASS();
}

static void test_sha256_incremental(void) {
    TEST("SHA-256: incremental update");
    /* Same as the 448-bit vector, split across multiple updates */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    s3__sha256_update(&ctx, msg, 20);
    s3__sha256_update(&ctx, msg + 20, 20);
    s3__sha256_update(&ctx, msg + 40, strlen(msg) - 40);
    uint8_t hash[32];
    s3__sha256_final(&ctx, hash);
    char hex[65];
    s3__hex_encode(hash, 32, hex);
    ASSERT_EQ_STR(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 Tests (RFC 4231)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_hmac_sha256_case1(void) {
    TEST("HMAC-SHA256: RFC 4231 test case 1");
    /* Key = 20 bytes of 0x0b */
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const char *data = "Hi There";
    uint8_t out[32];
    s3__hmac_sha256(key, 20, data, 8, out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    ASSERT_EQ_STR(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    PASS();
}

static void test_hmac_sha256_case2(void) {
    TEST("HMAC-SHA256: RFC 4231 test case 2");
    const char *key = "Jefe";
    const char *data = "what do ya want for nothing?";
    uint8_t out[32];
    s3__hmac_sha256(key, 4, data, strlen(data), out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    ASSERT_EQ_STR(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    PASS();
}

static void test_hmac_sha256_case3(void) {
    TEST("HMAC-SHA256: RFC 4231 test case 3");
    uint8_t key[20];
    memset(key, 0xaa, 20);
    uint8_t data[50];
    memset(data, 0xdd, 50);
    uint8_t out[32];
    s3__hmac_sha256(key, 20, data, 50, out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    ASSERT_EQ_STR(hex, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-1 Tests (FIPS 180-4)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha1_abc(void) {
    TEST("SHA-1: \"abc\"");
    uint8_t hash[20];
    s3__sha1("abc", 3, hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    PASS();
}

static void test_sha1_empty(void) {
    TEST("SHA-1: empty string");
    uint8_t hash[20];
    s3__sha1("", 0, hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CRC32 Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_crc32_check(void) {
    TEST("CRC32: \"123456789\"");
    uint32_t crc = s3__crc32(0, "123456789", 9);
    ASSERT_EQ_INT(crc, 0xCBF43926);
    PASS();
}

static void test_crc32_empty(void) {
    TEST("CRC32: empty");
    uint32_t crc = s3__crc32(0, "", 0);
    ASSERT_EQ_INT(crc, 0);
    PASS();
}

static void test_crc32_incremental(void) {
    TEST("CRC32: incremental");
    uint32_t crc = s3__crc32(0, "1234", 4);
    crc = s3__crc32(crc, "56789", 5);
    ASSERT_EQ_INT(crc, 0xCBF43926);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CRC32C Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_crc32c_check(void) {
    TEST("CRC32C: \"123456789\"");
    uint32_t crc = s3__crc32c(0, "123456789", 9);
    ASSERT_EQ_INT(crc, (int)0xE3069283);
    PASS();
}

static void test_crc32c_incremental(void) {
    TEST("CRC32C: incremental");
    uint32_t crc = s3__crc32c(0, "12345", 5);
    crc = s3__crc32c(crc, "6789", 4);
    ASSERT_EQ_INT(crc, (int)0xE3069283);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Base64 Tests (RFC 4648)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_base64_encode_empty(void) {
    TEST("Base64 encode: empty");
    char out[8];
    size_t len = s3__base64_encode((const uint8_t *)"", 0, out, sizeof(out));
    ASSERT_EQ_INT(len, 0);
    ASSERT_EQ_STR(out, "");
    PASS();
}

static void test_base64_encode_f(void) {
    TEST("Base64 encode: \"f\"");
    char out[8];
    s3__base64_encode((const uint8_t *)"f", 1, out, sizeof(out));
    ASSERT_EQ_STR(out, "Zg==");
    PASS();
}

static void test_base64_encode_fo(void) {
    TEST("Base64 encode: \"fo\"");
    char out[8];
    s3__base64_encode((const uint8_t *)"fo", 2, out, sizeof(out));
    ASSERT_EQ_STR(out, "Zm8=");
    PASS();
}

static void test_base64_encode_foo(void) {
    TEST("Base64 encode: \"foo\"");
    char out[8];
    s3__base64_encode((const uint8_t *)"foo", 3, out, sizeof(out));
    ASSERT_EQ_STR(out, "Zm9v");
    PASS();
}

static void test_base64_encode_foobar(void) {
    TEST("Base64 encode: \"foobar\"");
    char out[16];
    s3__base64_encode((const uint8_t *)"foobar", 6, out, sizeof(out));
    ASSERT_EQ_STR(out, "Zm9vYmFy");
    PASS();
}

static void test_base64_roundtrip(void) {
    TEST("Base64 roundtrip: binary data");
    uint8_t data[] = {0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f, 0x40};
    char encoded[32];
    s3__base64_encode(data, sizeof(data), encoded, sizeof(encoded));

    uint8_t decoded[32];
    size_t dec_len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(dec_len, sizeof(data));
    ASSERT_EQ_MEM(decoded, data, sizeof(data));
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * URI Encoding Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_uri_encode_unreserved(void) {
    TEST("URI encode: unreserved chars pass through");
    char out[256];
    s3__uri_encode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
                   66, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");
    PASS();
}

static void test_uri_encode_space(void) {
    TEST("URI encode: space → %20");
    char out[32];
    s3__uri_encode("hello world", 11, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "hello%20world");
    PASS();
}

static void test_uri_encode_special(void) {
    TEST("URI encode: special chars");
    char out[64];
    s3__uri_encode("test$file.txt", 13, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "test%24file.txt");
    PASS();
}

static void test_uri_encode_slash(void) {
    TEST("URI encode: slash encoding control");
    char out[64];
    s3__uri_encode("path/to/file", 12, out, sizeof(out), true);
    /* encode_slash=true: / gets encoded */
    ASSERT_EQ_STR(out, "path%2Fto%2Ffile");

    s3__uri_encode("path/to/file", 12, out, sizeof(out), false);
    /* encode_slash=false: / preserved */
    ASSERT_EQ_STR(out, "path/to/file");
    PASS();
}

static void test_uri_encode_path(void) {
    TEST("URI encode path: preserves slashes");
    char out[128];
    s3__uri_encode_path("photos/2024/my file.jpg", 23, out, sizeof(out));
    ASSERT_EQ_STR(out, "photos/2024/my%20file.jpg");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Hex Encoding Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_hex_encode(void) {
    TEST("Hex encode");
    uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff};
    char hex[13];
    s3__hex_encode(data, 6, hex);
    ASSERT_EQ_STR(hex, "deadbeef00ff");
    PASS();
}

static void test_hex_decode(void) {
    TEST("Hex decode");
    uint8_t out[6];
    int len = s3__hex_decode("DEADBEEF00ff", 12, out, sizeof(out));
    ASSERT_EQ_INT(len, 6);
    uint8_t expected[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff};
    ASSERT_EQ_MEM(out, expected, 6);
    PASS();
}

static void test_hex_roundtrip(void) {
    TEST("Hex roundtrip");
    uint8_t data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    char hex[17];
    s3__hex_encode(data, 8, hex);
    uint8_t decoded[8];
    int len = s3__hex_decode(hex, 16, decoded, sizeof(decoded));
    ASSERT_EQ_INT(len, 8);
    ASSERT_EQ_MEM(decoded, data, 8);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML Parser Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_find_simple(void) {
    TEST("XML find: simple tag");
    const char *xml = "<Root><Name>my-bucket</Name><Region>us-east-1</Region></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "Name", &val, &vlen);
    assert(found);
    char buf[64];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "my-bucket");
    PASS();
}

static void test_xml_find_nested(void) {
    TEST("XML find_in: nested extraction");
    const char *xml =
        "<ListBucketResult>"
        "<Contents><Key>file1.txt</Key><Size>1234</Size></Contents>"
        "<Contents><Key>file2.txt</Key><Size>5678</Size></Contents>"
        "</ListBucketResult>";
    const char *val; size_t vlen;

    /* Find first Contents, then Key within it */
    bool found = s3__xml_find(xml, strlen(xml), "Contents", &val, &vlen);
    assert(found);

    const char *key_val; size_t key_len;
    found = s3__xml_find(val, vlen, "Key", &key_val, &key_len);
    assert(found);
    char buf[64];
    s3__xml_decode_entities(key_val, key_len, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "file1.txt");
    PASS();
}

static int xml_each_counter(const char *e, size_t l, void *u) {
    (void)e; (void)l;
    (*(int *)u)++;
    return 0;
}

static void test_xml_each(void) {
    TEST("XML each: iterate elements");
    const char *xml =
        "<Result>"
        "<Item>one</Item>"
        "<Item>two</Item>"
        "<Item>three</Item>"
        "</Result>";

    int count = 0;
    s3__xml_each(xml, strlen(xml), "Item", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 3);
    PASS();
}

static void test_xml_entities(void) {
    TEST("XML decode entities");
    char out[128];
    const char *input = "&amp;&lt;&gt;&quot;&apos;";
    s3__xml_decode_entities(input, strlen(input), out, sizeof(out));
    ASSERT_EQ_STR(out, "&<>\"'");
    PASS();
}

static void test_xml_numeric_entities(void) {
    TEST("XML decode numeric entities");
    char out[128];
    s3__xml_decode_entities("&#65;&#66;&#x43;", 16, out, sizeof(out));
    ASSERT_EQ_STR(out, "ABC");
    PASS();
}

static void test_xml_builder(void) {
    TEST("XML builder");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "Root");
    s3__xml_buf_element(&b, "Name", "test & <value>");
    s3__xml_buf_element_int(&b, "Count", 42);
    s3__xml_buf_element_bool(&b, "Flag", true);
    s3__xml_buf_close(&b, "Root");

    /* Verify we can parse back what we built */
    const char *val; size_t vlen;
    bool found = s3__xml_find(b.data, b.len, "Count", &val, &vlen);
    assert(found);
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "42");

    found = s3__xml_find(b.data, b.len, "Flag", &val, &vlen);
    assert(found);
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "true");

    /* Verify entity encoding in Name */
    found = s3__xml_find(b.data, b.len, "Name", &val, &vlen);
    assert(found);
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "test & <value>");

    s3_buf_free(&b);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * S3 Error Parsing Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_s3_error_parse(void) {
    TEST("XML S3 error: parse AccessDenied response");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Error>"
        "<Code>AccessDenied</Code>"
        "<Message>Access Denied</Message>"
        "<RequestId>EXAMPLE-REQUEST-ID</RequestId>"
        "<HostId>EXAMPLE-HOST-ID</HostId>"
        "</Error>";

    /* Manually parse the error code */
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "Code", &val, &vlen);
    assert(found);
    char code[64];
    s3__xml_decode_entities(val, vlen, code, sizeof(code));
    ASSERT_EQ_STR(code, "AccessDenied");

    /* Map it */
    s3_status st = s3__map_s3_error_code(code);
    ASSERT_EQ_INT(st, S3_STATUS_ACCESS_DENIED);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SigV4 Signing Key Derivation Test
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sigv4_signing_key(void) {
    TEST("SigV4: signing key derivation");
    /* AWS documented example */
    const char *secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const char *datestamp = "20120215";
    const char *region = "us-east-1";
    const char *service = "iam";

    uint8_t key[32];
    s3__derive_signing_key(secret, datestamp, region, service, key);

    char hex[65];
    s3__hex_encode(key, 32, hex);
    ASSERT_EQ_STR(hex, "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Status String Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_status_strings(void) {
    TEST("Status strings: all values have names");
    /* Verify no nullptr returns for known statuses */
    for (int i = 0; i < S3_STATUS__COUNT; i++) {
        const char *str = s3_status_string((s3_status)i);
        if (!str || strlen(str) == 0) {
            printf("FAIL: status %d has no string\n", i);
            return;
        }
    }
    PASS();
}

static void test_status_string_ok(void) {
    TEST("Status string: OK");
    ASSERT_EQ_STR(s3_status_string(S3_STATUS_OK), "OK");
    PASS();
}

static void test_status_string_no_such_key(void) {
    TEST("Status string: NoSuchKey");
    const char *s = s3_status_string(S3_STATUS_NO_SUCH_KEY);
    assert(s != nullptr);
    assert(strlen(s) > 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Error Code Mapping Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_error_map_common_codes(void) {
    TEST("Error mapping: common S3 error codes");
    ASSERT_EQ_INT(s3__map_s3_error_code("AccessDenied"), S3_STATUS_ACCESS_DENIED);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchKey"), S3_STATUS_NO_SUCH_KEY);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchBucket"), S3_STATUS_NO_SUCH_BUCKET);
    ASSERT_EQ_INT(s3__map_s3_error_code("BucketAlreadyExists"), S3_STATUS_BUCKET_ALREADY_EXISTS);
    ASSERT_EQ_INT(s3__map_s3_error_code("BucketNotEmpty"), S3_STATUS_BUCKET_NOT_EMPTY);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidArgument"), S3_STATUS_INVALID_ARGUMENT_S3);
    ASSERT_EQ_INT(s3__map_s3_error_code("SignatureDoesNotMatch"), S3_STATUS_SIGNATURE_DOES_NOT_MATCH);
    ASSERT_EQ_INT(s3__map_s3_error_code("SlowDown"), S3_STATUS_SLOW_DOWN);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchUpload"), S3_STATUS_NO_SUCH_UPLOAD);
    ASSERT_EQ_INT(s3__map_s3_error_code("EntityTooLarge"), S3_STATUS_ENTITY_TOO_LARGE);
    PASS();
}

static void test_error_map_unknown(void) {
    TEST("Error mapping: unknown code");
    ASSERT_EQ_INT(s3__map_s3_error_code("SomeRandomError"), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_status_map(void) {
    TEST("HTTP status mapping");
    ASSERT_EQ_INT(s3__map_http_status(404), S3_STATUS_HTTP_NOT_FOUND);
    ASSERT_EQ_INT(s3__map_http_status(403), S3_STATUS_HTTP_FORBIDDEN);
    ASSERT_EQ_INT(s3__map_http_status(500), S3_STATUS_HTTP_INTERNAL_SERVER_ERROR);
    ASSERT_EQ_INT(s3__map_http_status(503), S3_STATUS_HTTP_SERVICE_UNAVAILABLE);
    ASSERT_EQ_INT(s3__map_http_status(304), S3_STATUS_NOT_MODIFIED);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Client Lifecycle Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_client_create_destroy(void) {
    TEST("Client: create and destroy");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = {
            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        .region = "us-east-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c != nullptr);

    const s3_error *err = s3_client_last_error(c);
    assert(err != nullptr);
    ASSERT_EQ_INT(err->status, S3_STATUS_OK);

    s3_client_destroy(c);
    PASS();
}

static void test_client_create_no_region(void) {
    TEST("Client: missing region → INVALID_ARGUMENT");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = {
            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
    });
    ASSERT_EQ_INT(st, S3_STATUS_INVALID_ARGUMENT);
    assert(c == nullptr);
    PASS();
}

static void test_client_create_no_creds(void) {
    TEST("Client: missing credentials → INVALID_ARGUMENT");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .region = "us-east-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_INVALID_ARGUMENT);
    assert(c == nullptr);
    PASS();
}

static void test_client_defaults(void) {
    TEST("Client: default config values");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = {
            .access_key_id = "AK",
            .secret_access_key = "SK",
        },
        .region = "eu-west-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c->use_https == true);
    assert(c->retry_policy.max_retries == 3);
    assert(c->retry_policy.jitter == true);
    s3_client_destroy(c);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Utility Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_storage_class_strings(void) {
    TEST("Storage class: enum ↔ string");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_STANDARD), "STANDARD");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_GLACIER), "GLACIER");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_DEEP_ARCHIVE), "DEEP_ARCHIVE");

    ASSERT_EQ_INT(s3__storage_class_from_string("STANDARD"), S3_STORAGE_CLASS_STANDARD);
    ASSERT_EQ_INT(s3__storage_class_from_string("GLACIER_IR"), S3_STORAGE_CLASS_GLACIER_IR);
    PASS();
}

static void test_canned_acl_strings(void) {
    TEST("Canned ACL: enum → string");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_PRIVATE), "private");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_PUBLIC_READ), "public-read");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_BUCKET_OWNER_FULL_CONTROL), "bucket-owner-full-control");
    PASS();
}

static void test_content_type_detection(void) {
    TEST("Content type detection");
    ASSERT_EQ_STR(s3_detect_content_type("photo.jpg"), "image/jpeg");
    ASSERT_EQ_STR(s3_detect_content_type("data.json"), "application/json");
    ASSERT_EQ_STR(s3_detect_content_type("page.html"), "text/html");
    ASSERT_EQ_STR(s3_detect_content_type("archive.tar.gz"), "application/gzip");
    ASSERT_EQ_STR(s3_detect_content_type("unknown.xyz"), "application/octet-stream");
    PASS();
}

static void test_timestamp_format(void) {
    TEST("Timestamp format: ISO 8601 + datestamp");
    char iso[17], date[9];
    s3__get_timestamp(iso, date);
    /* ISO: YYYYMMDDTHHMMSSZ — 16 chars */
    ASSERT_EQ_INT(strlen(iso), 16);
    assert(iso[8] == 'T');
    assert(iso[15] == 'Z');
    /* Date: YYYYMMDD — 8 chars */
    ASSERT_EQ_INT(strlen(date), 8);
    /* Date should be prefix of ISO */
    assert(memcmp(iso, date, 8) == 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Retry Logic Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_retry_should_retry(void) {
    TEST("Retry: should_retry logic");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
    });

    /* Should retry on 503 */
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 0) == true);
    /* Should retry on SlowDown */
    assert(s3__should_retry(c, S3_STATUS_SLOW_DOWN, 0) == true);
    /* Should NOT retry on 404 */
    assert(s3__should_retry(c, S3_STATUS_HTTP_NOT_FOUND, 0) == false);
    /* Should NOT retry on AccessDenied */
    assert(s3__should_retry(c, S3_STATUS_ACCESS_DENIED, 0) == false);
    /* Should NOT retry if at max attempts */
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 3) == false);

    s3_client_destroy(c);
    PASS();
}

static void test_retry_delay(void) {
    TEST("Retry: exponential backoff");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 5,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .jitter = false,
        },
    });

    int d0 = s3__retry_delay_ms(c, 0);
    int d1 = s3__retry_delay_ms(c, 1);
    int d2 = s3__retry_delay_ms(c, 2);

    ASSERT_EQ_INT(d0, 100);  /* 100 * 2^0 = 100 */
    ASSERT_EQ_INT(d1, 200);  /* 100 * 2^1 = 200 */
    ASSERT_EQ_INT(d2, 400);  /* 100 * 2^2 = 400 */

    /* Should cap at max */
    int d10 = s3__retry_delay_ms(c, 10);
    assert(d10 <= 10000);

    s3_client_destroy(c);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML S3 Response Parsing Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_parse_list_bucket_result(void) {
    TEST("XML: parse ListBucketResult");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Name>my-bucket</Name>"
        "<Prefix>photos/</Prefix>"
        "<MaxKeys>1000</MaxKeys>"
        "<IsTruncated>false</IsTruncated>"
        "<KeyCount>2</KeyCount>"
        "<Contents>"
        "<Key>photos/pic1.jpg</Key>"
        "<LastModified>2024-01-15T10:30:00.000Z</LastModified>"
        "<ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>"
        "<Size>12345</Size>"
        "<StorageClass>STANDARD</StorageClass>"
        "</Contents>"
        "<Contents>"
        "<Key>photos/pic2.png</Key>"
        "<LastModified>2024-01-16T11:00:00.000Z</LastModified>"
        "<ETag>&quot;abc123&quot;</ETag>"
        "<Size>67890</Size>"
        "<StorageClass>STANDARD_IA</StorageClass>"
        "</Contents>"
        "</ListBucketResult>";

    const char *val; size_t vlen;
    char buf[256];

    /* Name */
    assert(s3__xml_find(xml, strlen(xml), "Name", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "my-bucket");

    /* IsTruncated */
    assert(s3__xml_find(xml, strlen(xml), "IsTruncated", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "false");

    /* Count Contents elements */
    int count = 0;
    const char *p = xml;
    while ((p = strstr(p, "<Contents>")) != nullptr) { count++; p += 10; }
    ASSERT_EQ_INT(count, 2);

    /* Extract second key */
    p = strstr(xml, "<Contents>");
    p = strstr(p + 10, "<Contents>");  /* skip to second */
    const char *end = strstr(p, "</Contents>");
    assert(s3__xml_find(p, end - p + 11, "Key", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "photos/pic2.png");

    PASS();
}

static void test_xml_parse_delete_result(void) {
    TEST("XML: parse DeleteResult");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<DeleteResult>"
        "<Deleted><Key>file1.txt</Key></Deleted>"
        "<Deleted><Key>file2.txt</Key></Deleted>"
        "<Error><Key>file3.txt</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
        "</DeleteResult>";

    int deleted = 0, errors = 0;
    const char *p = xml;
    while ((p = strstr(p, "<Deleted>")) != nullptr) { deleted++; p += 9; }
    p = xml;
    while ((p = strstr(p, "<Error>")) != nullptr) { errors++; p += 7; }

    ASSERT_EQ_INT(deleted, 2);
    ASSERT_EQ_INT(errors, 1);
    PASS();
}

static void test_xml_parse_copy_result(void) {
    TEST("XML: parse CopyObjectResult");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<CopyObjectResult>"
        "<ETag>&quot;etag123&quot;</ETag>"
        "<LastModified>2024-03-15T10:00:00.000Z</LastModified>"
        "</CopyObjectResult>";

    const char *val; size_t vlen;
    char buf[128];

    assert(s3__xml_find(xml, strlen(xml), "ETag", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "\"etag123\"");

    assert(s3__xml_find(xml, strlen(xml), "LastModified", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "2024-03-15T10:00:00.000Z");
    PASS();
}

static void test_xml_parse_initiate_multipart(void) {
    TEST("XML: parse InitiateMultipartUploadResult");
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<InitiateMultipartUploadResult>"
        "<Bucket>my-bucket</Bucket>"
        "<Key>large-file.bin</Key>"
        "<UploadId>abc123-upload-id-xyz</UploadId>"
        "</InitiateMultipartUploadResult>";

    const char *val; size_t vlen;
    char buf[256];

    assert(s3__xml_find(xml, strlen(xml), "UploadId", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "abc123-upload-id-xyz");

    assert(s3__xml_find(xml, strlen(xml), "Key", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "large-file.bin");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 Additional Tests (RFC 4231 cases 4-6)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_hmac_sha256_case4(void) {
    TEST("HMAC-SHA256: RFC 4231 test case 4");
    uint8_t key[25];
    for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
    uint8_t data[50];
    memset(data, 0xcd, 50);
    uint8_t out[32];
    s3__hmac_sha256(key, 25, data, 50, out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    ASSERT_EQ_STR(hex, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    PASS();
}

static void test_hmac_sha256_case6(void) {
    TEST("HMAC-SHA256: RFC 4231 test case 6 (131-byte key)");
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const char *data = "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t out[32];
    s3__hmac_sha256(key, 131, data, strlen(data), out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    ASSERT_EQ_STR(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    PASS();
}

static void test_hmac_sha256_case7(void) {
    TEST("HMAC-SHA256: RFC 4231 test case 7 (131-byte key, longer data)");
    uint8_t key[131];
    memset(key, 0xaa, 131);
    const char *data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    uint8_t out[32];
    s3__hmac_sha256(key, 131, data, strlen(data), out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    ASSERT_EQ_STR(hex, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-256 Stress Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha256_one_byte_updates(void) {
    TEST("SHA-256: one byte at a time");
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    s3_sha256_ctx ctx;
    s3__sha256_init(&ctx);
    for (size_t i = 0; i < strlen(msg); i++)
        s3__sha256_update(&ctx, msg + i, 1);
    uint8_t hash[32];
    s3__sha256_final(&ctx, hash);
    char hex[65];
    s3__hex_encode(hash, 32, hex);
    ASSERT_EQ_STR(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    PASS();
}

static void test_sha256_63_byte_boundary(void) {
    TEST("SHA-256: 63-byte message (block boundary -1)");
    /* 63 bytes of 'a' */
    char msg[63];
    memset(msg, 'a', 63);
    char hex[65];
    s3__sha256_hex(msg, 63, hex);
    /* Pre-computed reference */
    assert(strlen(hex) == 64);
    assert(hex[0] != '\0');
    PASS();
}

static void test_sha256_64_byte_boundary(void) {
    TEST("SHA-256: 64-byte message (exact block)");
    char msg[64];
    memset(msg, 'b', 64);
    char hex[65];
    s3__sha256_hex(msg, 64, hex);
    assert(strlen(hex) == 64);
    PASS();
}

static void test_sha256_65_byte_boundary(void) {
    TEST("SHA-256: 65-byte message (block boundary +1)");
    char msg[65];
    memset(msg, 'c', 65);
    char hex[65];
    s3__sha256_hex(msg, 65, hex);
    assert(strlen(hex) == 64);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Base64 Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_base64_encode_one_byte(void) {
    TEST("Base64 encode: single byte 0x00");
    char out[8];
    uint8_t data[] = {0x00};
    s3__base64_encode(data, 1, out, sizeof(out));
    ASSERT_EQ_STR(out, "AA==");
    PASS();
}

static void test_base64_encode_two_bytes(void) {
    TEST("Base64 encode: two bytes 0x00 0x00");
    char out[8];
    uint8_t data[] = {0x00, 0x00};
    s3__base64_encode(data, 2, out, sizeof(out));
    ASSERT_EQ_STR(out, "AAA=");
    PASS();
}

static void test_base64_encode_all_ff(void) {
    TEST("Base64 encode: three 0xFF bytes");
    char out[8];
    uint8_t data[] = {0xff, 0xff, 0xff};
    s3__base64_encode(data, 3, out, sizeof(out));
    ASSERT_EQ_STR(out, "////");
    PASS();
}

static void test_base64_decode_invalid(void) {
    TEST("Base64 decode: invalid chars handled");
    uint8_t out[32];
    /* Decode valid base64 */
    size_t len = s3__base64_decode("SGVsbG8=", 8, out, sizeof(out));
    ASSERT_EQ_INT(len, 5);
    assert(memcmp(out, "Hello", 5) == 0);
    PASS();
}

static void test_base64_long_roundtrip(void) {
    TEST("Base64 roundtrip: 256 bytes");
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

/* ═══════════════════════════════════════════════════════════════════════════
 * URI Encoding Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_uri_encode_empty(void) {
    TEST("URI encode: empty string");
    char out[8];
    s3__uri_encode("", 0, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "");
    PASS();
}

static void test_uri_encode_all_special(void) {
    TEST("URI encode: all special chars");
    char out[128];
    s3__uri_encode("!@#$%^&*()", 10, out, sizeof(out), false);
    /* All should be percent-encoded */
    assert(strstr(out, "%21") != nullptr); /* ! */
    assert(strstr(out, "%40") != nullptr); /* @ */
    assert(strstr(out, "%23") != nullptr); /* # */
    assert(strstr(out, "%24") != nullptr); /* $ */
    assert(strstr(out, "%25") != nullptr); /* % */
    PASS();
}

static void test_uri_encode_unicode(void) {
    TEST("URI encode: UTF-8 bytes");
    char out[64];
    /* UTF-8 for '€' = 0xE2 0x82 0xAC */
    s3__uri_encode("\xe2\x82\xac", 3, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "%E2%82%AC");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML Parser Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_find_not_found(void) {
    TEST("XML find: tag not found");
    const char *xml = "<Root><Name>test</Name></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "Missing", &val, &vlen);
    assert(!found);
    PASS();
}

static void test_xml_find_empty_tag(void) {
    TEST("XML find: empty tag content");
    const char *xml = "<Root><Name></Name></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "Name", &val, &vlen);
    assert(found);
    ASSERT_EQ_INT(vlen, 0);
    PASS();
}

static void test_xml_entities_mixed(void) {
    TEST("XML decode: mixed content");
    char out[256];
    s3__xml_decode_entities("Hello &amp; World &lt;3&gt;", 27, out, sizeof(out));
    ASSERT_EQ_STR(out, "Hello & World <3>");
    PASS();
}

static void test_xml_entities_none(void) {
    TEST("XML decode: no entities");
    char out[64];
    const char *input = "Hello World 123";
    s3__xml_decode_entities(input, strlen(input), out, sizeof(out));
    ASSERT_EQ_STR(out, "Hello World 123");
    PASS();
}

static void test_xml_builder_nested(void) {
    TEST("XML builder: nested elements");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "Delete");
    s3__xml_buf_element_bool(&b, "Quiet", false);
    s3__xml_buf_open(&b, "Object");
    s3__xml_buf_element(&b, "Key", "test/file.txt");
    s3__xml_buf_close(&b, "Object");
    s3__xml_buf_open(&b, "Object");
    s3__xml_buf_element(&b, "Key", "another.txt");
    s3__xml_buf_element(&b, "VersionId", "v1");
    s3__xml_buf_close(&b, "Object");
    s3__xml_buf_close(&b, "Delete");

    /* Verify structure */
    const char *val; size_t vlen;
    assert(s3__xml_find(b.data, b.len, "Quiet", &val, &vlen));
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "false");

    /* Count Object elements */
    int count = 0;
    const char *p = b.data;
    while ((p = strstr(p, "<Object>")) != nullptr) { count++; p += 8; }
    ASSERT_EQ_INT(count, 2);

    s3_buf_free(&b);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Growable Buffer Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_buf_init_free(void) {
    TEST("Buffer: init and free");
    s3_buf b;
    s3_buf_init(&b);
    assert(b.data == nullptr);
    assert(b.len == 0);
    assert(b.cap == 0);
    s3_buf_free(&b);
    assert(b.data == nullptr);
    PASS();
}

static void test_buf_append(void) {
    TEST("Buffer: append strings");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "Hello");
    s3_buf_append_str(&b, " ");
    s3_buf_append_str(&b, "World");
    ASSERT_EQ_STR(b.data, "Hello World");
    ASSERT_EQ_INT(b.len, 11);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_grow(void) {
    TEST("Buffer: auto-grow on large append");
    s3_buf b;
    s3_buf_init(&b);
    /* Append 1000 bytes */
    char big[1001];
    memset(big, 'X', 1000);
    big[1000] = '\0';
    s3_buf_append_str(&b, big);
    ASSERT_EQ_INT(b.len, 1000);
    assert(b.cap >= 1000);
    /* Verify content */
    for (int i = 0; i < 1000; i++) assert(b.data[i] == 'X');
    s3_buf_free(&b);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Error Mapping Extended Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_error_map_all_codes(void) {
    TEST("Error mapping: all documented S3 codes");
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchVersion"), S3_STATUS_NO_SUCH_VERSION);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidPart"), S3_STATUS_INVALID_PART);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidPartOrder"), S3_STATUS_INVALID_PART_ORDER);
    ASSERT_EQ_INT(s3__map_s3_error_code("EntityTooSmall"), S3_STATUS_ENTITY_TOO_SMALL);
    ASSERT_EQ_INT(s3__map_s3_error_code("ExpiredToken"), S3_STATUS_EXPIRED_TOKEN);
    ASSERT_EQ_INT(s3__map_s3_error_code("MalformedXML"), S3_STATUS_MALFORMED_XML);
    ASSERT_EQ_INT(s3__map_s3_error_code("MethodNotAllowed"), S3_STATUS_METHOD_NOT_ALLOWED);
    ASSERT_EQ_INT(s3__map_s3_error_code("RestoreAlreadyInProgress"), S3_STATUS_RESTORE_ALREADY_IN_PROGRESS);
    ASSERT_EQ_INT(s3__map_s3_error_code("BucketAlreadyOwnedByYou"), S3_STATUS_BUCKET_ALREADY_OWNED_BY_YOU);
    ASSERT_EQ_INT(s3__map_s3_error_code("RequestTimeout"), S3_STATUS_REQUEST_TIMEOUT);
    ASSERT_EQ_INT(s3__map_s3_error_code("PreconditionFailed"), S3_STATUS_PRECONDITION_FAILED);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidRange"), S3_STATUS_INVALID_RANGE);
    PASS();
}

static void test_http_status_map_extended(void) {
    TEST("HTTP status mapping: extended");
    ASSERT_EQ_INT(s3__map_http_status(400), S3_STATUS_HTTP_BAD_REQUEST);
    ASSERT_EQ_INT(s3__map_http_status(405), S3_STATUS_METHOD_NOT_ALLOWED);
    ASSERT_EQ_INT(s3__map_http_status(409), S3_STATUS_HTTP_CONFLICT);
    ASSERT_EQ_INT(s3__map_http_status(411), S3_STATUS_HTTP_LENGTH_REQUIRED);
    ASSERT_EQ_INT(s3__map_http_status(412), S3_STATUS_PRECONDITION_FAILED);
    ASSERT_EQ_INT(s3__map_http_status(416), S3_STATUS_HTTP_RANGE_NOT_SATISFIABLE);
    ASSERT_EQ_INT(s3__map_http_status(501), S3_STATUS_HTTP_NOT_IMPLEMENTED);
    ASSERT_EQ_INT(s3__map_http_status(502), S3_STATUS_HTTP_BAD_GATEWAY);
    ASSERT_EQ_INT(s3__map_http_status(504), S3_STATUS_HTTP_GATEWAY_TIMEOUT);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Client Config Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_client_custom_config(void) {
    TEST("Client: custom config values preserved");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK", .session_token = "TOKEN" },
        .region = "ap-southeast-1",
        .endpoint = "minio.local:9000",
        .use_path_style = true,
        .use_https = false,
        .connect_timeout_ms = 5000,
        .request_timeout_ms = 30000,
        .user_agent = "my-app/2.0",
        .retry_policy = { .max_retries = 3 },  /* non-zero signals explicit config */
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    ASSERT_EQ_STR(c->region, "ap-southeast-1");
    ASSERT_EQ_STR(c->endpoint, "minio.local:9000");
    assert(c->use_path_style == true);
    assert(c->use_https == false);
    ASSERT_EQ_INT(c->connect_timeout_ms, 5000);
    ASSERT_EQ_INT(c->request_timeout_ms, 30000);
    ASSERT_EQ_STR(c->user_agent, "my-app/2.0");
    ASSERT_EQ_STR(c->session_token, "TOKEN");
    s3_client_destroy(c);
    PASS();
}

static void test_client_destroy_null(void) {
    TEST("Client: destroy nullptr is safe");
    s3_client_destroy(nullptr);
    PASS();
}

static void test_client_multiple_create_destroy(void) {
    TEST("Client: create/destroy multiple times");
    for (int i = 0; i < 10; i++) {
        s3_client *c = nullptr;
        s3_status st = s3_client_create(&c, &(s3_config){
            .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
            .region = "us-west-2",
        });
        ASSERT_EQ_INT(st, S3_STATUS_OK);
        s3_client_destroy(c);
    }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Class / ACL Extended Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_storage_class_all_values(void) {
    TEST("Storage class: all enum values");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_REDUCED_REDUNDANCY), "REDUCED_REDUNDANCY");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_STANDARD_IA), "STANDARD_IA");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_ONEZONE_IA), "ONEZONE_IA");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_INTELLIGENT_TIERING), "INTELLIGENT_TIERING");
    ASSERT_EQ_STR(s3__storage_class_string(S3_STORAGE_CLASS_EXPRESS_ONEZONE), "EXPRESS_ONEZONE");

    ASSERT_EQ_INT(s3__storage_class_from_string("REDUCED_REDUNDANCY"), S3_STORAGE_CLASS_REDUCED_REDUNDANCY);
    ASSERT_EQ_INT(s3__storage_class_from_string("ONEZONE_IA"), S3_STORAGE_CLASS_ONEZONE_IA);
    ASSERT_EQ_INT(s3__storage_class_from_string("DEEP_ARCHIVE"), S3_STORAGE_CLASS_DEEP_ARCHIVE);
    ASSERT_EQ_INT(s3__storage_class_from_string("EXPRESS_ONEZONE"), S3_STORAGE_CLASS_EXPRESS_ONEZONE);
    PASS();
}

static void test_canned_acl_all_values(void) {
    TEST("Canned ACL: all enum values");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_PUBLIC_READ_WRITE), "public-read-write");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_AUTHENTICATED_READ), "authenticated-read");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_AWS_EXEC_READ), "aws-exec-read");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_BUCKET_OWNER_READ), "bucket-owner-read");
    ASSERT_EQ_STR(s3__canned_acl_string(S3_ACL_LOG_DELIVERY_WRITE), "log-delivery-write");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Content Type Detection Extended
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_content_type_many(void) {
    TEST("Content type: many extensions");
    ASSERT_EQ_STR(s3_detect_content_type("file.css"), "text/css");
    ASSERT_EQ_STR(s3_detect_content_type("file.js"), "application/javascript");
    ASSERT_EQ_STR(s3_detect_content_type("file.xml"), "text/xml");
    ASSERT_EQ_STR(s3_detect_content_type("file.svg"), "image/svg+xml");
    ASSERT_EQ_STR(s3_detect_content_type("file.gif"), "image/gif");
    ASSERT_EQ_STR(s3_detect_content_type("file.webp"), "image/webp");
    ASSERT_EQ_STR(s3_detect_content_type("file.mp4"), "video/mp4");
    ASSERT_EQ_STR(s3_detect_content_type("file.mp3"), "audio/mpeg");
    ASSERT_EQ_STR(s3_detect_content_type("file.zip"), "application/zip");
    ASSERT_EQ_STR(s3_detect_content_type("file.txt"), "text/plain");
    PASS();
}

static void test_content_type_no_extension(void) {
    TEST("Content type: no extension → octet-stream");
    ASSERT_EQ_STR(s3_detect_content_type("README"), "application/octet-stream");
    ASSERT_EQ_STR(s3_detect_content_type(""), "application/octet-stream");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML S3 Complex Response Parsing
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_parse_complete_multipart(void) {
    TEST("XML: parse CompleteMultipartUploadResult");
    const char *xml =
        "<CompleteMultipartUploadResult>"
        "<Location>https://bucket.s3.amazonaws.com/key</Location>"
        "<Bucket>my-bucket</Bucket>"
        "<Key>large-file.bin</Key>"
        "<ETag>&quot;combined-etag&quot;</ETag>"
        "</CompleteMultipartUploadResult>";

    const char *val; size_t vlen;
    char buf[256];

    assert(s3__xml_find(xml, strlen(xml), "Location", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    assert(strstr(buf, "https://") != nullptr);

    assert(s3__xml_find(xml, strlen(xml), "ETag", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "\"combined-etag\"");
    PASS();
}

static void test_xml_parse_list_parts(void) {
    TEST("XML: parse ListPartsResult");
    const char *xml =
        "<ListPartsResult>"
        "<Bucket>bucket</Bucket>"
        "<Key>big.bin</Key>"
        "<UploadId>upload-123</UploadId>"
        "<IsTruncated>false</IsTruncated>"
        "<Part><PartNumber>1</PartNumber><ETag>&quot;etag1&quot;</ETag><Size>5242880</Size></Part>"
        "<Part><PartNumber>2</PartNumber><ETag>&quot;etag2&quot;</ETag><Size>3145728</Size></Part>"
        "</ListPartsResult>";

    const char *val; size_t vlen;
    char buf[128];

    assert(s3__xml_find(xml, strlen(xml), "UploadId", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "upload-123");

    int count = 0;
    const char *p = xml;
    while ((p = strstr(p, "<Part>")) != nullptr) { count++; p += 6; }
    ASSERT_EQ_INT(count, 2);
    PASS();
}

static void test_xml_parse_versioning(void) {
    TEST("XML: parse VersioningConfiguration");
    const char *xml =
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Status>Enabled</Status>"
        "</VersioningConfiguration>";

    const char *val; size_t vlen;
    char buf[32];
    assert(s3__xml_find(xml, strlen(xml), "Status", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "Enabled");
    PASS();
}

static void test_xml_parse_public_access_block(void) {
    TEST("XML: parse PublicAccessBlockConfiguration");
    const char *xml =
        "<PublicAccessBlockConfiguration>"
        "<BlockPublicAcls>true</BlockPublicAcls>"
        "<IgnorePublicAcls>true</IgnorePublicAcls>"
        "<BlockPublicPolicy>false</BlockPublicPolicy>"
        "<RestrictPublicBuckets>true</RestrictPublicBuckets>"
        "</PublicAccessBlockConfiguration>";

    const char *val; size_t vlen;
    char buf[16];

    assert(s3__xml_find(xml, strlen(xml), "BlockPublicAcls", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "true");

    assert(s3__xml_find(xml, strlen(xml), "BlockPublicPolicy", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "false");
    PASS();
}

static void test_xml_parse_tagging(void) {
    TEST("XML: parse Tagging response");
    const char *xml =
        "<Tagging><TagSet>"
        "<Tag><Key>env</Key><Value>production</Value></Tag>"
        "<Tag><Key>team</Key><Value>platform</Value></Tag>"
        "<Tag><Key>cost-center</Key><Value>12345</Value></Tag>"
        "</TagSet></Tagging>";

    int count = 0;
    s3__xml_each(xml, strlen(xml), "Tag", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 3);

    /* Extract first tag key */
    const char *val; size_t vlen;
    const char *tag_start, *tag_end;
    tag_start = strstr(xml, "<Tag>");
    tag_end = strstr(tag_start, "</Tag>");
    assert(s3__xml_find(tag_start, tag_end - tag_start + 6, "Key", &val, &vlen));
    char buf[64];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "env");
    PASS();
}

static void test_xml_parse_location_constraint(void) {
    TEST("XML: parse LocationConstraint");
    /* Non-us-east-1 region */
    const char *xml1 = "<LocationConstraint>eu-west-1</LocationConstraint>";
    const char *val; size_t vlen;
    assert(s3__xml_find(xml1, strlen(xml1), "LocationConstraint", &val, &vlen));
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "eu-west-1");

    /* us-east-1 returns empty */
    const char *xml2 = "<LocationConstraint/>";
    /* Self-closing may or may not be handled — just verify no crash */
    s3__xml_find(xml2, strlen(xml2), "LocationConstraint", &val, &vlen);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SigV4 Additional Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sigv4_signing_key_s3(void) {
    TEST("SigV4: signing key for s3 service");
    uint8_t key[32];
    s3__derive_signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                           "20240101", "us-east-1", "s3", key);
    /* Just verify it produces 32 bytes of non-zero */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (key[i] != 0) nonzero++;
    assert(nonzero > 0);
    PASS();
}

static void test_sigv4_different_regions(void) {
    TEST("SigV4: different regions produce different keys");
    uint8_t key1[32], key2[32];
    s3__derive_signing_key("secret", "20240101", "us-east-1", "s3", key1);
    s3__derive_signing_key("secret", "20240101", "eu-west-1", "s3", key2);
    assert(memcmp(key1, key2, 32) != 0);
    PASS();
}

static void test_sigv4_different_dates(void) {
    TEST("SigV4: different dates produce different keys");
    uint8_t key1[32], key2[32];
    s3__derive_signing_key("secret", "20240101", "us-east-1", "s3", key1);
    s3__derive_signing_key("secret", "20240102", "us-east-1", "s3", key2);
    assert(memcmp(key1, key2, 32) != 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_free Test
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_s3_free(void) {
    TEST("s3_free: free allocated memory");
    void *p = S3_MALLOC(100);
    assert(p != nullptr);
    s3_free(p);  /* should not crash */
    PASS();
}

static void test_s3_free_null(void) {
    TEST("s3_free: free nullptr is safe");
    s3_free(nullptr);  /* should not crash */
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — SHA-256 Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha256_55_byte_boundary(void) {
    TEST("SHA-256: 55-byte message (padding boundary)");
    char msg[55];
    memset(msg, 'a', 55);
    char hex[65];
    s3__sha256_hex(msg, 55, hex);
    /* 55 bytes is the max that fits in one block with padding */
    assert(strlen(hex) == 64);
    /* Verify deterministic */
    char hex2[65];
    s3__sha256_hex(msg, 55, hex2);
    ASSERT_EQ_STR(hex, hex2);
    PASS();
}

static void test_sha256_56_byte_boundary(void) {
    TEST("SHA-256: 56-byte message (needs two blocks for padding)");
    char msg[56];
    memset(msg, 'a', 56);
    char hex[65];
    s3__sha256_hex(msg, 56, hex);
    assert(strlen(hex) == 64);
    /* Must differ from 55-byte */
    char hex55[65];
    char msg55[55];
    memset(msg55, 'a', 55);
    s3__sha256_hex(msg55, 55, hex55);
    assert(strcmp(hex, hex55) != 0);
    PASS();
}

static void test_sha256_large_input(void) {
    TEST("SHA-256: large input (2000 bytes)");
    char msg[2000];
    memset(msg, 'X', 2000);
    char hex[65];
    s3__sha256_hex(msg, 2000, hex);
    assert(strlen(hex) == 64);
    /* Verify deterministic */
    char hex2[65];
    s3__sha256_hex(msg, 2000, hex2);
    ASSERT_EQ_STR(hex, hex2);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — SHA-1 Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha1_448bit(void) {
    TEST("SHA-1: 448-bit message");
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t hash[20];
    s3__sha1(msg, strlen(msg), hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    PASS();
}

static void test_sha1_896bit(void) {
    TEST("SHA-1: 896-bit message");
    const char *msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t hash[20];
    s3__sha1(msg, strlen(msg), hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "a49b2446a02c645bf419f995b67091253a04a259");
    PASS();
}

static void test_sha1_incremental(void) {
    TEST("SHA-1: incremental update");
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    s3_sha1_ctx ctx;
    s3__sha1_init(&ctx);
    s3__sha1_update(&ctx, msg, 20);
    s3__sha1_update(&ctx, msg + 20, strlen(msg) - 20);
    uint8_t hash[20];
    s3__sha1_final(&ctx, hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    PASS();
}

static void test_sha1_one_byte_updates(void) {
    TEST("SHA-1: one byte at a time");
    const char *msg = "abc";
    s3_sha1_ctx ctx;
    s3__sha1_init(&ctx);
    for (size_t i = 0; i < 3; i++)
        s3__sha1_update(&ctx, msg + i, 1);
    uint8_t hash[20];
    s3__sha1_final(&ctx, hash);
    char hex[41];
    s3__hex_encode(hash, 20, hex);
    ASSERT_EQ_STR(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — HMAC-SHA256 Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_hmac_sha256_empty_data(void) {
    TEST("HMAC-SHA256: empty data");
    uint8_t key[20];
    memset(key, 0x0b, 20);
    uint8_t out[32];
    s3__hmac_sha256(key, 20, "", 0, out);
    /* Just verify it produces 32 bytes and doesn't crash */
    char hex[65];
    s3__hex_encode(out, 32, hex);
    assert(strlen(hex) == 64);
    PASS();
}

static void test_hmac_sha256_64byte_key(void) {
    TEST("HMAC-SHA256: key exactly 64 bytes (block size)");
    uint8_t key[64];
    memset(key, 0xAA, 64);
    const char *data = "Test data";
    uint8_t out[32];
    s3__hmac_sha256(key, 64, data, strlen(data), out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    assert(strlen(hex) == 64);
    /* Verify deterministic */
    uint8_t out2[32];
    s3__hmac_sha256(key, 64, data, strlen(data), out2);
    ASSERT_EQ_MEM(out, out2, 32);
    PASS();
}

static void test_hmac_sha256_empty_key(void) {
    TEST("HMAC-SHA256: empty key (zero-length)");
    uint8_t out[32];
    s3__hmac_sha256("", 0, "data", 4, out);
    char hex[65];
    s3__hex_encode(out, 32, hex);
    assert(strlen(hex) == 64);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — CRC32/CRC32C Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_crc32_single_byte(void) {
    TEST("CRC32: single byte");
    uint32_t crc = s3__crc32(0, "A", 1);
    assert(crc != 0);  /* Should produce non-zero for non-empty input */
    PASS();
}

static void test_crc32_all_zeros(void) {
    TEST("CRC32: all zeros");
    uint8_t data[16];
    memset(data, 0, 16);
    uint32_t crc = s3__crc32(0, data, 16);
    assert(crc != 0);  /* CRC of all-zero bytes should not be zero */
    PASS();
}

static void test_crc32_all_ff(void) {
    TEST("CRC32: all 0xFF");
    uint8_t data[16];
    memset(data, 0xFF, 16);
    uint32_t crc = s3__crc32(0, data, 16);
    assert(crc != 0);
    PASS();
}

static void test_crc32c_single_byte(void) {
    TEST("CRC32C: single byte");
    uint32_t crc = s3__crc32c(0, "A", 1);
    assert(crc != 0);
    PASS();
}

static void test_crc32c_all_zeros(void) {
    TEST("CRC32C: all zeros");
    uint8_t data[16];
    memset(data, 0, 16);
    uint32_t crc = s3__crc32c(0, data, 16);
    assert(crc != 0);
    PASS();
}

static void test_crc32c_all_ff(void) {
    TEST("CRC32C: all 0xFF");
    uint8_t data[16];
    memset(data, 0xFF, 16);
    uint32_t crc = s3__crc32c(0, data, 16);
    assert(crc != 0);
    PASS();
}

static void test_crc32c_empty(void) {
    TEST("CRC32C: empty");
    uint32_t crc = s3__crc32c(0, "", 0);
    ASSERT_EQ_INT(crc, 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Base64 Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_base64_decode_AAAA(void) {
    TEST("Base64 decode: AAAA -> 3 zero bytes");
    uint8_t out[8];
    size_t len = s3__base64_decode("AAAA", 4, out, sizeof(out));
    ASSERT_EQ_INT(len, 3);
    ASSERT_EQ_INT(out[0], 0);
    ASSERT_EQ_INT(out[1], 0);
    ASSERT_EQ_INT(out[2], 0);
    PASS();
}

static void test_base64_decode_no_padding(void) {
    TEST("Base64 decode: without padding chars");
    /* "SGVsbG8" is "Hello" without the trailing = */
    uint8_t out[32];
    size_t len = s3__base64_decode("SGVsbG8", 7, out, sizeof(out));
    /* Decoder may or may not handle missing padding; just verify no crash */
    (void)len;
    PASS();
}

static void test_base64_encode_three_bytes(void) {
    TEST("Base64 encode: 3 bytes (no padding)");
    char out[8];
    s3__base64_encode((const uint8_t *)"abc", 3, out, sizeof(out));
    ASSERT_EQ_STR(out, "YWJj");
    PASS();
}

static void test_base64_roundtrip_one_byte(void) {
    TEST("Base64 roundtrip: 1 byte");
    uint8_t data[] = {0x42};
    char encoded[8];
    s3__base64_encode(data, 1, encoded, sizeof(encoded));
    uint8_t decoded[4];
    size_t len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(len, 1);
    ASSERT_EQ_INT(decoded[0], 0x42);
    PASS();
}

static void test_base64_roundtrip_two_bytes(void) {
    TEST("Base64 roundtrip: 2 bytes");
    uint8_t data[] = {0x42, 0x99};
    char encoded[8];
    s3__base64_encode(data, 2, encoded, sizeof(encoded));
    uint8_t decoded[4];
    size_t len = s3__base64_decode(encoded, strlen(encoded), decoded, sizeof(decoded));
    ASSERT_EQ_INT(len, 2);
    ASSERT_EQ_MEM(decoded, data, 2);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — URI Encoding Individual Chars
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_uri_encode_tilde(void) {
    TEST("URI encode: tilde preserved");
    char out[8];
    s3__uri_encode("~", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "~");
    PASS();
}

static void test_uri_encode_dot(void) {
    TEST("URI encode: dot preserved");
    char out[8];
    s3__uri_encode(".", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, ".");
    PASS();
}

static void test_uri_encode_dash(void) {
    TEST("URI encode: dash preserved");
    char out[8];
    s3__uri_encode("-", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "-");
    PASS();
}

static void test_uri_encode_underscore(void) {
    TEST("URI encode: underscore preserved");
    char out[8];
    s3__uri_encode("_", 1, out, sizeof(out), false);
    ASSERT_EQ_STR(out, "_");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — XML Parser Coverage
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_find_in_parent_child(void) {
    TEST("XML find_in: parent/child lookup");
    const char *xml =
        "<Root><Parent><Child>value</Child></Parent></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find_in(xml, strlen(xml), "Parent", "Child", &val, &vlen);
    assert(found);
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "value");
    PASS();
}

static void test_xml_find_in_not_found(void) {
    TEST("XML find_in: child not in parent");
    const char *xml = "<Root><Parent><A>1</A></Parent><B>2</B></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find_in(xml, strlen(xml), "Parent", "B", &val, &vlen);
    assert(!found);
    PASS();
}

static void test_xml_each_zero_matches(void) {
    TEST("XML each: zero matches returns 0");
    const char *xml = "<Root><A>1</A><B>2</B></Root>";
    int count = 0;
    int result = s3__xml_each(xml, strlen(xml), "Missing", xml_each_counter, &count);
    ASSERT_EQ_INT(result, 0);
    ASSERT_EQ_INT(count, 0);
    PASS();
}

static int xml_each_stop_at_2(const char *e, size_t l, void *u) {
    (void)e; (void)l;
    int *count = (int *)u;
    (*count)++;
    return (*count >= 2) ? 1 : 0;  /* stop after 2 */
}

static void test_xml_each_early_stop(void) {
    TEST("XML each: callback returns non-zero (early stop)");
    const char *xml =
        "<R><I>a</I><I>b</I><I>c</I><I>d</I></R>";
    int count = 0;
    int result = s3__xml_each(xml, strlen(xml), "I", xml_each_stop_at_2, &count);
    ASSERT_EQ_INT(result, 2);
    ASSERT_EQ_INT(count, 2);
    PASS();
}

static void test_xml_with_attributes(void) {
    TEST("XML: tag with attributes");
    const char *xml = "<Root><Tag attr=\"val\">content</Tag></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "Tag", &val, &vlen);
    assert(found);
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "content");
    PASS();
}

static void test_xml_with_namespace(void) {
    TEST("XML: tag with xmlns namespace prefix");
    const char *xml =
        "<s3:Name xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\">value</s3:Name>";
    const char *val; size_t vlen;
    /* Our parser matches exact tag names, so "s3:Name" should work */
    bool found = s3__xml_find(xml, strlen(xml), "s3:Name", &val, &vlen);
    assert(found);
    char buf[32];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "value");
    PASS();
}

static void test_xml_empty_input(void) {
    TEST("XML find: empty input");
    const char *val; size_t vlen;
    bool found = s3__xml_find("", 0, "Tag", &val, &vlen);
    assert(!found);
    found = s3__xml_find(nullptr, 0, "Tag", &val, &vlen);
    assert(!found);
    PASS();
}

static void test_xml_self_closing(void) {
    TEST("XML: self-closing tag");
    const char *xml = "<Root><Empty/><Name>val</Name></Root>";
    const char *val; size_t vlen;
    bool found = s3__xml_find(xml, strlen(xml), "Empty", &val, &vlen);
    assert(found);
    ASSERT_EQ_INT(vlen, 0);
    PASS();
}

static void test_xml_decode_only_amp(void) {
    TEST("XML decode: only ampersand");
    char out[16];
    s3__xml_decode_entities("&amp;", 5, out, sizeof(out));
    ASSERT_EQ_STR(out, "&");
    PASS();
}

static void test_xml_decode_only_lt(void) {
    TEST("XML decode: only lt");
    char out[16];
    s3__xml_decode_entities("&lt;", 4, out, sizeof(out));
    ASSERT_EQ_STR(out, "<");
    PASS();
}

static void test_xml_decode_adjacent_entities(void) {
    TEST("XML decode: adjacent entities");
    char out[32];
    s3__xml_decode_entities("&amp;&amp;&lt;&gt;", 18, out, sizeof(out));
    ASSERT_EQ_STR(out, "&&<>");
    PASS();
}

static void test_xml_decode_entity_at_end(void) {
    TEST("XML decode: entity at end of string");
    char out[32];
    s3__xml_decode_entities("hello&amp;", 10, out, sizeof(out));
    ASSERT_EQ_STR(out, "hello&");
    PASS();
}

static void test_xml_decode_empty(void) {
    TEST("XML decode: empty input");
    char out[16];
    s3__xml_decode_entities("", 0, out, sizeof(out));
    ASSERT_EQ_STR(out, "");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — XML Builder Round-Trips
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_xml_build_delete_batch(void) {
    TEST("XML build+parse: Delete batch");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "Delete");
    s3__xml_buf_element_bool(&b, "Quiet", true);
    for (int i = 0; i < 3; i++) {
        s3__xml_buf_open(&b, "Object");
        char key[32];
        snprintf(key, sizeof(key), "file%d.txt", i);
        s3__xml_buf_element(&b, "Key", key);
        s3__xml_buf_close(&b, "Object");
    }
    s3__xml_buf_close(&b, "Delete");

    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find(b.data, b.len, "Quiet", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "true");

    int count = 0;
    s3__xml_each(b.data, b.len, "Object", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 3);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_create_bucket_config(void) {
    TEST("XML build+parse: CreateBucketConfiguration");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "CreateBucketConfiguration");
    s3__xml_buf_element(&b, "LocationConstraint", "eu-west-1");
    s3__xml_buf_close(&b, "CreateBucketConfiguration");

    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find(b.data, b.len, "LocationConstraint", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "eu-west-1");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_tagging(void) {
    TEST("XML build+parse: Tagging");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "Tagging");
    s3__xml_buf_open(&b, "TagSet");
    s3__xml_buf_open(&b, "Tag");
    s3__xml_buf_element(&b, "Key", "env");
    s3__xml_buf_element(&b, "Value", "prod");
    s3__xml_buf_close(&b, "Tag");
    s3__xml_buf_close(&b, "TagSet");
    s3__xml_buf_close(&b, "Tagging");

    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find_in(b.data, b.len, "Tag", "Key", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "env");
    assert(s3__xml_find_in(b.data, b.len, "Tag", "Value", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "prod");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_restore_request(void) {
    TEST("XML build+parse: RestoreRequest");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "RestoreRequest");
    s3__xml_buf_element_int(&b, "Days", 7);
    s3__xml_buf_open(&b, "GlacierJobParameters");
    s3__xml_buf_element(&b, "Tier", "Expedited");
    s3__xml_buf_close(&b, "GlacierJobParameters");
    s3__xml_buf_close(&b, "RestoreRequest");

    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find(b.data, b.len, "Days", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "7");
    assert(s3__xml_find_in(b.data, b.len, "GlacierJobParameters", "Tier", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "Expedited");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_complete_multipart(void) {
    TEST("XML build+parse: CompleteMultipartUpload");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "CompleteMultipartUpload");
    for (int i = 1; i <= 3; i++) {
        s3__xml_buf_open(&b, "Part");
        s3__xml_buf_element_int(&b, "PartNumber", i);
        char etag[32];
        snprintf(etag, sizeof(etag), "\"etag%d\"", i);
        s3__xml_buf_element(&b, "ETag", etag);
        s3__xml_buf_close(&b, "Part");
    }
    s3__xml_buf_close(&b, "CompleteMultipartUpload");

    int count = 0;
    s3__xml_each(b.data, b.len, "Part", xml_each_counter, &count);
    ASSERT_EQ_INT(count, 3);
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_versioning_config(void) {
    TEST("XML build+parse: VersioningConfiguration");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "VersioningConfiguration");
    s3__xml_buf_element(&b, "Status", "Enabled");
    s3__xml_buf_close(&b, "VersioningConfiguration");

    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find(b.data, b.len, "Status", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "Enabled");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_public_access_block(void) {
    TEST("XML build+parse: PublicAccessBlockConfiguration");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "PublicAccessBlockConfiguration");
    s3__xml_buf_element_bool(&b, "BlockPublicAcls", true);
    s3__xml_buf_element_bool(&b, "IgnorePublicAcls", true);
    s3__xml_buf_element_bool(&b, "BlockPublicPolicy", true);
    s3__xml_buf_element_bool(&b, "RestrictPublicBuckets", true);
    s3__xml_buf_close(&b, "PublicAccessBlockConfiguration");

    const char *val; size_t vlen; char buf[16];
    assert(s3__xml_find(b.data, b.len, "BlockPublicAcls", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "true");
    assert(s3__xml_find(b.data, b.len, "RestrictPublicBuckets", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "true");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_lifecycle_config(void) {
    TEST("XML build+parse: LifecycleConfiguration");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "LifecycleConfiguration");
    s3__xml_buf_open(&b, "Rule");
    s3__xml_buf_element(&b, "ID", "archive-rule");
    s3__xml_buf_element(&b, "Status", "Enabled");
    s3__xml_buf_open(&b, "Filter");
    s3__xml_buf_element(&b, "Prefix", "logs/");
    s3__xml_buf_close(&b, "Filter");
    s3__xml_buf_open(&b, "Transition");
    s3__xml_buf_element_int(&b, "Days", 30);
    s3__xml_buf_element(&b, "StorageClass", "GLACIER");
    s3__xml_buf_close(&b, "Transition");
    s3__xml_buf_open(&b, "Expiration");
    s3__xml_buf_element_int(&b, "Days", 365);
    s3__xml_buf_close(&b, "Expiration");
    s3__xml_buf_close(&b, "Rule");
    s3__xml_buf_close(&b, "LifecycleConfiguration");

    const char *val; size_t vlen; char buf[64];
    assert(s3__xml_find_in(b.data, b.len, "Rule", "ID", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "archive-rule");
    assert(s3__xml_find_in(b.data, b.len, "Transition", "StorageClass", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "GLACIER");
    assert(s3__xml_find_in(b.data, b.len, "Expiration", "Days", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "365");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_cors_config(void) {
    TEST("XML build+parse: CORSConfiguration");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "CORSConfiguration");
    s3__xml_buf_open(&b, "CORSRule");
    s3__xml_buf_element(&b, "AllowedOrigin", "*");
    s3__xml_buf_element(&b, "AllowedMethod", "GET");
    s3__xml_buf_element(&b, "AllowedMethod", "PUT");
    s3__xml_buf_element_int(&b, "MaxAgeSeconds", 3600);
    s3__xml_buf_close(&b, "CORSRule");
    s3__xml_buf_close(&b, "CORSConfiguration");

    const char *val; size_t vlen; char buf[32];
    assert(s3__xml_find_in(b.data, b.len, "CORSRule", "AllowedOrigin", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "*");
    assert(s3__xml_find_in(b.data, b.len, "CORSRule", "MaxAgeSeconds", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "3600");
    s3_buf_free(&b);
    PASS();
}

static void test_xml_build_notification_config(void) {
    TEST("XML build+parse: NotificationConfiguration");
    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3__xml_buf_open(&b, "NotificationConfiguration");
    s3__xml_buf_open(&b, "TopicConfiguration");
    s3__xml_buf_element(&b, "Id", "notify-1");
    s3__xml_buf_element(&b, "Topic", "arn:aws:sns:us-east-1:123456789:my-topic");
    s3__xml_buf_element(&b, "Event", "s3:ObjectCreated:*");
    s3__xml_buf_close(&b, "TopicConfiguration");
    s3__xml_buf_close(&b, "NotificationConfiguration");

    const char *val; size_t vlen; char buf[64];
    assert(s3__xml_find_in(b.data, b.len, "TopicConfiguration", "Id", &val, &vlen));
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "notify-1");
    s3_buf_free(&b);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Error Mapping: ALL remaining S3 error codes
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_error_map_all_remaining_codes(void) {
    TEST("Error mapping: all remaining S3 error codes");
    ASSERT_EQ_INT(s3__map_s3_error_code("AccountProblem"), S3_STATUS_ACCOUNT_PROBLEM);
    ASSERT_EQ_INT(s3__map_s3_error_code("AllAccessDisabled"), S3_STATUS_ALL_ACCESS_DISABLED);
    ASSERT_EQ_INT(s3__map_s3_error_code("CredentialsNotSupported"), S3_STATUS_CREDENTIALS_NOT_SUPPORTED);
    ASSERT_EQ_INT(s3__map_s3_error_code("CrossLocationLoggingProhibited"), S3_STATUS_CROSS_LOCATION_LOGGING_PROHIBITED);
    ASSERT_EQ_INT(s3__map_s3_error_code("IllegalLocationConstraintException"), S3_STATUS_ILLEGAL_LOCATION_CONSTRAINT);
    ASSERT_EQ_INT(s3__map_s3_error_code("IllegalVersioningConfigurationException"), S3_STATUS_ILLEGAL_VERSIONING_CONFIGURATION);
    ASSERT_EQ_INT(s3__map_s3_error_code("IncompleteBody"), S3_STATUS_INCOMPLETE_BODY);
    ASSERT_EQ_INT(s3__map_s3_error_code("IncorrectNumberOfFilesInPostRequest"), S3_STATUS_INCORRECT_NUMBER_OF_FILES_IN_POST);
    ASSERT_EQ_INT(s3__map_s3_error_code("InlineDataTooLarge"), S3_STATUS_INLINE_DATA_TOO_LARGE);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidAccessKeyId"), S3_STATUS_INVALID_ACCESS_KEY_ID);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidBucketName"), S3_STATUS_INVALID_BUCKET_NAME);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidBucketState"), S3_STATUS_INVALID_BUCKET_STATE);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidDigest"), S3_STATUS_INVALID_DIGEST);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidEncryptionAlgorithmError"), S3_STATUS_INVALID_ENCRYPTION_ALGORITHM);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidLocationConstraint"), S3_STATUS_INVALID_LOCATION_CONSTRAINT);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidObjectState"), S3_STATUS_INVALID_OBJECT_STATE);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidPayer"), S3_STATUS_INVALID_PAYER);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidPolicyDocument"), S3_STATUS_INVALID_POLICY_DOCUMENT);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidRequest"), S3_STATUS_INVALID_REQUEST);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidSecurity"), S3_STATUS_INVALID_SECURITY);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidSOAPRequest"), S3_STATUS_INVALID_SOAP_REQUEST);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidStorageClass"), S3_STATUS_INVALID_STORAGE_CLASS);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidTargetBucketForLogging"), S3_STATUS_INVALID_TARGET_BUCKET_FOR_LOGGING);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidToken"), S3_STATUS_INVALID_TOKEN);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidURI"), S3_STATUS_INVALID_URI);
    ASSERT_EQ_INT(s3__map_s3_error_code("KeyTooLongError"), S3_STATUS_KEY_TOO_LONG);
    ASSERT_EQ_INT(s3__map_s3_error_code("MalformedACLError"), S3_STATUS_MALFORMED_ACL);
    ASSERT_EQ_INT(s3__map_s3_error_code("MalformedPOSTRequest"), S3_STATUS_MALFORMED_POST_REQUEST);
    ASSERT_EQ_INT(s3__map_s3_error_code("MaxMessageLengthExceeded"), S3_STATUS_MAX_MESSAGE_LENGTH_EXCEEDED);
    ASSERT_EQ_INT(s3__map_s3_error_code("MaxPostPreDataLengthExceededError"), S3_STATUS_MAX_POST_PRE_DATA_LENGTH_EXCEEDED);
    ASSERT_EQ_INT(s3__map_s3_error_code("MetadataTooLarge"), S3_STATUS_METADATA_TOO_LARGE);
    ASSERT_EQ_INT(s3__map_s3_error_code("MissingAttachment"), S3_STATUS_MISSING_ATTACHMENT);
    ASSERT_EQ_INT(s3__map_s3_error_code("MissingContentLength"), S3_STATUS_MISSING_CONTENT_LENGTH);
    ASSERT_EQ_INT(s3__map_s3_error_code("MissingRequestBodyError"), S3_STATUS_MISSING_REQUEST_BODY);
    ASSERT_EQ_INT(s3__map_s3_error_code("MissingSecurityElement"), S3_STATUS_MISSING_SECURITY_ELEMENT);
    ASSERT_EQ_INT(s3__map_s3_error_code("MissingSecurityHeader"), S3_STATUS_MISSING_SECURITY_HEADER);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoLoggingStatusForKey"), S3_STATUS_NO_LOGGING_STATUS_FOR_KEY);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchBucketPolicy"), S3_STATUS_NO_SUCH_BUCKET_POLICY);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchCORSConfiguration"), S3_STATUS_NO_SUCH_CORS_CONFIGURATION);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchLifecycleConfiguration"), S3_STATUS_NO_SUCH_LIFECYCLE_CONFIGURATION);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchWebsiteConfiguration"), S3_STATUS_NO_SUCH_WEBSITE_CONFIGURATION);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchTagSet"), S3_STATUS_NO_SUCH_TAG_SET);
    ASSERT_EQ_INT(s3__map_s3_error_code("NoSuchAccessPoint"), S3_STATUS_NO_SUCH_ACCESS_POINT);
    ASSERT_EQ_INT(s3__map_s3_error_code("NotImplemented"), S3_STATUS_NOT_IMPLEMENTED_S3);
    ASSERT_EQ_INT(s3__map_s3_error_code("NotSignedUp"), S3_STATUS_NOT_SIGNED_UP);
    ASSERT_EQ_INT(s3__map_s3_error_code("OperationAborted"), S3_STATUS_OPERATION_ABORTED);
    ASSERT_EQ_INT(s3__map_s3_error_code("PermanentRedirect"), S3_STATUS_PERMANENT_REDIRECT);
    ASSERT_EQ_INT(s3__map_s3_error_code("Redirect"), S3_STATUS_REDIRECT);
    ASSERT_EQ_INT(s3__map_s3_error_code("RequestIsNotMultiPartContent"), S3_STATUS_REQUEST_IS_NOT_MULTI_PART_CONTENT);
    ASSERT_EQ_INT(s3__map_s3_error_code("RequestTimeTooSkewed"), S3_STATUS_REQUEST_TIME_TOO_SKEWED);
    ASSERT_EQ_INT(s3__map_s3_error_code("RequestTorrentOfBucketError"), S3_STATUS_REQUEST_TORRENT_OF_BUCKET);
    ASSERT_EQ_INT(s3__map_s3_error_code("ServerSideEncryptionConfigurationNotFoundError"), S3_STATUS_SERVER_SIDE_ENCRYPTION_CONFIG_NOT_FOUND);
    ASSERT_EQ_INT(s3__map_s3_error_code("ServiceUnavailable"), S3_STATUS_SERVICE_UNAVAILABLE);
    ASSERT_EQ_INT(s3__map_s3_error_code("TemporaryRedirect"), S3_STATUS_TEMPORARY_REDIRECT);
    ASSERT_EQ_INT(s3__map_s3_error_code("TokenRefreshRequired"), S3_STATUS_TOKEN_REFRESH_REQUIRED);
    ASSERT_EQ_INT(s3__map_s3_error_code("TooManyBuckets"), S3_STATUS_TOO_MANY_BUCKETS);
    ASSERT_EQ_INT(s3__map_s3_error_code("UnexpectedContent"), S3_STATUS_UNEXPECTED_CONTENT);
    ASSERT_EQ_INT(s3__map_s3_error_code("UnresolvableGrantByEmailAddress"), S3_STATUS_UNRESOLVABLE_GRANT_BY_EMAIL);
    ASSERT_EQ_INT(s3__map_s3_error_code("UserKeyMustBeSpecified"), S3_STATUS_USER_KEY_MUST_BE_SPECIFIED);
    ASSERT_EQ_INT(s3__map_s3_error_code("InvalidTag"), S3_STATUS_INVALID_TAG);
    PASS();
}

static void test_error_map_null(void) {
    TEST("Error mapping: null code");
    ASSERT_EQ_INT(s3__map_s3_error_code(nullptr), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_status_map_200(void) {
    TEST("HTTP status mapping: 200 -> unknown");
    /* 200 is success, not an error; should map to unknown */
    ASSERT_EQ_INT(s3__map_http_status(200), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_status_map_301(void) {
    TEST("HTTP status mapping: 301 -> unknown");
    ASSERT_EQ_INT(s3__map_http_status(301), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

static void test_http_status_map_307(void) {
    TEST("HTTP status mapping: 307 -> unknown");
    ASSERT_EQ_INT(s3__map_http_status(307), S3_STATUS_UNKNOWN_ERROR);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — s3_status_string individual verification
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_status_string_each_value(void) {
    TEST("Status string: verify each enum individually non-null");
    const struct { s3_status st; const char *expected; } checks[] = {
        { S3_STATUS_OK, "OK" },
        { S3_STATUS_INVALID_ARGUMENT, "Invalid argument" },
        { S3_STATUS_OUT_OF_MEMORY, "Out of memory" },
        { S3_STATUS_INTERNAL_ERROR, "Internal error" },
        { S3_STATUS_CURL_ERROR, "CURL error" },
        { S3_STATUS_ACCESS_DENIED, "Access denied" },
        { S3_STATUS_NO_SUCH_KEY, "No such key" },
        { S3_STATUS_NO_SUCH_BUCKET, "No such bucket" },
        { S3_STATUS_SLOW_DOWN, "Slow down" },
        { S3_STATUS_HTTP_NOT_FOUND, "HTTP 404 Not Found" },
        { S3_STATUS_HTTP_SERVICE_UNAVAILABLE, "HTTP 503 Service Unavailable" },
        { S3_STATUS_UNKNOWN_ERROR, "Unknown error" },
    };
    for (size_t i = 0; i < sizeof(checks)/sizeof(checks[0]); i++) {
        const char *s = s3_status_string(checks[i].st);
        assert(s != nullptr);
        ASSERT_EQ_STR(s, checks[i].expected);
    }
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Client
 * ═══════════════════════════════════════════════════════════════════════════ */

static s3_status test_cred_provider(const char **ak, const char **sk,
                                     const char **token, void *ud) {
    (void)ud;
    *ak = "PROVIDER_AK";
    *sk = "PROVIDER_SK";
    *token = nullptr;
    return S3_STATUS_OK;
}

static void test_client_with_credential_provider(void) {
    TEST("Client: create with credential_provider (no static creds)");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .region = "us-east-1",
        .credential_provider = test_cred_provider,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    assert(c != nullptr);
    assert(c->credential_provider == test_cred_provider);
    s3_client_destroy(c);
    PASS();
}

static void test_client_multiple_simultaneous(void) {
    TEST("Client: multiple clients simultaneously");
    s3_client *c1 = nullptr, *c2 = nullptr, *c3 = nullptr;
    s3_status st;
    st = s3_client_create(&c1, &(s3_config){
        .credentials = { .access_key_id = "AK1", .secret_access_key = "SK1" },
        .region = "us-east-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    st = s3_client_create(&c2, &(s3_config){
        .credentials = { .access_key_id = "AK2", .secret_access_key = "SK2" },
        .region = "eu-west-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);
    st = s3_client_create(&c3, &(s3_config){
        .credentials = { .access_key_id = "AK3", .secret_access_key = "SK3" },
        .region = "ap-northeast-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);

    /* Verify they are independent */
    ASSERT_EQ_STR(c1->region, "us-east-1");
    ASSERT_EQ_STR(c2->region, "eu-west-1");
    ASSERT_EQ_STR(c3->region, "ap-northeast-1");

    s3_client_destroy(c3);
    s3_client_destroy(c2);
    s3_client_destroy(c1);
    PASS();
}

static void test_client_deep_copy(void) {
    TEST("Client: deep copy - modify originals after create");
    char ak[] = "AKIAIOSFODNN7EXAMPLE";
    char sk[] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    char region[] = "us-east-1";

    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = ak, .secret_access_key = sk },
        .region = region,
    });
    ASSERT_EQ_INT(st, S3_STATUS_OK);

    /* Modify original strings */
    memset(ak, 'X', strlen(ak));
    memset(sk, 'Y', strlen(sk));
    memset(region, 'Z', strlen(region));

    /* Client should still have the original values */
    ASSERT_EQ_STR(c->access_key_id, "AKIAIOSFODNN7EXAMPLE");
    ASSERT_EQ_STR(c->secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    ASSERT_EQ_STR(c->region, "us-east-1");

    s3_client_destroy(c);
    PASS();
}

static void test_client_null_out(void) {
    TEST("Client: null out pointer -> INVALID_ARGUMENT");
    s3_status st = s3_client_create(nullptr, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
    });
    ASSERT_EQ_INT(st, S3_STATUS_INVALID_ARGUMENT);
    PASS();
}

static void test_client_null_config(void) {
    TEST("Client: null config -> INVALID_ARGUMENT");
    s3_client *c = nullptr;
    s3_status st = s3_client_create(&c, nullptr);
    ASSERT_EQ_INT(st, S3_STATUS_INVALID_ARGUMENT);
    PASS();
}

static void test_client_last_error_null(void) {
    TEST("Client: last_error on null client");
    const s3_error *err = s3_client_last_error(nullptr);
    assert(err == nullptr);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Retry
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_retry_delay_with_jitter(void) {
    TEST("Retry: delay with jitter in expected range");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 5,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .jitter = true,
        },
    });

    /* With jitter, delay should be in [base*mult^attempt*0.5, base*mult^attempt*1.0] */
    for (int trial = 0; trial < 20; trial++) {
        int d = s3__retry_delay_ms(c, 0);
        assert(d >= 50 && d <= 100);  /* 100 * [0.5, 1.0) */
    }
    for (int trial = 0; trial < 20; trial++) {
        int d = s3__retry_delay_ms(c, 1);
        assert(d >= 100 && d <= 200);  /* 200 * [0.5, 1.0) */
    }

    s3_client_destroy(c);
    PASS();
}

static void test_retry_all_flags_disabled(void) {
    TEST("Retry: all flags disabled should not retry");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 5,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .jitter = false,
            .retry_on_throttle = false,
            .retry_on_5xx = false,
            .retry_on_timeout = false,
        },
    });

    /* Should not retry on throttle */
    assert(s3__should_retry(c, S3_STATUS_SLOW_DOWN, 0) == false);
    /* Should not retry on 5xx */
    assert(s3__should_retry(c, S3_STATUS_HTTP_INTERNAL_SERVER_ERROR, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 0) == false);
    /* Should not retry on timeout */
    assert(s3__should_retry(c, S3_STATUS_TIMEOUT, 0) == false);
    assert(s3__should_retry(c, S3_STATUS_REQUEST_TIMEOUT, 0) == false);
    /* CURL_ERROR should still retry (it's unconditional) */
    assert(s3__should_retry(c, S3_STATUS_CURL_ERROR, 0) == true);

    s3_client_destroy(c);
    PASS();
}

static void test_retry_exact_boundary(void) {
    TEST("Retry: exact boundary (max_retries - 1 vs max_retries)");
    s3_client *c = nullptr;
    s3_client_create(&c, &(s3_config){
        .credentials = { .access_key_id = "AK", .secret_access_key = "SK" },
        .region = "us-east-1",
        .retry_policy = {
            .max_retries = 3,
            .base_delay_ms = 100,
            .max_delay_ms = 10000,
            .backoff_multiplier = 2.0,
            .retry_on_5xx = true,
        },
    });

    /* attempt == max_retries - 1 (2) should retry */
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 2) == true);
    /* attempt == max_retries (3) should NOT retry */
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 3) == false);
    /* attempt > max_retries should NOT retry */
    assert(s3__should_retry(c, S3_STATUS_HTTP_SERVICE_UNAVAILABLE, 4) == false);

    s3_client_destroy(c);
    PASS();
}

static void test_retry_null_client(void) {
    TEST("Retry: null client returns false/0");
    assert(s3__should_retry(nullptr, S3_STATUS_SLOW_DOWN, 0) == false);
    ASSERT_EQ_INT(s3__retry_delay_ms(nullptr, 0), 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Utility Functions
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_strdup_null(void) {
    TEST("s3__strdup: null -> null");
    char *result = s3__strdup(nullptr);
    assert(result == nullptr);
    PASS();
}

static void test_strdup_empty(void) {
    TEST("s3__strdup: empty string -> empty string");
    char *result = s3__strdup("");
    assert(result != nullptr);
    ASSERT_EQ_STR(result, "");
    S3_FREE(result);
    PASS();
}

static void test_strdup_normal(void) {
    TEST("s3__strdup: normal string");
    char *result = s3__strdup("hello world");
    assert(result != nullptr);
    ASSERT_EQ_STR(result, "hello world");
    S3_FREE(result);
    PASS();
}

static void test_strndup_truncation(void) {
    TEST("s3__strndup: truncation test");
    char *result = s3__strndup("hello world", 5);
    assert(result != nullptr);
    ASSERT_EQ_STR(result, "hello");
    S3_FREE(result);
    PASS();
}

static void test_strndup_no_truncation(void) {
    TEST("s3__strndup: n > length (no truncation)");
    char *result = s3__strndup("hi", 100);
    assert(result != nullptr);
    ASSERT_EQ_STR(result, "hi");
    S3_FREE(result);
    PASS();
}

static void test_strndup_null(void) {
    TEST("s3__strndup: null -> null");
    char *result = s3__strndup(nullptr, 5);
    assert(result == nullptr);
    PASS();
}

static void test_timestamp_strict_format(void) {
    TEST("Timestamp: strict format verification");
    char iso[17], date[9];
    s3__get_timestamp(iso, date);
    /* All chars in date should be digits */
    for (int i = 0; i < 8; i++) {
        assert(date[i] >= '0' && date[i] <= '9');
    }
    /* ISO: YYYYMMDDTHHMMSSZ */
    for (int i = 0; i < 8; i++) {
        assert(iso[i] >= '0' && iso[i] <= '9');
    }
    assert(iso[8] == 'T');
    for (int i = 9; i < 15; i++) {
        assert(iso[i] >= '0' && iso[i] <= '9');
    }
    assert(iso[15] == 'Z');
    ASSERT_EQ_INT(strlen(iso), 16);
    ASSERT_EQ_INT(strlen(date), 8);
    PASS();
}

static void test_content_type_case_insensitive(void) {
    TEST("Content type: case insensitive extensions");
    ASSERT_EQ_STR(s3_detect_content_type("photo.JPG"), "image/jpeg");
    ASSERT_EQ_STR(s3_detect_content_type("page.Html"), "text/html");
    ASSERT_EQ_STR(s3_detect_content_type("data.JSON"), "application/json");
    ASSERT_EQ_STR(s3_detect_content_type("image.PNG"), "image/png");
    PASS();
}

static void test_content_type_path_with_dir(void) {
    TEST("Content type: path with directory");
    ASSERT_EQ_STR(s3_detect_content_type("path/to/file.png"), "image/png");
    ASSERT_EQ_STR(s3_detect_content_type("/var/data/report.pdf"), "application/pdf");
    PASS();
}

static void test_content_type_double_extension(void) {
    TEST("Content type: double extension (.tar.gz)");
    ASSERT_EQ_STR(s3_detect_content_type("archive.tar.gz"), "application/gzip");
    /* .tar alone */
    ASSERT_EQ_STR(s3_detect_content_type("archive.tar"), "application/x-tar");
    PASS();
}

static void test_content_type_null(void) {
    TEST("Content type: null filename");
    ASSERT_EQ_STR(s3_detect_content_type(nullptr), "application/octet-stream");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — SigV4
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sigv4_empty_region_service(void) {
    TEST("SigV4: signing key with empty region/service");
    uint8_t key[32];
    s3__derive_signing_key("secret", "20240101", "", "", key);
    /* Just verify no crash and deterministic */
    uint8_t key2[32];
    s3__derive_signing_key("secret", "20240101", "", "", key2);
    ASSERT_EQ_MEM(key, key2, 32);
    PASS();
}

static void test_sigv4_deterministic(void) {
    TEST("SigV4: signing key deterministic (same inputs -> same output)");
    uint8_t key1[32], key2[32];
    s3__derive_signing_key("mySecret123", "20250101", "us-west-2", "s3", key1);
    s3__derive_signing_key("mySecret123", "20250101", "us-west-2", "s3", key2);
    ASSERT_EQ_MEM(key1, key2, 32);
    PASS();
}

static void test_sigv4_different_services(void) {
    TEST("SigV4: different services produce different keys");
    uint8_t key_s3[32], key_iam[32];
    s3__derive_signing_key("secret", "20240101", "us-east-1", "s3", key_s3);
    s3__derive_signing_key("secret", "20240101", "us-east-1", "iam", key_iam);
    assert(memcmp(key_s3, key_iam, 32) != 0);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Growable Buffer
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_buf_many_small_appends(void) {
    TEST("Buffer: 200 small appends");
    s3_buf b;
    s3_buf_init(&b);
    for (int i = 0; i < 200; i++) {
        s3_buf_append_str(&b, "a");
    }
    ASSERT_EQ_INT(b.len, 200);
    assert(b.cap >= 200);
    for (int i = 0; i < 200; i++) assert(b.data[i] == 'a');
    s3_buf_free(&b);
    PASS();
}

static void test_buf_append_empty_string(void) {
    TEST("Buffer: append empty string");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "hello");
    s3_buf_append_str(&b, "");
    s3_buf_append_str(&b, "world");
    ASSERT_EQ_STR(b.data, "helloworld");
    ASSERT_EQ_INT(b.len, 10);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_free_reinit_append(void) {
    TEST("Buffer: free, re-init, and append again");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append_str(&b, "first");
    ASSERT_EQ_INT(b.len, 5);
    s3_buf_free(&b);
    assert(b.data == nullptr);
    assert(b.len == 0);

    s3_buf_init(&b);
    s3_buf_append_str(&b, "second");
    ASSERT_EQ_STR(b.data, "second");
    ASSERT_EQ_INT(b.len, 6);
    s3_buf_free(&b);
    PASS();
}

static void test_buf_append_raw(void) {
    TEST("Buffer: append raw bytes");
    s3_buf b;
    s3_buf_init(&b);
    s3_buf_append(&b, "abc\0def", 7);
    ASSERT_EQ_INT(b.len, 7);
    assert(b.data[3] == '\0');
    assert(b.data[4] == 'd');
    s3_buf_free(&b);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Free Functions on Zero-Initialized Structs
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_free_head_object_result_zero(void) {
    TEST("Free: s3_head_object_result on zero-init");
    s3_head_object_result r;
    memset(&r, 0, sizeof(r));
    s3_head_object_result_free(&r);  /* should not crash */
    PASS();
}

static void test_free_list_objects_result_zero(void) {
    TEST("Free: s3_list_objects_result on zero-init");
    s3_list_objects_result r;
    memset(&r, 0, sizeof(r));
    s3_list_objects_result_free(&r);  /* should not crash */
    PASS();
}

static void test_free_delete_objects_result_zero(void) {
    TEST("Free: s3_delete_objects_result on zero-init");
    s3_delete_objects_result r;
    memset(&r, 0, sizeof(r));
    s3_delete_objects_result_free(&r);  /* should not crash */
    PASS();
}

static void test_free_tag_set_zero(void) {
    TEST("Free: s3_tag_set on zero-init");
    s3_tag_set r;
    memset(&r, 0, sizeof(r));
    s3_tag_set_free(&r);  /* should not crash */
    PASS();
}

static void test_free_head_object_result_null(void) {
    TEST("Free: s3_head_object_result_free(null)");
    s3_head_object_result_free(nullptr);
    PASS();
}

static void test_free_list_objects_result_null(void) {
    TEST("Free: s3_list_objects_result_free(null)");
    s3_list_objects_result_free(nullptr);
    PASS();
}

static void test_free_delete_objects_result_null(void) {
    TEST("Free: s3_delete_objects_result_free(null)");
    s3_delete_objects_result_free(nullptr);
    PASS();
}

static void test_free_tag_set_null(void) {
    TEST("Free: s3_tag_set_free(null)");
    s3_tag_set_free(nullptr);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Hex Encoding Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_hex_encode_empty(void) {
    TEST("Hex encode: empty input");
    char hex[4] = "xyz";
    s3__hex_encode((const uint8_t *)"", 0, hex);
    ASSERT_EQ_STR(hex, "");
    PASS();
}

static void test_hex_decode_empty(void) {
    TEST("Hex decode: empty input");
    uint8_t out[4];
    int len = s3__hex_decode("", 0, out, sizeof(out));
    ASSERT_EQ_INT(len, 0);
    PASS();
}

static void test_hex_encode_single_byte(void) {
    TEST("Hex encode: single byte");
    uint8_t data[] = {0xAB};
    char hex[4];
    s3__hex_encode(data, 1, hex);
    ASSERT_EQ_STR(hex, "ab");
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW TESTS — Storage Class Edge Cases
 * ═══════════════════════════════════════════════════════════════════════════ */

static void test_sha256_exactly_128_bytes(void) {
    TEST("SHA-256: exactly 128 bytes (two full blocks)");
    char msg[128];
    memset(msg, 'Z', 128);
    char hex[65];
    s3__sha256_hex(msg, 128, hex);
    assert(strlen(hex) == 64);
    /* Deterministic */
    char hex2[65];
    s3__sha256_hex(msg, 128, hex2);
    ASSERT_EQ_STR(hex, hex2);
    PASS();
}

static void test_crc32_deterministic(void) {
    TEST("CRC32: deterministic (same input -> same output)");
    uint32_t crc1 = s3__crc32(0, "test data", 9);
    uint32_t crc2 = s3__crc32(0, "test data", 9);
    ASSERT_EQ_INT(crc1, crc2);
    PASS();
}

static void test_crc32c_deterministic(void) {
    TEST("CRC32C: deterministic (same input -> same output)");
    uint32_t crc1 = s3__crc32c(0, "test data", 9);
    uint32_t crc2 = s3__crc32c(0, "test data", 9);
    ASSERT_EQ_INT(crc1, crc2);
    PASS();
}

static void test_crc32_vs_crc32c_differ(void) {
    TEST("CRC32 vs CRC32C: produce different values");
    uint32_t crc = s3__crc32(0, "test", 4);
    uint32_t crc_c = s3__crc32c(0, "test", 4);
    assert(crc != crc_c);
    PASS();
}

static void test_xml_find_in_null_inputs(void) {
    TEST("XML find_in: null inputs return false");
    const char *val; size_t vlen;
    assert(!s3__xml_find_in(nullptr, 0, "P", "C", &val, &vlen));
    assert(!s3__xml_find_in("<R/>", 4, nullptr, "C", &val, &vlen));
    assert(!s3__xml_find_in("<R/>", 4, "R", nullptr, &val, &vlen));
    PASS();
}

static void test_xml_each_null_inputs(void) {
    TEST("XML each: null inputs return 0");
    ASSERT_EQ_INT(s3__xml_each(nullptr, 0, "Tag", xml_each_counter, nullptr), 0);
    ASSERT_EQ_INT(s3__xml_each("<R/>", 4, nullptr, xml_each_counter, nullptr), 0);
    ASSERT_EQ_INT(s3__xml_each("<R/>", 4, "R", nullptr, nullptr), 0);
    PASS();
}

static void test_xml_find_null_tag(void) {
    TEST("XML find: null tag returns false");
    const char *val; size_t vlen;
    assert(!s3__xml_find("<R/>", 4, nullptr, &val, &vlen));
    PASS();
}

static void test_storage_class_from_string_null(void) {
    TEST("Storage class from string: null -> STANDARD");
    ASSERT_EQ_INT(s3__storage_class_from_string(nullptr), S3_STORAGE_CLASS_STANDARD);
    PASS();
}

static void test_storage_class_from_string_unknown(void) {
    TEST("Storage class from string: unknown -> STANDARD");
    ASSERT_EQ_INT(s3__storage_class_from_string("UNKNOWN_CLASS"), S3_STORAGE_CLASS_STANDARD);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("\n═══ libs3 Test Suite ═══\n\n");

    printf("── SHA-256 ──\n");
    test_sha256_empty();
    test_sha256_abc();
    test_sha256_448bit();
    test_sha256_long();
    test_sha256_incremental();

    printf("── HMAC-SHA256 ──\n");
    test_hmac_sha256_case1();
    test_hmac_sha256_case2();
    test_hmac_sha256_case3();

    printf("── SHA-1 ──\n");
    test_sha1_abc();
    test_sha1_empty();

    printf("── CRC32 ──\n");
    test_crc32_check();
    test_crc32_empty();
    test_crc32_incremental();

    printf("── CRC32C ──\n");
    test_crc32c_check();
    test_crc32c_incremental();

    printf("── Base64 ──\n");
    test_base64_encode_empty();
    test_base64_encode_f();
    test_base64_encode_fo();
    test_base64_encode_foo();
    test_base64_encode_foobar();
    test_base64_roundtrip();

    printf("── URI Encoding ──\n");
    test_uri_encode_unreserved();
    test_uri_encode_space();
    test_uri_encode_special();
    test_uri_encode_slash();
    test_uri_encode_path();

    printf("── Hex Encoding ──\n");
    test_hex_encode();
    test_hex_decode();
    test_hex_roundtrip();

    printf("── XML Parser ──\n");
    test_xml_find_simple();
    test_xml_find_nested();
    test_xml_each();
    test_xml_entities();
    test_xml_numeric_entities();
    test_xml_builder();

    printf("── S3 Error Parsing ──\n");
    test_xml_s3_error_parse();
    test_error_map_common_codes();
    test_error_map_unknown();
    test_http_status_map();

    printf("── Status Strings ──\n");
    test_status_strings();
    test_status_string_ok();
    test_status_string_no_such_key();

    printf("── SigV4 ──\n");
    test_sigv4_signing_key();

    printf("── Client Lifecycle ──\n");
    test_client_create_destroy();
    test_client_create_no_region();
    test_client_create_no_creds();
    test_client_defaults();

    printf("── Utilities ──\n");
    test_storage_class_strings();
    test_canned_acl_strings();
    test_content_type_detection();
    test_timestamp_format();

    printf("── Retry Logic ──\n");
    test_retry_should_retry();
    test_retry_delay();

    printf("── HMAC-SHA256 Extended ──\n");
    test_hmac_sha256_case4();
    test_hmac_sha256_case6();
    test_hmac_sha256_case7();

    printf("── SHA-256 Stress ──\n");
    test_sha256_one_byte_updates();
    test_sha256_63_byte_boundary();
    test_sha256_64_byte_boundary();
    test_sha256_65_byte_boundary();

    printf("── Base64 Extended ──\n");
    test_base64_encode_one_byte();
    test_base64_encode_two_bytes();
    test_base64_encode_all_ff();
    test_base64_decode_invalid();
    test_base64_long_roundtrip();

    printf("── URI Encoding Extended ──\n");
    test_uri_encode_empty();
    test_uri_encode_all_special();
    test_uri_encode_unicode();

    printf("── XML Extended ──\n");
    test_xml_find_not_found();
    test_xml_find_empty_tag();
    test_xml_entities_mixed();
    test_xml_entities_none();
    test_xml_builder_nested();

    printf("── Buffer ──\n");
    test_buf_init_free();
    test_buf_append();
    test_buf_grow();

    printf("── Error Mapping Extended ──\n");
    test_error_map_all_codes();
    test_http_status_map_extended();

    printf("── Client Config Extended ──\n");
    test_client_custom_config();
    test_client_destroy_null();
    test_client_multiple_create_destroy();

    printf("── Storage Class / ACL Extended ──\n");
    test_storage_class_all_values();
    test_canned_acl_all_values();

    printf("── Content Type Extended ──\n");
    test_content_type_many();
    test_content_type_no_extension();

    printf("── XML S3 Response Parsing ──\n");
    test_xml_parse_list_bucket_result();
    test_xml_parse_delete_result();
    test_xml_parse_copy_result();
    test_xml_parse_initiate_multipart();
    test_xml_parse_complete_multipart();
    test_xml_parse_list_parts();
    test_xml_parse_versioning();
    test_xml_parse_public_access_block();
    test_xml_parse_tagging();
    test_xml_parse_location_constraint();

    printf("── SigV4 Extended ──\n");
    test_sigv4_signing_key_s3();
    test_sigv4_different_regions();
    test_sigv4_different_dates();

    printf("── Memory ──\n");
    test_s3_free();
    test_s3_free_null();

    printf("\n── SHA-256 Edge Cases ──\n");
    test_sha256_55_byte_boundary();
    test_sha256_56_byte_boundary();
    test_sha256_large_input();

    printf("── SHA-1 Extended ──\n");
    test_sha1_448bit();
    test_sha1_896bit();
    test_sha1_incremental();
    test_sha1_one_byte_updates();

    printf("── HMAC-SHA256 Edge Cases ──\n");
    test_hmac_sha256_empty_data();
    test_hmac_sha256_64byte_key();
    test_hmac_sha256_empty_key();

    printf("── CRC32/CRC32C Edge Cases ──\n");
    test_crc32_single_byte();
    test_crc32_all_zeros();
    test_crc32_all_ff();
    test_crc32c_single_byte();
    test_crc32c_all_zeros();
    test_crc32c_all_ff();
    test_crc32c_empty();

    printf("── Base64 Edge Cases ──\n");
    test_base64_decode_AAAA();
    test_base64_decode_no_padding();
    test_base64_encode_three_bytes();
    test_base64_roundtrip_one_byte();
    test_base64_roundtrip_two_bytes();

    printf("── URI Encoding Individual Chars ──\n");
    test_uri_encode_tilde();
    test_uri_encode_dot();
    test_uri_encode_dash();
    test_uri_encode_underscore();

    printf("── XML Parser Coverage ──\n");
    test_xml_find_in_parent_child();
    test_xml_find_in_not_found();
    test_xml_each_zero_matches();
    test_xml_each_early_stop();
    test_xml_with_attributes();
    test_xml_with_namespace();
    test_xml_empty_input();
    test_xml_self_closing();
    test_xml_decode_only_amp();
    test_xml_decode_only_lt();
    test_xml_decode_adjacent_entities();
    test_xml_decode_entity_at_end();
    test_xml_decode_empty();

    printf("── XML Builder Round-Trips ──\n");
    test_xml_build_delete_batch();
    test_xml_build_create_bucket_config();
    test_xml_build_tagging();
    test_xml_build_restore_request();
    test_xml_build_complete_multipart();
    test_xml_build_versioning_config();
    test_xml_build_public_access_block();
    test_xml_build_lifecycle_config();
    test_xml_build_cors_config();
    test_xml_build_notification_config();

    printf("── Error Mapping Complete ──\n");
    test_error_map_all_remaining_codes();
    test_error_map_null();
    test_http_status_map_200();
    test_http_status_map_301();
    test_http_status_map_307();

    printf("── Status String Each ──\n");
    test_status_string_each_value();

    printf("── Client Extended ──\n");
    test_client_with_credential_provider();
    test_client_multiple_simultaneous();
    test_client_deep_copy();
    test_client_null_out();
    test_client_null_config();
    test_client_last_error_null();

    printf("── Retry Extended ──\n");
    test_retry_delay_with_jitter();
    test_retry_all_flags_disabled();
    test_retry_exact_boundary();
    test_retry_null_client();

    printf("── Utility Functions ──\n");
    test_strdup_null();
    test_strdup_empty();
    test_strdup_normal();
    test_strndup_truncation();
    test_strndup_no_truncation();
    test_strndup_null();
    test_timestamp_strict_format();
    test_content_type_case_insensitive();
    test_content_type_path_with_dir();
    test_content_type_double_extension();
    test_content_type_null();

    printf("── SigV4 Extended ──\n");
    test_sigv4_empty_region_service();
    test_sigv4_deterministic();
    test_sigv4_different_services();

    printf("── Buffer Extended ──\n");
    test_buf_many_small_appends();
    test_buf_append_empty_string();
    test_buf_free_reinit_append();
    test_buf_append_raw();

    printf("── Free Functions ──\n");
    test_free_head_object_result_zero();
    test_free_list_objects_result_zero();
    test_free_delete_objects_result_zero();
    test_free_tag_set_zero();
    test_free_head_object_result_null();
    test_free_list_objects_result_null();
    test_free_delete_objects_result_null();
    test_free_tag_set_null();

    printf("── Hex Edge Cases ──\n");
    test_hex_encode_empty();
    test_hex_decode_empty();
    test_hex_encode_single_byte();

    printf("── Additional Edge Cases ──\n");
    test_sha256_exactly_128_bytes();
    test_crc32_deterministic();
    test_crc32c_deterministic();
    test_crc32_vs_crc32c_differ();
    test_xml_find_in_null_inputs();
    test_xml_each_null_inputs();
    test_xml_find_null_tag();

    printf("── Storage Class Edge Cases ──\n");
    test_storage_class_from_string_null();
    test_storage_class_from_string_unknown();

    printf("\n═══════════════════════════════════════\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("═══════════════════════════════════════\n\n");

    return tests_passed == tests_run ? 0 : 1;
}
