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

    printf("── XML S3 Response Parsing ──\n");
    test_xml_parse_list_bucket_result();
    test_xml_parse_delete_result();
    test_xml_parse_copy_result();
    test_xml_parse_initiate_multipart();

    printf("\n═══════════════════════════════════════\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("═══════════════════════════════════════\n\n");

    return tests_passed == tests_run ? 0 : 1;
}
