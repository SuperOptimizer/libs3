/* JSON + XML scraper unit tests -- no network.
 * Links the instrumented library and reaches the scraper helpers via the
 * internal test header (single translation unit -> honest coverage). */
#include "libs3_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)
#define CHECK_STR(a,b) do { char *_v = (a); \
    if (!_v || strcmp(_v,(b)) != 0) { \
      printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, \
             _v?_v:"(null)",(b)); fails++; } free(_v); } while (0)

int main(void) {
    /* JSON: typical `aws configure export-credentials` / IMDS output */
    const char *creds =
        "{\n"
        "  \"AccessKeyId\": \"AKIAEXAMPLE\",\n"
        "  \"SecretAccessKey\": \"sshh/secret+key\",\n"
        "  \"SessionToken\": \"FwoGZ...token\",\n"
        "  \"Expiration\": \"2026-05-18T18:42:00Z\"\n"
        "}";
    CHECK_STR(json_string_field(creds, "AccessKeyId"), "AKIAEXAMPLE");
    CHECK_STR(json_string_field(creds, "SecretAccessKey"), "sshh/secret+key");
    CHECK_STR(json_string_field(creds, "SessionToken"), "FwoGZ...token");
    CHECK_STR(json_string_field(creds, "Expiration"),
              "2026-05-18T18:42:00Z");
    CHECK(json_string_field(creds, "Missing") == NULL);

    /* IMDS uses "Token" not "SessionToken" */
    const char *imds = "{\"Code\":\"Success\",\"Token\":\"abc\\\"def\"}";
    CHECK_STR(json_string_field(imds, "Token"), "abc\"def");

    time_t t = parse_iso8601("2026-05-18T18:42:00Z");
    CHECK(t > 0);
    /* round-trip the y/m/d back out */
    struct tm tm;
    gmtime_r(&t, &tm);
    CHECK(tm.tm_year + 1900 == 2026 && tm.tm_mon + 1 == 5 &&
          tm.tm_mday == 18 && tm.tm_hour == 18);

    /* XML: ListObjectsV2 response */
    const char *xml =
        "<?xml version=\"1.0\"?>"
        "<ListBucketResult>"
        "<IsTruncated>true</IsTruncated>"
        "<NextContinuationToken>tok123</NextContinuationToken>"
        "<Contents><Key>a%2Fb.txt</Key><Size>1234</Size>"
          "<ETag>\"abc\"</ETag></Contents>"
        "<Contents><Key>c.bin</Key><Size>9</Size>"
          "<ETag>\"def\"</ETag></Contents>"
        "<CommonPrefixes><Prefix>dir1%2F</Prefix></CommonPrefixes>"
        "<CommonPrefixes><Prefix>dir2%2F</Prefix></CommonPrefixes>"
        "</ListBucketResult>";
    CHECK_STR(xml_tag(xml, "IsTruncated", NULL), "true");
    CHECK_STR(xml_tag(xml, "NextContinuationToken", NULL), "tok123");

    const char *end = NULL;
    char *k1 = xml_tag(xml, "Key", &end);
    CHECK(k1 && strcmp(k1, "a%2Fb.txt") == 0);
    free(k1);
    char *k2 = xml_tag(end, "Key", &end);
    CHECK(k2 && strcmp(k2, "c.bin") == 0);
    free(k2);

    char dec[] = "a%2Fb%20c+d";
    url_decode_inplace(dec);
    CHECK(strcmp(dec, "a/b c d") == 0);

    /* query-value encoding: '/', '+', '=' must all be percent-encoded
       (S3 continuation tokens arrive un-encoded and contain them) */
    char *enc = url_encode("a/b c+d=e");
    CHECK(enc && strcmp(enc, "a%2Fb%20c%2Bd%3De") == 0);
    free(enc);
    char *tok = url_encode("1zU+OA/vi==");
    CHECK(tok && strcmp(tok, "1zU%2BOA%2Fvi%3D%3D") == 0);
    free(tok);

    /* UploadId extraction for multipart */
    const char *mp = "<InitiateMultipartUploadResult>"
                      "<UploadId>VXBsb2FkIElE</UploadId>"
                      "</InitiateMultipartUploadResult>";
    CHECK_STR(xml_tag(mp, "UploadId", NULL), "VXBsb2FkIElE");

    printf(fails ? "test_parsers: %d FAILED\n" : "test_parsers: OK\n",
           fails);
    return fails ? 1 : 0;
}
