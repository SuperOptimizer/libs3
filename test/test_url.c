/* URL parse / convert unit tests -- no network. */
#include "libs3.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    CHECK(s3_url_is_s3("s3://b/k"));
    CHECK(s3_url_is_s3("S3://b/k"));
    CHECK(s3_url_is_s3("s3+us-west-2://b/k"));
    CHECK(!s3_url_is_s3("https://example.com/x"));
    CHECK(!s3_url_is_s3("ftp://b/k"));
    CHECK(!s3_url_is_s3(NULL));

    s3_url u;
    CHECK(s3_url_parse("s3://my-bucket/path/to/key.txt", &u) == S3_OK);
    CHECK(strcmp(u.bucket, "my-bucket") == 0);
    CHECK(strcmp(u.key, "path/to/key.txt") == 0);
    CHECK(strcmp(u.region, "") == 0);
    char buf[256];
    CHECK(s3_url_to_https(&u, buf, sizeof buf) == S3_OK);
    CHECK(strcmp(buf,
        "https://my-bucket.s3.amazonaws.com/path/to/key.txt") == 0);
    s3_url_free(&u);

    CHECK(s3_url_parse("s3+us-west-2://bkt/k", &u) == S3_OK);
    CHECK(strcmp(u.region, "us-west-2") == 0);
    CHECK(s3_url_to_https(&u, buf, sizeof buf) == S3_OK);
    CHECK(strcmp(buf,
        "https://bkt.s3.us-west-2.amazonaws.com/k") == 0);
    s3_url_free(&u);

    /* bucket only, no key */
    CHECK(s3_url_parse("s3://bucket-only", &u) == S3_OK);
    CHECK(strcmp(u.bucket, "bucket-only") == 0);
    CHECK(strcmp(u.key, "") == 0);
    s3_url_free(&u);

    /* too-small buffer */
    CHECK(s3_url_parse("s3://b/k", &u) == S3_OK);
    char tiny[8];
    CHECK(s3_url_to_https(&u, tiny, sizeof tiny) == S3_ERR_INVALID_ARG);
    s3_url_free(&u);

    CHECK(s3_url_parse("https://nope", &u) == S3_ERR_INVALID_ARG);

    printf(fails ? "test_url: %d FAILED\n" : "test_url: OK\n", fails);
    return fails ? 1 : 0;
}
