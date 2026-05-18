/*
 * Fuzz harness for libs3's response parsers -- the code that consumes
 * untrusted bytes from an S3 / IMDS server:
 *
 *   xml_tag / list-XML walking      (ListObjectsV2, multipart responses)
 *   json_string_field              (IMDS / export-credentials JSON)
 *   s3_url_parse / s3_url_to_https  (s3:// URL handling)
 *   url_decode_inplace             (encoding-type=url key/prefix decode)
 *
 * Uses the standard libFuzzer entry point `LLVMFuzzerTestOneInput`, so
 * the same harness builds with either:
 *   - AFL++:     afl-clang-lto  -fsanitize=fuzzer  (see fuzz/build.sh)
 *   - libFuzzer: clang -fsanitize=fuzzer,address,undefined
 *
 * The first input byte selects which parser to drive, so one corpus +
 * one fuzzer covers every parser.
 */
#include "libs3_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Walk a ListObjectsV2-shaped body exactly as s3_list does. */
static void exercise_list_xml(const char *body) {
    const char *p = body, *end;
    while ((p = strstr(p, "<CommonPrefixes>")) != NULL) {
        const char *be = strstr(p, "</CommonPrefixes>");
        char *pref = xml_tag(p, "Prefix", &end);
        if (pref) { url_decode_inplace(pref); free(pref); }
        p = be ? be + 17 : p + 16;
    }
    p = body;
    while ((p = strstr(p, "<Contents>")) != NULL) {
        const char *be = strstr(p, "</Contents>");
        size_t blen = be ? (size_t)(be - p) : strlen(p);
        char *blk = malloc(blen + 1);
        if (!blk) return;
        memcpy(blk, p, blen);
        blk[blen] = 0;
        char *k = xml_tag(blk, "Key", NULL);
        char *s = xml_tag(blk, "Size", NULL);
        char *e = xml_tag(blk, "ETag", NULL);
        if (k) url_decode_inplace(k);
        free(k); free(s); free(e); free(blk);
        p = be ? be + 11 : p + 10;
    }
    char *t  = xml_tag(body, "IsTruncated", NULL);
    char *nt = xml_tag(body, "NextContinuationToken", NULL);
    char *ui = xml_tag(body, "UploadId", NULL);
    free(t); free(nt); free(ui);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    if (len < 1) return 0;

    /* Private NUL-terminated copy: the parsers are C-string based, just
       as libcurl keeps its write buffer NUL-terminated. data+1..end is
       the payload; data[0] selects the parser. */
    char *s = malloc(len);          /* (len-1) payload bytes + NUL */
    if (!s) return 0;
    memcpy(s, data + 1, len - 1);
    s[len - 1] = '\0';

    switch (data[0] & 3) {
    case 0:
        exercise_list_xml(s);
        break;
    case 1: {
        static const char *keys[] = {
            "AccessKeyId", "SecretAccessKey", "Token",
            "SessionToken", "Expiration", "Code", "" };
        for (int i = 0; keys[i][0]; i++)
            free(json_string_field(s, keys[i]));
        break;
    }
    case 2: {
        s3_url u;
        if (s3_url_parse(s, &u) == S3_OK) {
            char buf[2048];
            s3_url_to_https(&u, buf, sizeof buf);
            s3_url_free(&u);
        }
        break;
    }
    case 3:
        url_decode_inplace(s);      /* in-place; s is writable */
        break;
    }

    free(s);
    return 0;
}
