/* Real EC2 IMDSv2 test. Gated behind LIBS3_IMDS=1 and meant to run ON an
 * EC2 instance that has an IAM role attached. Exercises the genuine
 * link-local 169.254.169.254 path (which no mock/CI can), then performs
 * a real SigV4-signed GET to prove the resolved instance-role
 * credentials actually work end to end.
 *
 *   # on the EC2 box, after building:
 *   LIBS3_IMDS=1 ./build/test_imds_ec2
 *   # optional: a key the instance role can read (proves signing on a
 *   #           private object, not just the public open-data bucket):
 *   LIBS3_IMDS=1 LIBS3_IMDS_TEST_URL=s3://my-bucket/some-key \
 *       ./build/test_imds_ec2
 *
 * Note: this test must NOT set LIBS3_IMDS_BASE -- it deliberately hits
 * the real metadata service.
 */
#include "libs3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PUBLIC_URL \
    "s3://vesuvius-challenge-open-data/PHerc0172/volumes/" \
    "20241024131838-7.910um-53keV-masked.zarr/.zgroup"

int main(void) {
    if (!getenv("LIBS3_IMDS")) {
        printf("test_imds_ec2: SKIPPED "
               "(set LIBS3_IMDS=1 on an EC2 instance with a role)\n");
        return 0;
    }
    if (getenv("LIBS3_IMDS_BASE")) {
        printf("test_imds_ec2: REFUSING -- LIBS3_IMDS_BASE is set; "
               "this test must hit the real metadata service\n");
        return 1;
    }

    int fails = 0;

    /* 1. Resolve credentials. With no AWS_PROFILE / no working `aws`
       CLI on a clean instance, resolution falls through to IMDSv2.
       We assert the instance-role shape: non-empty key/secret AND a
       session token (instance-role creds are always temporary). */
    unsetenv("AWS_PROFILE");
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    unsetenv("AWS_SESSION_TOKEN");

    s3_credentials cr = {0};
    s3_status rc = s3_credentials_load(NULL, &cr);
    printf("IMDS resolve rc=%d key=%.8s... token=%s\n", rc,
           cr.access_key ? cr.access_key : "(null)",
           (cr.session_token && cr.session_token[0]) ? "present"
                                                     : "MISSING");
    if (rc != S3_OK) { fails++; }
    if (!cr.access_key || !cr.access_key[0] ||
        !cr.secret_key || !cr.secret_key[0]) {
        printf("  FAIL: empty instance-role credentials\n");
        fails++;
    }
    if (!cr.session_token || !cr.session_token[0]) {
        /* instance-role creds are STS temporaries -> token expected */
        printf("  FAIL: no session token (not instance-role creds?)\n");
        fails++;
    }

    /* 2. Prove the creds actually sign a working request. */
    s3_config cfg = {0};
    cfg.creds = cr;
    if (!cfg.creds.region || !cfg.creds.region[0])
        cfg.creds.region = (char *)"us-east-1";
    s3_client *c = s3_client_new(&cfg);

    const char *url = getenv("LIBS3_IMDS_TEST_URL");
    int private_obj = url && url[0];
    if (!private_obj) url = PUBLIC_URL;

    s3_response r = {0};
    rc = s3_get(c, url, &r);
    printf("signed GET %s -> rc=%d status=%ld bytes=%zu\n",
           private_obj ? "(private, role-scoped)" : "(public open-data)",
           rc, r.status, r.body_len);

    if (private_obj) {
        /* A private object only succeeds if SigV4 signing with the
           instance-role creds is correct. */
        if (rc != S3_OK || !s3_response_ok(&r)) {
            printf("  FAIL: signed request to private object failed\n");
            fails++;
        }
    } else {
        /* Public bucket: still asserts the request completed and the
           transport/signing path didn't error. (A public object would
           also serve anonymously, so this is a weaker check -- set
           LIBS3_IMDS_TEST_URL to a private key for a strong one.) */
        if (rc != S3_OK || !s3_response_ok(&r)) {
            printf("  FAIL: signed GET against public bucket failed\n");
            fails++;
        }
    }
    s3_response_free(&r);

    /* 2b. Optional write proof: if LIBS3_IMDS_WRITE_PREFIX names an
       s3:// prefix the instance role may write (e.g. the role's scoped
       path), round-trip PUT -> GET -> DELETE. This proves SigV4 signing
       with IMDS STS creds works for writes, not just reads. */
    const char *wp = getenv("LIBS3_IMDS_WRITE_PREFIX");
    if (wp && wp[0]) {
        size_t n = strlen(wp);
        char key[1024];
        snprintf(key, sizeof key, "%s%slibs3-imds-writetest.txt",
                 wp, (n && wp[n - 1] == '/') ? "" : "/");
        const char *body = "written via instance-role creds (libs3)\n";

        rc = s3_put(c, key, body, strlen(body), "text/plain", &r);
        printf("write PUT %s -> rc=%d status=%ld\n", key, rc, r.status);
        if (rc != S3_OK || !s3_response_ok(&r)) fails++;
        s3_response_free(&r);

        rc = s3_get(c, key, &r);
        printf("write GET -> rc=%d status=%ld bytes=%zu\n",
               rc, r.status, r.body_len);
        if (rc != S3_OK || r.body_len != strlen(body) ||
            memcmp(r.body, body, r.body_len) != 0)
            fails++;
        s3_response_free(&r);

        rc = s3_delete(c, key, &r);
        printf("write DELETE -> rc=%d status=%ld\n", rc, r.status);
        if (rc != S3_OK) fails++;
        s3_response_free(&r);
    } else {
        printf("write proof SKIPPED "
               "(set LIBS3_IMDS_WRITE_PREFIX to a role-writable s3:// prefix)\n");
    }

    /* 3. The in-process cache should serve a second resolve without a
       fresh metadata round trip (we can't see hit counts here, but it
       must still return the same identity). */
    s3_credentials cr2 = {0};
    rc = s3_credentials_load(NULL, &cr2);
    if (rc != S3_OK || !cr2.access_key ||
        strcmp(cr.access_key, cr2.access_key) != 0) {
        printf("  FAIL: cached re-resolve changed identity\n");
        fails++;
    }
    s3_credentials_free(&cr2);

    s3_client_free(c);
    s3_credentials_free(&cr);

    printf(fails ? "test_imds_ec2: %d FAILED\n" : "test_imds_ec2: OK\n",
           fails);
    return fails ? 1 : 0;
}
