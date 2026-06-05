/* Credential-resolver tests with no AWS account.
 *
 * Strategy: point $HOME at a temp dir holding fixture ~/.aws files and
 * neutralise the earlier resolution stages so the INI/env branches are
 * what actually runs:
 *   - PATH is emptied so popen("aws ...") fails (no export-credentials)
 *   - AWS_EC2_METADATA_DISABLED is irrelevant to us, but there is no
 *     169.254.169.254 route off EC2 so IMDSv2 fails on its 1s timeout
 *   - AWS_PROFILE is cleared so the explicit-profile path is skipped
 *
 * Links the instrumented library; reaches the SSO/ISO8601 helpers via
 * the internal test header (single translation unit -> honest coverage).
 */
#include "libs3_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static char tmpl[] = "/tmp/libs3credXXXXXX";

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(2); }
    fputs(content, f);
    fclose(f);
}

int main(void) {
    char *home = mkdtemp(tmpl);
    if (!home) { perror("mkdtemp"); return 2; }
    char awsdir[256], creds[256], config[256];
    snprintf(awsdir, sizeof awsdir, "%s/.aws", home);
    mkdir(awsdir, 0700);
    snprintf(creds,  sizeof creds,  "%s/.aws/credentials", home);
    snprintf(config, sizeof config, "%s/.aws/config", home);

    /* Neutralise export-credentials + explicit profile + env keys. */
    setenv("HOME", home, 1);
    setenv("PATH", "", 1);                 /* popen("aws ...") -> fail */
    /* Point IMDS at a dead port so the instance-role step fails fast and
       resolution falls through to the INI/env paths these cases assert.
       (Without this the test fails *on an EC2 box with a role attached*,
       because IMDS correctly outranks INI/env in the resolution chain.) */
    setenv("LIBS3_IMDS_BASE", "http://127.0.0.1:1", 1);
    unsetenv("AWS_PROFILE");
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    unsetenv("AWS_SESSION_TOKEN");
    unsetenv("AWS_DEFAULT_REGION");

    /* --- 1. INI: default profile from ~/.aws/credentials ------------- */
    write_file(creds,
        "[default]\n"
        "aws_access_key_id = AKIA_DEFAULT\n"
        "aws_secret_access_key = secret_default\n"
        "aws_session_token = tok_default\n"
        "\n"
        "[work]\n"
        "aws_access_key_id = AKIA_WORK\n"
        "aws_secret_access_key = secret_work\n");
    write_file(config,
        "[default]\nregion = us-east-1\n"
        "[profile work]\nregion = eu-west-1\n");

    s3_credentials cr = {0};
    s3_status rc = s3_credentials_load("default", &cr);
    CHECK(rc == S3_OK);
    CHECK(strcmp(cr.access_key, "AKIA_DEFAULT") == 0);
    CHECK(strcmp(cr.secret_key, "secret_default") == 0);
    CHECK(strcmp(cr.session_token, "tok_default") == 0);
    CHECK(strcmp(cr.region, "us-east-1") == 0);
    s3_credentials_free(&cr);

    /* --- 2. INI: named non-default profile via $AWS_PROFILE ---------- */
    /* (AWS_PROFILE also drives the export-creds path, which fails with
       empty PATH, so resolution falls through to the INI parser.) */
    setenv("AWS_PROFILE", "work", 1);
    rc = s3_credentials_load("default", &cr);
    CHECK(rc == S3_OK);
    CHECK(strcmp(cr.access_key, "AKIA_WORK") == 0);
    CHECK(strcmp(cr.region, "eu-west-1") == 0);
    s3_credentials_free(&cr);
    unsetenv("AWS_PROFILE");

    /* --- 3. Environment variables win when INI is absent ------------- */
    unlink(creds);
    unlink(config);
    setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "secret_env", 1);
    setenv("AWS_DEFAULT_REGION", "ap-south-1", 1);
    rc = s3_credentials_load(NULL, &cr);
    CHECK(rc == S3_OK);
    CHECK(strcmp(cr.access_key, "AKIA_ENV") == 0);
    CHECK(strcmp(cr.region, "ap-south-1") == 0);
    s3_credentials_free(&cr);
    s3_credentials_from_env(&cr);
    CHECK(strcmp(cr.access_key, "AKIA_ENV") == 0);
    s3_credentials_free(&cr);

    /* --- 4. Nothing anywhere -> S3_ERR_NO_CREDS --------------------- */
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    unsetenv("AWS_DEFAULT_REGION");
    /* s3_credentials_load caches resolved creds; subtest 3 populated it. The
       creds were just revoked, so drop the cache to observe the miss. */
    libs3_test_reset_cred_cache();
    rc = s3_credentials_load(NULL, &cr);
    CHECK(rc == S3_ERR_NO_CREDS);
    s3_credentials_free(&cr);

    /* --- 5. SSO-profile scanner (static helper) --------------------- */
    write_file(config,
        "[default]\nregion = us-east-1\n"
        "[profile sso-a]\n"
        "sso_account_id = 111111111111\n"
        "sso_role_name = Admin\n"
        "[profile plain]\naws_access_key_id = X\n"
        "[profile sso-b]\nsso_session = corp\n");
    char **profs = NULL; size_t np = 0;
    find_sso_profiles(&profs, &np);
    CHECK(np == 2);
    int seen_a = 0, seen_b = 0;
    for (size_t i = 0; i < np; i++) {
        if (strcmp(profs[i], "sso-a") == 0) seen_a = 1;
        if (strcmp(profs[i], "sso-b") == 0) seen_b = 1;
        free(profs[i]);
    }
    free(profs);
    CHECK(seen_a && seen_b);

    /* --- 6. ISO8601 parse + bad input ------------------------------- */
    CHECK(parse_iso8601("2026-05-18T18:42:00Z") > 0);
    CHECK(parse_iso8601("garbage") == 0);

    /* --- 7. resolved-credential cache ------------------------------- */
    /* A fresh resolution is cached and served on the next call even after the
       underlying source changes; reset forces a re-read. This is what stops a
       per-request cred provider from popen()ing the `aws` CLI every call. */
    unlink(creds); unlink(config);
    libs3_test_reset_cred_cache();
    setenv("AWS_ACCESS_KEY_ID", "AKIA_CACHE1", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "secret1", 1);
    rc = s3_credentials_load(NULL, &cr);
    CHECK(rc == S3_OK && strcmp(cr.access_key, "AKIA_CACHE1") == 0);
    s3_credentials_free(&cr);
    /* mutate the source: a NON-cached load would now see CACHE2; the cache
       must still return CACHE1. */
    setenv("AWS_ACCESS_KEY_ID", "AKIA_CACHE2", 1);
    rc = s3_credentials_load(NULL, &cr);
    CHECK(rc == S3_OK && strcmp(cr.access_key, "AKIA_CACHE1") == 0);  /* served from cache */
    s3_credentials_free(&cr);
    /* reset -> re-resolve -> see the new value */
    libs3_test_reset_cred_cache();
    rc = s3_credentials_load(NULL, &cr);
    CHECK(rc == S3_OK && strcmp(cr.access_key, "AKIA_CACHE2") == 0);  /* fresh */
    s3_credentials_free(&cr);
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    libs3_test_reset_cred_cache();

    /* cleanup temp dir */
    unlink(config);
    rmdir(awsdir);
    rmdir(home);

    printf(fails ? "test_creds: %d FAILED\n" : "test_creds: OK\n", fails);
    return fails ? 1 : 0;
}
