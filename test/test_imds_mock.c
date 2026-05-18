/* IMDSv2 tests against a local mock metadata server -- runs anywhere,
 * no EC2 needed. Covers the token+role+creds fetch sequence, JSON parse,
 * the in-process cache (hit / refresh-before-expiry / stale fallback),
 * and the missing-role / bad-JSON error paths.
 *
 * libs3's IMDS base is overridden to this mock via $LIBS3_IMDS_BASE
 * (set before any libs3 call). Links the instrumented test library.
 */
#include "libs3_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* ---- controllable mock metadata server ---------------------------- */

static int    g_listen_fd = -1;
static int    g_port = 0;
static atomic_int g_stop = 0;

/* Scripted responses, shared between the test (mutator) and the server
 * thread (reader). All access is under g_mtx -- without it TSan flags
 * the snprintf-in-set_creds vs write-in-send_resp race (a test bug, not
 * a libs3 one). */
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static char g_token[128]   = "MOCKTOKEN";
static char g_role[128]    = "libs3-test-role";
static char g_creds[1024]  = "";
static int  g_role_status  = 200;   /* set 404 to simulate "no role" */
static int  g_token_status = 200;
static int  g_hits_token = 0, g_hits_role = 0, g_hits_creds = 0;

static void send_resp(int fd, int status, const char *body) {
    char hdr[256];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, status == 200 ? "OK" : "Not Found",
        body ? strlen(body) : 0);
    write(fd, hdr, n);
    if (body && body[0]) write(fd, body, strlen(body));
}

static void *serve(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        int cfd = accept(g_listen_fd, NULL, NULL);
        if (cfd < 0) continue;
        char req[2048] = {0};
        ssize_t r = read(cfd, req, sizeof req - 1);
        if (r <= 0) { close(cfd); continue; }

        /* crude method + path parse of the request line */
        char method[8] = {0}, path[512] = {0};
        sscanf(req, "%7s %511s", method, path);

        /* Snapshot the scripted state under the lock, then respond
           outside it (no blocking socket I/O while holding the mutex). */
        int status = 404;
        char body[1024] = "";
        pthread_mutex_lock(&g_mtx);
        if (strcmp(method, "PUT") == 0 &&
            strstr(path, "/latest/api/token")) {
            g_hits_token++;
            status = g_token_status;
            if (status == 200) snprintf(body, sizeof body, "%s", g_token);
        } else if (strstr(path, "/security-credentials/") &&
                   path[strlen(path) - 1] == '/') {
            g_hits_role++;
            status = g_role_status;
            if (status == 200) snprintf(body, sizeof body, "%s", g_role);
        } else if (strstr(path, "/security-credentials/")) {
            g_hits_creds++;
            status = 200;
            snprintf(body, sizeof body, "%s", g_creds);
        }
        pthread_mutex_unlock(&g_mtx);
        send_resp(cfd, status, body);
        close(cfd);
    }
    return NULL;
}

static pthread_t g_thr;

static void start_mock(void) {
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;                              /* ephemeral */
    bind(g_listen_fd, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(g_listen_fd, (struct sockaddr *)&a, &al);
    g_port = ntohs(a.sin_port);
    listen(g_listen_fd, 8);
    pthread_create(&g_thr, NULL, serve, NULL);
}

static void stop_mock(void) {
    atomic_store(&g_stop, 1);
    /* unblock accept() with a throwaway connection */
    int f = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(g_port);
    connect(f, (struct sockaddr *)&a, sizeof a);
    close(f);
    pthread_join(g_thr, NULL);
    close(g_listen_fd);
}

/* Build a creds JSON blob with an expiry `secs` from now (0 = none). */
static void set_creds(const char *ak, const char *sk, const char *tok,
                      int secs_from_now) {
    pthread_mutex_lock(&g_mtx);
    if (secs_from_now) {
        time_t t = time(NULL) + secs_from_now;
        struct tm tm;
        gmtime_r(&t, &tm);
        char iso[32];
        strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tm);
        snprintf(g_creds, sizeof g_creds,
            "{\"Code\":\"Success\",\"AccessKeyId\":\"%s\","
            "\"SecretAccessKey\":\"%s\",\"Token\":\"%s\","
            "\"Expiration\":\"%s\"}", ak, sk, tok, iso);
    } else {
        snprintf(g_creds, sizeof g_creds,
            "{\"Code\":\"Success\",\"AccessKeyId\":\"%s\","
            "\"SecretAccessKey\":\"%s\",\"Token\":\"%s\"}",
            ak, sk, tok);
    }
    pthread_mutex_unlock(&g_mtx);
}

/* Locked setters/getters for the other scripted globals + hit counters. */
static void set_status(int *which, int val) {
    pthread_mutex_lock(&g_mtx);
    *which = val;
    pthread_mutex_unlock(&g_mtx);
}
static void set_creds_raw(const char *s) {
    pthread_mutex_lock(&g_mtx);
    snprintf(g_creds, sizeof g_creds, "%s", s);
    pthread_mutex_unlock(&g_mtx);
}
static int get_hits(const int *counter) {
    pthread_mutex_lock(&g_mtx);
    int v = *counter;
    pthread_mutex_unlock(&g_mtx);
    return v;
}

int main(void) {
    start_mock();
    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", g_port);
    setenv("LIBS3_IMDS_BASE", base, 1);

    s3_credentials cr = {0};
    time_t exp = 0;

    /* --- 1. happy path: token -> role -> creds with expiry ---------- */
    set_creds("AKIA_IMDS", "secret_imds", "session_imds", 3600);
    libs3_test_reset_imds_cache();
    CHECK(libs3_test_fetch_imds(&cr, &exp));
    CHECK(strcmp(cr.access_key, "AKIA_IMDS") == 0);
    CHECK(strcmp(cr.secret_key, "secret_imds") == 0);
    CHECK(strcmp(cr.session_token, "session_imds") == 0);
    CHECK(exp > time(NULL));
    CHECK(get_hits(&g_hits_token) >= 1 &&
          get_hits(&g_hits_role) >= 1 &&
          get_hits(&g_hits_creds) >= 1);
    s3_credentials_free(&cr);

    /* --- 2. no IAM role attached (listing 404) -> failure ----------- */
    set_status(&g_role_status, 404);
    libs3_test_reset_imds_cache();
    CHECK(!libs3_test_fetch_imds(&cr, &exp));
    s3_credentials_free(&cr);
    set_status(&g_role_status, 200);

    /* --- 3. token endpoint down -> failure (not on EC2 / IMDS off) -- */
    set_status(&g_token_status, 404);
    libs3_test_reset_imds_cache();
    CHECK(!libs3_test_fetch_imds(&cr, &exp));
    s3_credentials_free(&cr);
    set_status(&g_token_status, 200);

    /* --- 4. malformed creds JSON -> parse failure ------------------- */
    set_creds_raw("{not valid json");
    libs3_test_reset_imds_cache();
    CHECK(!libs3_test_fetch_imds(&cr, &exp));
    s3_credentials_free(&cr);

    /* --- 5. cache hit: second cached call makes no new creds fetch -- */
    set_creds("AK_CACHE", "SK_CACHE", "TOK_CACHE", 3600);
    libs3_test_reset_imds_cache();
    int creds_before = get_hits(&g_hits_creds);
    CHECK(libs3_test_cached_imds(&cr));
    CHECK(strcmp(cr.access_key, "AK_CACHE") == 0);
    s3_credentials_free(&cr);
    int after_first = get_hits(&g_hits_creds);
    CHECK(after_first > creds_before);            /* fetched once */
    CHECK(libs3_test_cached_imds(&cr));           /* served from cache */
    CHECK(strcmp(cr.access_key, "AK_CACHE") == 0);
    CHECK(get_hits(&g_hits_creds) == after_first);/* no new fetch */
    s3_credentials_free(&cr);

    /* --- 6. refresh-before-expiry: creds expiring within 5 min are
             re-fetched on the next cached call ----------------------- */
    set_creds("AK_OLD", "SK_OLD", "TOK_OLD", 120);  /* < 300s margin */
    libs3_test_reset_imds_cache();
    CHECK(libs3_test_cached_imds(&cr));
    CHECK(strcmp(cr.access_key, "AK_OLD") == 0);
    s3_credentials_free(&cr);
    int h = get_hits(&g_hits_creds);
    set_creds("AK_NEW", "SK_NEW", "TOK_NEW", 3600);
    CHECK(libs3_test_cached_imds(&cr));            /* must refresh */
    CHECK(strcmp(cr.access_key, "AK_NEW") == 0);
    CHECK(get_hits(&g_hits_creds) > h);
    s3_credentials_free(&cr);

    /* --- 7. stale-cache fallback: refresh fails but unexpired copy
             is still served --------------------------------------- */
    set_creds("AK_KEEP", "SK_KEEP", "TOK_KEEP", 3600);
    libs3_test_reset_imds_cache();
    CHECK(libs3_test_cached_imds(&cr));
    s3_credentials_free(&cr);
    set_status(&g_token_status, 500);              /* break refresh */
    /* not within refresh window (3600s > 300s) so cache is returned
       without attempting a refresh -- still valid */
    CHECK(libs3_test_cached_imds(&cr));
    CHECK(strcmp(cr.access_key, "AK_KEEP") == 0);
    s3_credentials_free(&cr);
    set_status(&g_token_status, 200);

    /* --- 8. full s3_credentials_load path uses IMDS when no profile,
             no export-creds (PATH emptied), no INI, no env ---------- */
    setenv("PATH", "", 1);
    unsetenv("AWS_PROFILE");
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    setenv("HOME", "/nonexistent-libs3-home", 1);
    set_creds("AK_LOAD", "SK_LOAD", "TOK_LOAD", 3600);
    libs3_test_reset_imds_cache();
    s3_status rc = s3_credentials_load(NULL, &cr);
    printf("load via IMDS rc=%d key=%s\n", rc,
           cr.access_key ? cr.access_key : "(null)");
    CHECK(rc == S3_OK && strcmp(cr.access_key, "AK_LOAD") == 0 &&
          strcmp(cr.session_token, "TOK_LOAD") == 0);
    s3_credentials_free(&cr);

    stop_mock();
    printf(fails ? "test_imds_mock: %d FAILED\n" : "test_imds_mock: OK\n",
           fails);
    return fails ? 1 : 0;
}
