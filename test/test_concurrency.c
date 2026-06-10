/* Concurrency stress test -- the verification ThreadSanitizer is for.
 *
 * Mirrors volume-cartographer's usage: many worker threads sharing a
 * single s3_client, hammering GET / ranged GET / HEAD / batched GET,
 * with a refresh-aware cred_provider re-resolved per request, plus the
 * process-wide fast-abort flag flipped mid-flight (VC's shutdown path).
 *
 * Build + run under TSan to catch data races on the thread-local curl
 * handle, the IMDS/cred cache mutex, and the atomic abort flag:
 *   cmake -S . -B build-tsan -DLIBS3_TSAN=ON -DCMAKE_C_COMPILER=clang-21
 *   cmake --build build-tsan
 *   LIBS3_MINIO=1 ./build-tsan/test_concurrency
 *
 * The shared-state portion (abort flag + provider racing) always runs;
 * the network loop is gated on LIBS3_MINIO=1 (needs local MinIO up).
 */
#include "libs3.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUCKET   "s3://libs3-test/"
#define NTHREADS 16
#define NOBJS    8

static int fails = 0;
#define CHECK(c) do { if (!(c)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
    atomic_fetch_add(&g_fail, 1); } } while (0)
static atomic_int g_fail = 0;

/* Refresh-aware provider: called per request from every worker thread
 * concurrently -- exercises resolve_request_creds + the cred path under
 * contention. Returns freshly-owned strings each call (libs3 frees). */
static atomic_int g_provider_calls = 0;
static s3_status mc_provider(void *ud, s3_credentials *out) {
    (void)ud;
    atomic_fetch_add(&g_provider_calls, 1);
    out->access_key    = strdup("libs3test");
    out->secret_key    = strdup("libs3secret");
    out->session_token = strdup("");
    out->region        = strdup("us-east-1");
    return S3_OK;
}

static s3_client *g_client;
static atomic_int g_started = 0;

/* Worker: repeatedly GET / range / HEAD / batch a random object. */
static void *worker(void *arg) {
    long id = (long)arg;
    atomic_fetch_add(&g_started, 1);
    char key[64];
    for (int it = 0; it < 25; it++) {
        int o = (int)((id + it) % NOBJS);
        snprintf(key, sizeof key, BUCKET "obj-%d.bin", o);
        s3_response r = {0};
        s3_status rc;

        switch (it % 4) {
        case 0:
            rc = s3_get(g_client, key, &r);
            if (!s3_global_is_aborted())
                CHECK(rc == S3_OK || rc == S3_ERR_ABORTED);
            break;
        case 1:
            rc = s3_get_range(g_client, key, 0, 64, &r);
            if (!s3_global_is_aborted())
                CHECK(rc == S3_OK || rc == S3_ERR_ABORTED);
            break;
        case 2:
            rc = s3_head(g_client, key, &r);
            if (!s3_global_is_aborted())
                CHECK(rc == S3_OK || rc == S3_ERR_ABORTED);
            break;
        case 3: {
            char k2[64];
            snprintf(k2, sizeof k2, BUCKET "obj-%d.bin",
                     (o + 1) % NOBJS);
            s3_range_req rq[2] = { { key, 0, 32, 0 }, { k2, 0, 0, 0 } };
            s3_response br[2] = {0};
            rc = s3_get_batch(g_client, rq, 2, 2, br);
            (void)rc;
            s3_response_free(&br[0]);
            s3_response_free(&br[1]);
            break;
        }
        }
        s3_response_free(&r);
    }
    return NULL;
}

/* File-scope (clang has no nested functions -- and clang is what we
 * run under TSan). Race the process-wide abort flag. */
static atomic_int g_flag_stop = 0;
static void *flag_flipper(void *a) {
    (void)a;
    for (int i = 0; i < 100000 && !atomic_load(&g_flag_stop); i++) {
        s3_global_abort();
        s3_global_reset_abort();
    }
    return NULL;
}
static void *flag_reader(void *a) {
    (void)a;
    for (int i = 0; i < 100000 && !atomic_load(&g_flag_stop); i++)
        (void)s3_global_is_aborted();
    return NULL;
}

int main(void) {
    /* ---- always-on: race the abort flag + provider, no network ---- */
    {
        s3_config cfg = { .cred_provider = mc_provider };
        s3_client *c = s3_client_new(&cfg);
        CHECK(c != NULL);

        /* Hammer the global abort flag: two threads flipping it while
           two read it -- TSan verifies the atomic is race-free. */
        s3_global_reset_abort();
        atomic_store(&g_flag_stop, 0);
        pthread_t f1, f2, r1, r2;
        pthread_create(&f1, NULL, flag_flipper, NULL);
        pthread_create(&f2, NULL, flag_flipper, NULL);
        pthread_create(&r1, NULL, flag_reader, NULL);
        pthread_create(&r2, NULL, flag_reader, NULL);
        usleep(200000);
        atomic_store(&g_flag_stop, 1);
        pthread_join(f1, NULL); pthread_join(f2, NULL);
        pthread_join(r1, NULL); pthread_join(r2, NULL);
        s3_global_reset_abort();
        s3_client_free(c);
        printf("abort-flag race: clean\n");
    }

    if (!getenv("LIBS3_MINIO")) {
        printf("test_concurrency: network part SKIPPED "
               "(set LIBS3_MINIO=1 with MinIO up)\n");
        printf(atomic_load(&g_fail) ? "test_concurrency: FAILED\n"
                                    : "test_concurrency: OK\n");
        return atomic_load(&g_fail) ? 1 : 0;
    }

    /* ---- shared-client network stress ----------------------------- */
    s3_config cfg = {0};
    cfg.cred_provider     = mc_provider;     /* per-request, contended */
    cfg.endpoint          = "localhost:9000";
    cfg.endpoint_insecure = true;
    g_client = s3_client_new(&cfg);
    CHECK(g_client != NULL);

    /* seed objects */
    for (int o = 0; o < NOBJS; o++) {
        char key[64], body[256];
        snprintf(key, sizeof key, BUCKET "obj-%d.bin", o);
        memset(body, 'a' + o, sizeof body);
        s3_response r = {0};
        s3_status rc = s3_put(g_client, key, body, sizeof body,
                              "application/octet-stream", &r);
        CHECK(rc == S3_OK && s3_response_ok(&r));
        s3_response_free(&r);
    }

    /* Phase 1: NTHREADS workers, no abort -- pure shared-client load. */
    s3_global_reset_abort();
    pthread_t th[NTHREADS];
    for (long i = 0; i < NTHREADS; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);
    for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
    printf("phase1 (%d threads, no abort): done, provider_calls=%d\n",
           NTHREADS, atomic_load(&g_provider_calls));

    /* Phase 2: workers running while another thread fires the
       process-wide abort mid-flight (VC fast-shutdown). Must not crash,
       hang, or race; in-flight calls return S3_ERR_ABORTED promptly. */
    s3_global_reset_abort();
    for (long i = 0; i < NTHREADS; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);
    while (atomic_load(&g_started) < NTHREADS) usleep(1000);
    usleep(5000);
    s3_global_abort();                       /* <-- mid-flight */
    for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
    printf("phase2 (abort mid-flight): all workers joined cleanly\n");
    s3_global_reset_abort();

    /* cleanup */
    for (int o = 0; o < NOBJS; o++) {
        char key[64];
        snprintf(key, sizeof key, BUCKET "obj-%d.bin", o);
        s3_response r = {0};
        s3_delete(g_client, key, &r);
        s3_response_free(&r);
    }
    s3_client_free(g_client);

    fails = atomic_load(&g_fail);
    printf(fails ? "test_concurrency: %d FAILED\n"
                 : "test_concurrency: OK\n", fails);
    return fails ? 1 : 0;
}
