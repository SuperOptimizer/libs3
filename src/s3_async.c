/*
 * libs3 — Async event loop, futures, and async operation variants
 */

#include "s3_internal.h"
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Event Loop — Background thread function
 * ═══════════════════════════════════════════════════════════════════════════ */

static void *s3__event_loop_thread(void *arg) {
    s3_event_loop *loop = (s3_event_loop *)arg;

    while (true) {
        pthread_mutex_lock(&loop->lock);
        bool running = loop->running;
        pthread_mutex_unlock(&loop->lock);

        if (!running) break;

        int numfds = 0;
        curl_multi_poll(loop->multi, nullptr, 0, 100, &numfds);

        int still_running = 0;
        curl_multi_perform(loop->multi, &still_running);

        /* Check for completed transfers */
        CURLMsg *msg;
        int msgs_in_queue;
        while ((msg = curl_multi_info_read(loop->multi, &msgs_in_queue)) != nullptr) {
            if (msg->msg == CURLMSG_DONE) {
                /* Transfer completed — curl_multi integration will be
                 * wired up later when individual operations use multi. */
                S3_UNUSED(msg);
            }
        }
    }

    return nullptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Event Loop — Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_event_loop_create(s3_event_loop **out, const s3_event_loop_opts *opts) {
    if (!out) return S3_STATUS_INVALID_ARGUMENT;

    s3_event_loop *loop = (s3_event_loop *)S3_CALLOC(1, sizeof(s3_event_loop));
    if (!loop) return S3_STATUS_OUT_OF_MEMORY;

    loop->multi = curl_multi_init();
    if (!loop->multi) {
        S3_FREE(loop);
        return S3_STATUS_INTERNAL_ERROR;
    }

    pthread_mutex_init(&loop->lock, nullptr);
    pthread_cond_init(&loop->cond, nullptr);

    loop->mode = opts ? opts->mode : S3_LOOP_AUTO;
    loop->max_concurrent = (opts && opts->max_concurrent > 0)
                               ? opts->max_concurrent : 64;
    loop->running = true;

    curl_multi_setopt(loop->multi, CURLMOPT_MAXCONNECTS, (long)loop->max_concurrent);

    if (loop->mode == S3_LOOP_AUTO) {
        int rc = pthread_create(&loop->thread, nullptr, s3__event_loop_thread, loop);
        if (rc != 0) {
            curl_multi_cleanup(loop->multi);
            pthread_mutex_destroy(&loop->lock);
            pthread_cond_destroy(&loop->cond);
            S3_FREE(loop);
            return S3_STATUS_INTERNAL_ERROR;
        }
    }

    *out = loop;
    return S3_STATUS_OK;
}

void s3_event_loop_destroy(s3_event_loop *loop) {
    if (!loop) return;

    pthread_mutex_lock(&loop->lock);
    loop->running = false;
    pthread_cond_broadcast(&loop->cond);
    pthread_mutex_unlock(&loop->lock);

    if (loop->mode == S3_LOOP_AUTO) {
        pthread_join(loop->thread, nullptr);
    }

    curl_multi_cleanup(loop->multi);
    pthread_mutex_destroy(&loop->lock);
    pthread_cond_destroy(&loop->cond);
    S3_FREE(loop);
}

s3_status s3_event_loop_poll(s3_event_loop *loop, int timeout_ms) {
    if (!loop) return S3_STATUS_INVALID_ARGUMENT;

    int numfds = 0;
    CURLMcode mc = curl_multi_poll(loop->multi, nullptr, 0, timeout_ms, &numfds);
    if (mc != CURLM_OK) return S3_STATUS_INTERNAL_ERROR;

    int still_running = 0;
    mc = curl_multi_perform(loop->multi, &still_running);
    if (mc != CURLM_OK) return S3_STATUS_INTERNAL_ERROR;

    /* Dispatch completed transfers */
    CURLMsg *msg;
    int msgs_in_queue;
    while ((msg = curl_multi_info_read(loop->multi, &msgs_in_queue)) != nullptr) {
        if (msg->msg == CURLMSG_DONE) {
            S3_UNUSED(msg);
        }
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Future — Internal helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_future *s3__future_create(void) {
    s3_future *f = (s3_future *)S3_CALLOC(1, sizeof(s3_future));
    if (!f) return nullptr;

    atomic_store(&f->state, S3_FUTURE_PENDING);
    f->status = S3_STATUS_OK;
    f->result = nullptr;
    f->result_size = 0;
    f->on_complete = nullptr;
    f->userdata = nullptr;

    pthread_mutex_init(&f->mutex, nullptr);
    pthread_cond_init(&f->cond, nullptr);

    return f;
}

void s3__future_complete(s3_future *f, s3_status status, void *result, size_t result_size) {
    if (!f) return;

    s3_completion_fn callback = nullptr;
    void *cb_userdata = nullptr;

    pthread_mutex_lock(&f->mutex);
    f->status = status;
    f->result = result;
    f->result_size = result_size;
    atomic_store(&f->state, (status == S3_STATUS_OK) ? S3_FUTURE_DONE : S3_FUTURE_FAILED);
    pthread_cond_broadcast(&f->cond);

    callback = f->on_complete;
    cb_userdata = f->userdata;
    pthread_mutex_unlock(&f->mutex);

    if (callback) {
        callback(f, cb_userdata);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Future — Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_future_state s3_future_state_get(const s3_future *f) {
    if (!f) return S3_FUTURE_FAILED;
    return (s3_future_state)atomic_load(&f->state);
}

bool s3_future_is_done(const s3_future *f) {
    if (!f) return true;
    int st = atomic_load(&f->state);
    return st == S3_FUTURE_DONE || st == S3_FUTURE_FAILED;
}

s3_status s3_future_wait(s3_future *f) {
    if (!f) return S3_STATUS_INVALID_ARGUMENT;

    pthread_mutex_lock(&f->mutex);
    while (!s3_future_is_done(f)) {
        pthread_cond_wait(&f->cond, &f->mutex);
    }
    s3_status status = f->status;
    pthread_mutex_unlock(&f->mutex);

    return status;
}

s3_status s3_future_status(const s3_future *f) {
    if (!f) return S3_STATUS_INVALID_ARGUMENT;
    return f->status;
}

void *s3_future_result(const s3_future *f) {
    if (!f) return nullptr;
    return f->result;
}

void s3_future_on_complete(s3_future *f, s3_completion_fn fn, void *userdata) {
    if (!f) return;

    bool already_done = false;

    pthread_mutex_lock(&f->mutex);
    f->on_complete = fn;
    f->userdata = userdata;
    already_done = s3_future_is_done(f);
    pthread_mutex_unlock(&f->mutex);

    if (already_done && fn) {
        fn(f, userdata);
    }
}

void s3_future_destroy(s3_future *f) {
    if (!f) return;

    if (f->result) {
        S3_FREE(f->result);
        f->result = nullptr;
    }

    pthread_mutex_destroy(&f->mutex);
    pthread_cond_destroy(&f->cond);
    S3_FREE(f);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Async Operation Variants — Thread-based implementation
 *
 * Each async variant spawns a detached thread that runs the sync version
 * and completes the future. This is a valid first implementation;
 * curl_multi integration can be added later.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* --- put_object_async --- */

typedef struct {
    s3_client              *client;
    char                   *bucket;
    char                   *key;
    void                   *data;
    size_t                  data_len;
    s3_put_object_opts     *opts;
    s3_future              *future;
} s3__put_object_async_ctx;

static void *s3__put_object_async_thread(void *arg) {
    s3__put_object_async_ctx *ctx = (s3__put_object_async_ctx *)arg;

    s3_put_object_result *result = (s3_put_object_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        status = S3_STATUS_OUT_OF_MEMORY;
        s3__future_complete(ctx->future, status, nullptr, 0);
    } else {
        status = s3_put_object(ctx->client, ctx->bucket, ctx->key,
                               ctx->data, ctx->data_len, ctx->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(ctx->future, status, result,
                            result ? sizeof(*result) : 0);
    }

    S3_FREE(ctx->bucket);
    S3_FREE(ctx->key);
    S3_FREE(ctx->data);
    S3_FREE(ctx->opts);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_put_object_async(s3_client *c, const char *bucket, const char *key,
                              const void *data, size_t data_len,
                              const s3_put_object_opts *opts, s3_future **future) {
    if (!c || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__put_object_async_ctx *ctx = (s3__put_object_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->bucket = s3__strdup(bucket);
    ctx->key = s3__strdup(key);
    ctx->future = f;
    ctx->data = nullptr;
    ctx->data_len = data_len;
    ctx->opts = nullptr;

    if (data && data_len > 0) {
        ctx->data = S3_MALLOC(data_len);
        if (!ctx->data) {
            S3_FREE(ctx->bucket);
            S3_FREE(ctx->key);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->data, data, data_len);
    }

    if (opts) {
        ctx->opts = (s3_put_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!ctx->opts) {
            S3_FREE(ctx->data);
            S3_FREE(ctx->bucket);
            S3_FREE(ctx->key);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->opts, opts, sizeof(*opts));
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__put_object_async_thread, ctx);
    if (rc != 0) {
        S3_FREE(ctx->opts);
        S3_FREE(ctx->data);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx->key);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}

/* --- get_object_async --- */

typedef struct {
    s3_client              *client;
    char                   *bucket;
    char                   *key;
    s3_get_object_opts     *opts;
    s3_future              *future;
} s3__get_object_async_ctx;

typedef struct {
    void   *data;
    size_t  data_len;
} s3__get_object_async_result;

static void *s3__get_object_async_thread(void *arg) {
    s3__get_object_async_ctx *ctx = (s3__get_object_async_ctx *)arg;

    void *data = nullptr;
    size_t data_len = 0;

    s3_status status = s3_get_object(ctx->client, ctx->bucket, ctx->key,
                                     &data, &data_len, ctx->opts);

    if (status == S3_STATUS_OK) {
        s3__get_object_async_result *result = (s3__get_object_async_result *)
            S3_CALLOC(1, sizeof(*result));
        if (result) {
            result->data = data;
            result->data_len = data_len;
            s3__future_complete(ctx->future, status, result, sizeof(*result));
        } else {
            S3_FREE(data);
            s3__future_complete(ctx->future, S3_STATUS_OUT_OF_MEMORY, nullptr, 0);
        }
    } else {
        s3__future_complete(ctx->future, status, nullptr, 0);
    }

    S3_FREE(ctx->bucket);
    S3_FREE(ctx->key);
    S3_FREE(ctx->opts);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_get_object_async(s3_client *c, const char *bucket, const char *key,
                              const s3_get_object_opts *opts, s3_future **future) {
    if (!c || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__get_object_async_ctx *ctx = (s3__get_object_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->bucket = s3__strdup(bucket);
    ctx->key = s3__strdup(key);
    ctx->future = f;
    ctx->opts = nullptr;

    if (opts) {
        ctx->opts = (s3_get_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!ctx->opts) {
            S3_FREE(ctx->bucket);
            S3_FREE(ctx->key);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->opts, opts, sizeof(*opts));
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__get_object_async_thread, ctx);
    if (rc != 0) {
        S3_FREE(ctx->opts);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx->key);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}

/* --- delete_object_async --- */

typedef struct {
    s3_client                *client;
    char                     *bucket;
    char                     *key;
    s3_delete_object_opts    *opts;
    s3_future                *future;
} s3__delete_object_async_ctx;

static void *s3__delete_object_async_thread(void *arg) {
    s3__delete_object_async_ctx *ctx = (s3__delete_object_async_ctx *)arg;

    s3_delete_object_result *result = (s3_delete_object_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        status = S3_STATUS_OUT_OF_MEMORY;
        s3__future_complete(ctx->future, status, nullptr, 0);
    } else {
        status = s3_delete_object(ctx->client, ctx->bucket, ctx->key,
                                  ctx->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(ctx->future, status, result,
                            result ? sizeof(*result) : 0);
    }

    S3_FREE(ctx->bucket);
    S3_FREE(ctx->key);
    S3_FREE(ctx->opts);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_delete_object_async(s3_client *c, const char *bucket, const char *key,
                                 const s3_delete_object_opts *opts, s3_future **future) {
    if (!c || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__delete_object_async_ctx *ctx = (s3__delete_object_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->bucket = s3__strdup(bucket);
    ctx->key = s3__strdup(key);
    ctx->future = f;
    ctx->opts = nullptr;

    if (opts) {
        ctx->opts = (s3_delete_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!ctx->opts) {
            S3_FREE(ctx->bucket);
            S3_FREE(ctx->key);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->opts, opts, sizeof(*opts));
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__delete_object_async_thread, ctx);
    if (rc != 0) {
        S3_FREE(ctx->opts);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx->key);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}

/* --- head_object_async --- */

typedef struct {
    s3_client              *client;
    char                   *bucket;
    char                   *key;
    s3_head_object_opts    *opts;
    s3_future              *future;
} s3__head_object_async_ctx;

static void *s3__head_object_async_thread(void *arg) {
    s3__head_object_async_ctx *ctx = (s3__head_object_async_ctx *)arg;

    s3_head_object_result *result = (s3_head_object_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        status = S3_STATUS_OUT_OF_MEMORY;
        s3__future_complete(ctx->future, status, nullptr, 0);
    } else {
        status = s3_head_object(ctx->client, ctx->bucket, ctx->key,
                                ctx->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(ctx->future, status, result,
                            result ? sizeof(*result) : 0);
    }

    S3_FREE(ctx->bucket);
    S3_FREE(ctx->key);
    S3_FREE(ctx->opts);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_head_object_async(s3_client *c, const char *bucket, const char *key,
                               const s3_head_object_opts *opts, s3_future **future) {
    if (!c || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__head_object_async_ctx *ctx = (s3__head_object_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->bucket = s3__strdup(bucket);
    ctx->key = s3__strdup(key);
    ctx->future = f;
    ctx->opts = nullptr;

    if (opts) {
        ctx->opts = (s3_head_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!ctx->opts) {
            S3_FREE(ctx->bucket);
            S3_FREE(ctx->key);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->opts, opts, sizeof(*opts));
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__head_object_async_thread, ctx);
    if (rc != 0) {
        S3_FREE(ctx->opts);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx->key);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}

/* --- copy_object_async --- */

typedef struct {
    s3_client              *client;
    char                   *src_bucket;
    char                   *src_key;
    char                   *dst_bucket;
    char                   *dst_key;
    s3_copy_object_opts    *opts;
    s3_future              *future;
} s3__copy_object_async_ctx;

static void *s3__copy_object_async_thread(void *arg) {
    s3__copy_object_async_ctx *ctx = (s3__copy_object_async_ctx *)arg;

    s3_copy_object_result *result = (s3_copy_object_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        status = S3_STATUS_OUT_OF_MEMORY;
        s3__future_complete(ctx->future, status, nullptr, 0);
    } else {
        status = s3_copy_object(ctx->client,
                                ctx->src_bucket, ctx->src_key,
                                ctx->dst_bucket, ctx->dst_key,
                                ctx->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(ctx->future, status, result,
                            result ? sizeof(*result) : 0);
    }

    S3_FREE(ctx->src_bucket);
    S3_FREE(ctx->src_key);
    S3_FREE(ctx->dst_bucket);
    S3_FREE(ctx->dst_key);
    S3_FREE(ctx->opts);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_copy_object_async(s3_client *c,
                               const char *src_bucket, const char *src_key,
                               const char *dst_bucket, const char *dst_key,
                               const s3_copy_object_opts *opts, s3_future **future) {
    if (!c || !src_bucket || !src_key || !dst_bucket || !dst_key || !future)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__copy_object_async_ctx *ctx = (s3__copy_object_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->src_bucket = s3__strdup(src_bucket);
    ctx->src_key = s3__strdup(src_key);
    ctx->dst_bucket = s3__strdup(dst_bucket);
    ctx->dst_key = s3__strdup(dst_key);
    ctx->future = f;
    ctx->opts = nullptr;

    if (opts) {
        ctx->opts = (s3_copy_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!ctx->opts) {
            S3_FREE(ctx->src_bucket);
            S3_FREE(ctx->src_key);
            S3_FREE(ctx->dst_bucket);
            S3_FREE(ctx->dst_key);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->opts, opts, sizeof(*opts));
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__copy_object_async_thread, ctx);
    if (rc != 0) {
        S3_FREE(ctx->opts);
        S3_FREE(ctx->src_bucket);
        S3_FREE(ctx->src_key);
        S3_FREE(ctx->dst_bucket);
        S3_FREE(ctx->dst_key);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}

/* --- list_objects_async --- */

typedef struct {
    s3_client              *client;
    char                   *bucket;
    s3_list_objects_opts   *opts;
    s3_future              *future;
} s3__list_objects_async_ctx;

static void *s3__list_objects_async_thread(void *arg) {
    s3__list_objects_async_ctx *ctx = (s3__list_objects_async_ctx *)arg;

    s3_list_objects_result *result = (s3_list_objects_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        status = S3_STATUS_OUT_OF_MEMORY;
        s3__future_complete(ctx->future, status, nullptr, 0);
    } else {
        status = s3_list_objects_v2(ctx->client, ctx->bucket, ctx->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(ctx->future, status, result,
                            result ? sizeof(*result) : 0);
    }

    S3_FREE(ctx->bucket);
    S3_FREE(ctx->opts);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_list_objects_async(s3_client *c, const char *bucket,
                                const s3_list_objects_opts *opts, s3_future **future) {
    if (!c || !bucket || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__list_objects_async_ctx *ctx = (s3__list_objects_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->bucket = s3__strdup(bucket);
    ctx->future = f;
    ctx->opts = nullptr;

    if (opts) {
        ctx->opts = (s3_list_objects_opts *)S3_MALLOC(sizeof(*opts));
        if (!ctx->opts) {
            S3_FREE(ctx->bucket);
            S3_FREE(ctx);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(ctx->opts, opts, sizeof(*opts));
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__list_objects_async_thread, ctx);
    if (rc != 0) {
        S3_FREE(ctx->opts);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}

/* --- delete_objects_async --- */

typedef struct {
    s3_client                *client;
    char                     *bucket;
    s3_delete_object_entry   *entries;
    int                       entry_count;
    bool                      quiet;
    s3_future                *future;
    /* Storage for deep-copied entry strings */
    char                    **key_copies;
    char                    **version_id_copies;
} s3__delete_objects_async_ctx;

static void *s3__delete_objects_async_thread(void *arg) {
    s3__delete_objects_async_ctx *ctx = (s3__delete_objects_async_ctx *)arg;

    s3_delete_objects_result *result = (s3_delete_objects_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        status = S3_STATUS_OUT_OF_MEMORY;
        s3__future_complete(ctx->future, status, nullptr, 0);
    } else {
        status = s3_delete_objects(ctx->client, ctx->bucket,
                                   ctx->entries, ctx->entry_count,
                                   ctx->quiet, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(ctx->future, status, result,
                            result ? sizeof(*result) : 0);
    }

    /* Clean up deep copies */
    for (int i = 0; i < ctx->entry_count; i++) {
        S3_FREE(ctx->key_copies[i]);
        if (ctx->version_id_copies[i]) S3_FREE(ctx->version_id_copies[i]);
    }
    S3_FREE(ctx->key_copies);
    S3_FREE(ctx->version_id_copies);
    S3_FREE(ctx->entries);
    S3_FREE(ctx->bucket);
    S3_FREE(ctx);
    return nullptr;
}

s3_status s3_delete_objects_async(s3_client *c, const char *bucket,
                                  const s3_delete_object_entry *entries, int entry_count,
                                  bool quiet, s3_future **future) {
    if (!c || !bucket || !entries || entry_count <= 0 || !future)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__delete_objects_async_ctx *ctx = (s3__delete_objects_async_ctx *)S3_CALLOC(1, sizeof(*ctx));
    if (!ctx) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    ctx->client = c;
    ctx->bucket = s3__strdup(bucket);
    ctx->entry_count = entry_count;
    ctx->quiet = quiet;
    ctx->future = f;

    /* Deep-copy entries and their strings */
    ctx->entries = (s3_delete_object_entry *)S3_CALLOC((size_t)entry_count, sizeof(s3_delete_object_entry));
    ctx->key_copies = (char **)S3_CALLOC((size_t)entry_count, sizeof(char *));
    ctx->version_id_copies = (char **)S3_CALLOC((size_t)entry_count, sizeof(char *));

    if (!ctx->entries || !ctx->key_copies || !ctx->version_id_copies) {
        S3_FREE(ctx->entries);
        S3_FREE(ctx->key_copies);
        S3_FREE(ctx->version_id_copies);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    for (int i = 0; i < entry_count; i++) {
        ctx->key_copies[i] = s3__strdup(entries[i].key);
        ctx->version_id_copies[i] = entries[i].version_id
                                        ? s3__strdup(entries[i].version_id) : nullptr;
        ctx->entries[i].key = ctx->key_copies[i];
        ctx->entries[i].version_id = ctx->version_id_copies[i];
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, s3__delete_objects_async_thread, ctx);
    if (rc != 0) {
        for (int i = 0; i < entry_count; i++) {
            S3_FREE(ctx->key_copies[i]);
            if (ctx->version_id_copies[i]) S3_FREE(ctx->version_id_copies[i]);
        }
        S3_FREE(ctx->key_copies);
        S3_FREE(ctx->version_id_copies);
        S3_FREE(ctx->entries);
        S3_FREE(ctx->bucket);
        S3_FREE(ctx);
        s3_future_destroy(f);
        return S3_STATUS_INTERNAL_ERROR;
    }
    pthread_detach(thread);

    *future = f;
    return S3_STATUS_OK;
}
