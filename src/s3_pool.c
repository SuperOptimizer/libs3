/*
 * libs3 — Thread pool for parallel S3 operations
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Forward declarations for future helpers defined in s3_async.c
 * ═══════════════════════════════════════════════════════════════════════════ */

extern s3_future *s3__future_create(void);
extern void s3__future_complete(s3_future *f, s3_status status,
                                void *result, size_t result_size);

/* ═══════════════════════════════════════════════════════════════════════════
 * Work Queue Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

static void s3__work_queue_init(s3_work_queue *q) {
    q->head = nullptr;
    q->tail = nullptr;
    q->shutdown = false;
    pthread_mutex_init(&q->mutex, nullptr);
    pthread_cond_init(&q->cond, nullptr);
}

static void s3__work_queue_destroy(s3_work_queue *q) {
    /* Free any remaining work items */
    s3_work_item *item = q->head;
    while (item) {
        s3_work_item *next = item->next;
        S3_FREE(item->arg);
        S3_FREE(item);
        item = next;
    }
    q->head = nullptr;
    q->tail = nullptr;
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

static void s3__work_queue_enqueue(s3_work_queue *q, s3_work_item *item) {
    pthread_mutex_lock(&q->mutex);
    item->next = nullptr;
    if (q->tail) {
        q->tail->next = item;
    } else {
        q->head = item;
    }
    q->tail = item;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

static s3_work_item *s3__work_queue_dequeue(s3_work_queue *q) {
    /* Caller must hold q->mutex */
    s3_work_item *item = q->head;
    if (item) {
        q->head = item->next;
        if (!q->head) {
            q->tail = nullptr;
        }
        item->next = nullptr;
    }
    return item;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Worker Thread
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    s3_pool   *pool;
    int        worker_index;
} s3__worker_ctx;

static void *s3__worker_thread(void *arg) {
    s3__worker_ctx *wctx = (s3__worker_ctx *)arg;
    s3_pool *pool = wctx->pool;
    int idx = wctx->worker_index;
    S3_FREE(wctx);

    s3_client *client = pool->workers[idx];
    s3_work_queue *q = &pool->queue;

    while (true) {
        pthread_mutex_lock(&q->mutex);

        while (!q->head && !q->shutdown) {
            pthread_cond_wait(&q->cond, &q->mutex);
        }

        if (q->shutdown && !q->head) {
            pthread_mutex_unlock(&q->mutex);
            break;
        }

        s3_work_item *item = s3__work_queue_dequeue(q);
        pthread_mutex_unlock(&q->mutex);

        if (item) {
            /* Execute the work function */
            item->fn(client, item->arg, item->future);
            S3_FREE(item->arg);
            S3_FREE(item);
        }
    }

    return nullptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Pool — Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_pool_create(s3_pool **out, const s3_config *config,
                         const s3_pool_opts *opts) {
    if (!out || !config) return S3_STATUS_INVALID_ARGUMENT;

    int num_workers = (opts && opts->num_workers > 0) ? opts->num_workers : 4;

    s3_pool *pool = (s3_pool *)S3_CALLOC(1, sizeof(s3_pool));
    if (!pool) return S3_STATUS_OUT_OF_MEMORY;

    pool->num_workers = num_workers;
    pool->shutdown = false;

    /* Allocate worker client array */
    pool->workers = (s3_client **)S3_CALLOC((size_t)num_workers, sizeof(s3_client *));
    if (!pool->workers) {
        S3_FREE(pool);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    /* Create worker clients, each with its own deep-copied config and CURL handle */
    for (int i = 0; i < num_workers; i++) {
        s3_status st = s3_client_create(&pool->workers[i], config);
        if (st != S3_STATUS_OK) {
            /* Clean up already-created clients */
            for (int j = 0; j < i; j++) {
                s3_client_destroy(pool->workers[j]);
            }
            S3_FREE(pool->workers);
            S3_FREE(pool);
            return st;
        }
    }

    /* Initialize work queue */
    s3__work_queue_init(&pool->queue);

    /* Allocate thread array */
    pool->threads = (pthread_t *)S3_CALLOC((size_t)num_workers, sizeof(pthread_t));
    if (!pool->threads) {
        for (int i = 0; i < num_workers; i++) {
            s3_client_destroy(pool->workers[i]);
        }
        s3__work_queue_destroy(&pool->queue);
        S3_FREE(pool->workers);
        S3_FREE(pool);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    /* Spawn worker threads */
    for (int i = 0; i < num_workers; i++) {
        s3__worker_ctx *wctx = (s3__worker_ctx *)S3_MALLOC(sizeof(s3__worker_ctx));
        if (!wctx) {
            /* Signal shutdown and join already-started threads */
            pthread_mutex_lock(&pool->queue.mutex);
            pool->queue.shutdown = true;
            pthread_cond_broadcast(&pool->queue.cond);
            pthread_mutex_unlock(&pool->queue.mutex);
            for (int j = 0; j < i; j++) {
                pthread_join(pool->threads[j], nullptr);
            }
            for (int j = 0; j < num_workers; j++) {
                s3_client_destroy(pool->workers[j]);
            }
            s3__work_queue_destroy(&pool->queue);
            S3_FREE(pool->threads);
            S3_FREE(pool->workers);
            S3_FREE(pool);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        wctx->pool = pool;
        wctx->worker_index = i;

        int rc = pthread_create(&pool->threads[i], nullptr, s3__worker_thread, wctx);
        if (rc != 0) {
            S3_FREE(wctx);
            pthread_mutex_lock(&pool->queue.mutex);
            pool->queue.shutdown = true;
            pthread_cond_broadcast(&pool->queue.cond);
            pthread_mutex_unlock(&pool->queue.mutex);
            for (int j = 0; j < i; j++) {
                pthread_join(pool->threads[j], nullptr);
            }
            for (int j = 0; j < num_workers; j++) {
                s3_client_destroy(pool->workers[j]);
            }
            s3__work_queue_destroy(&pool->queue);
            S3_FREE(pool->threads);
            S3_FREE(pool->workers);
            S3_FREE(pool);
            return S3_STATUS_INTERNAL_ERROR;
        }
    }

    *out = pool;
    return S3_STATUS_OK;
}

void s3_pool_destroy(s3_pool *pool) {
    if (!pool) return;

    /* Signal shutdown */
    pthread_mutex_lock(&pool->queue.mutex);
    pool->queue.shutdown = true;
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->queue.cond);
    pthread_mutex_unlock(&pool->queue.mutex);

    /* Join all worker threads */
    for (int i = 0; i < pool->num_workers; i++) {
        pthread_join(pool->threads[i], nullptr);
    }

    /* Destroy worker clients */
    for (int i = 0; i < pool->num_workers; i++) {
        s3_client_destroy(pool->workers[i]);
    }

    s3__work_queue_destroy(&pool->queue);
    S3_FREE(pool->threads);
    S3_FREE(pool->workers);
    S3_FREE(pool);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Pool Operation Wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* --- pool_put_object --- */

typedef struct {
    char                   *bucket;
    char                   *key;
    void                   *data;
    size_t                  data_len;
    s3_put_object_opts     *opts;
} s3__pool_put_object_arg;

static void s3__pool_put_object_fn(s3_client *c, void *arg, s3_future *f) {
    s3__pool_put_object_arg *a = (s3__pool_put_object_arg *)arg;

    s3_put_object_result *result = (s3_put_object_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        s3__future_complete(f, S3_STATUS_OUT_OF_MEMORY, nullptr, 0);
    } else {
        status = s3_put_object(c, a->bucket, a->key, a->data, a->data_len,
                               a->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(f, status, result, result ? sizeof(*result) : 0);
    }

    S3_FREE(a->bucket);
    S3_FREE(a->key);
    S3_FREE(a->data);
    S3_FREE(a->opts);
}

s3_status s3_pool_put_object(s3_pool *pool, const char *bucket, const char *key,
                             const void *data, size_t data_len,
                             const s3_put_object_opts *opts, s3_future **future) {
    if (!pool || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__pool_put_object_arg *arg = (s3__pool_put_object_arg *)S3_CALLOC(1, sizeof(*arg));
    if (!arg) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    arg->bucket = s3__strdup(bucket);
    arg->key = s3__strdup(key);
    arg->data_len = data_len;
    arg->data = nullptr;
    arg->opts = nullptr;

    if (data && data_len > 0) {
        arg->data = S3_MALLOC(data_len);
        if (!arg->data) {
            S3_FREE(arg->bucket);
            S3_FREE(arg->key);
            S3_FREE(arg);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(arg->data, data, data_len);
    }

    if (opts) {
        arg->opts = (s3_put_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!arg->opts) {
            S3_FREE(arg->data);
            S3_FREE(arg->bucket);
            S3_FREE(arg->key);
            S3_FREE(arg);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(arg->opts, opts, sizeof(*opts));
    }

    s3_work_item *item = (s3_work_item *)S3_CALLOC(1, sizeof(s3_work_item));
    if (!item) {
        S3_FREE(arg->opts);
        S3_FREE(arg->data);
        S3_FREE(arg->bucket);
        S3_FREE(arg->key);
        S3_FREE(arg);
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    item->fn = s3__pool_put_object_fn;
    item->arg = arg;
    item->future = f;
    item->next = nullptr;

    s3__work_queue_enqueue(&pool->queue, item);

    *future = f;
    return S3_STATUS_OK;
}

/* --- pool_get_object --- */

typedef struct {
    char                   *bucket;
    char                   *key;
    s3_get_object_opts     *opts;
} s3__pool_get_object_arg;

typedef struct {
    void   *data;
    size_t  data_len;
} s3__pool_get_object_result;

static void s3__pool_get_object_fn(s3_client *c, void *arg, s3_future *f) {
    s3__pool_get_object_arg *a = (s3__pool_get_object_arg *)arg;

    void *data = nullptr;
    size_t data_len = 0;

    s3_status status = s3_get_object(c, a->bucket, a->key, &data, &data_len, a->opts);

    if (status == S3_STATUS_OK) {
        s3__pool_get_object_result *result = (s3__pool_get_object_result *)
            S3_CALLOC(1, sizeof(*result));
        if (result) {
            result->data = data;
            result->data_len = data_len;
            s3__future_complete(f, status, result, sizeof(*result));
        } else {
            S3_FREE(data);
            s3__future_complete(f, S3_STATUS_OUT_OF_MEMORY, nullptr, 0);
        }
    } else {
        s3__future_complete(f, status, nullptr, 0);
    }

    S3_FREE(a->bucket);
    S3_FREE(a->key);
    S3_FREE(a->opts);
}

s3_status s3_pool_get_object(s3_pool *pool, const char *bucket, const char *key,
                             const s3_get_object_opts *opts, s3_future **future) {
    if (!pool || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__pool_get_object_arg *arg = (s3__pool_get_object_arg *)S3_CALLOC(1, sizeof(*arg));
    if (!arg) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    arg->bucket = s3__strdup(bucket);
    arg->key = s3__strdup(key);
    arg->opts = nullptr;

    if (opts) {
        arg->opts = (s3_get_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!arg->opts) {
            S3_FREE(arg->bucket);
            S3_FREE(arg->key);
            S3_FREE(arg);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(arg->opts, opts, sizeof(*opts));
    }

    s3_work_item *item = (s3_work_item *)S3_CALLOC(1, sizeof(s3_work_item));
    if (!item) {
        S3_FREE(arg->opts);
        S3_FREE(arg->bucket);
        S3_FREE(arg->key);
        S3_FREE(arg);
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    item->fn = s3__pool_get_object_fn;
    item->arg = arg;
    item->future = f;
    item->next = nullptr;

    s3__work_queue_enqueue(&pool->queue, item);

    *future = f;
    return S3_STATUS_OK;
}

/* --- pool_delete_object --- */

typedef struct {
    char                     *bucket;
    char                     *key;
    s3_delete_object_opts    *opts;
} s3__pool_delete_object_arg;

static void s3__pool_delete_object_fn(s3_client *c, void *arg, s3_future *f) {
    s3__pool_delete_object_arg *a = (s3__pool_delete_object_arg *)arg;

    s3_delete_object_result *result = (s3_delete_object_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        s3__future_complete(f, S3_STATUS_OUT_OF_MEMORY, nullptr, 0);
    } else {
        status = s3_delete_object(c, a->bucket, a->key, a->opts, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(f, status, result, result ? sizeof(*result) : 0);
    }

    S3_FREE(a->bucket);
    S3_FREE(a->key);
    S3_FREE(a->opts);
}

s3_status s3_pool_delete_object(s3_pool *pool, const char *bucket, const char *key,
                                const s3_delete_object_opts *opts, s3_future **future) {
    if (!pool || !bucket || !key || !future) return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__pool_delete_object_arg *arg = (s3__pool_delete_object_arg *)S3_CALLOC(1, sizeof(*arg));
    if (!arg) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    arg->bucket = s3__strdup(bucket);
    arg->key = s3__strdup(key);
    arg->opts = nullptr;

    if (opts) {
        arg->opts = (s3_delete_object_opts *)S3_MALLOC(sizeof(*opts));
        if (!arg->opts) {
            S3_FREE(arg->bucket);
            S3_FREE(arg->key);
            S3_FREE(arg);
            s3_future_destroy(f);
            return S3_STATUS_OUT_OF_MEMORY;
        }
        memcpy(arg->opts, opts, sizeof(*opts));
    }

    s3_work_item *item = (s3_work_item *)S3_CALLOC(1, sizeof(s3_work_item));
    if (!item) {
        S3_FREE(arg->opts);
        S3_FREE(arg->bucket);
        S3_FREE(arg->key);
        S3_FREE(arg);
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    item->fn = s3__pool_delete_object_fn;
    item->arg = arg;
    item->future = f;
    item->next = nullptr;

    s3__work_queue_enqueue(&pool->queue, item);

    *future = f;
    return S3_STATUS_OK;
}

/* --- pool_delete_objects --- */

typedef struct {
    char                     *bucket;
    s3_delete_object_entry   *entries;
    int                       entry_count;
    bool                      quiet;
    char                    **key_copies;
    char                    **version_id_copies;
} s3__pool_delete_objects_arg;

static void s3__pool_delete_objects_fn(s3_client *c, void *arg, s3_future *f) {
    s3__pool_delete_objects_arg *a = (s3__pool_delete_objects_arg *)arg;

    s3_delete_objects_result *result = (s3_delete_objects_result *)S3_CALLOC(1, sizeof(*result));
    s3_status status;

    if (!result) {
        s3__future_complete(f, S3_STATUS_OUT_OF_MEMORY, nullptr, 0);
    } else {
        status = s3_delete_objects(c, a->bucket, a->entries, a->entry_count,
                                   a->quiet, result);
        if (status != S3_STATUS_OK) {
            S3_FREE(result);
            result = nullptr;
        }
        s3__future_complete(f, status, result, result ? sizeof(*result) : 0);
    }

    /* Clean up deep copies */
    for (int i = 0; i < a->entry_count; i++) {
        S3_FREE(a->key_copies[i]);
        if (a->version_id_copies[i]) S3_FREE(a->version_id_copies[i]);
    }
    S3_FREE(a->key_copies);
    S3_FREE(a->version_id_copies);
    S3_FREE(a->entries);
    S3_FREE(a->bucket);
}

s3_status s3_pool_delete_objects(s3_pool *pool, const char *bucket,
                                const s3_delete_object_entry *entries, int entry_count,
                                bool quiet, s3_future **future) {
    if (!pool || !bucket || !entries || entry_count <= 0 || !future)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_future *f = s3__future_create();
    if (!f) return S3_STATUS_OUT_OF_MEMORY;

    s3__pool_delete_objects_arg *arg = (s3__pool_delete_objects_arg *)S3_CALLOC(1, sizeof(*arg));
    if (!arg) {
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    arg->bucket = s3__strdup(bucket);
    arg->entry_count = entry_count;
    arg->quiet = quiet;

    arg->entries = (s3_delete_object_entry *)S3_CALLOC((size_t)entry_count,
                                                        sizeof(s3_delete_object_entry));
    arg->key_copies = (char **)S3_CALLOC((size_t)entry_count, sizeof(char *));
    arg->version_id_copies = (char **)S3_CALLOC((size_t)entry_count, sizeof(char *));

    if (!arg->entries || !arg->key_copies || !arg->version_id_copies) {
        S3_FREE(arg->entries);
        S3_FREE(arg->key_copies);
        S3_FREE(arg->version_id_copies);
        S3_FREE(arg->bucket);
        S3_FREE(arg);
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    for (int i = 0; i < entry_count; i++) {
        arg->key_copies[i] = s3__strdup(entries[i].key);
        arg->version_id_copies[i] = entries[i].version_id
                                        ? s3__strdup(entries[i].version_id) : nullptr;
        arg->entries[i].key = arg->key_copies[i];
        arg->entries[i].version_id = arg->version_id_copies[i];
    }

    s3_work_item *item = (s3_work_item *)S3_CALLOC(1, sizeof(s3_work_item));
    if (!item) {
        for (int i = 0; i < entry_count; i++) {
            S3_FREE(arg->key_copies[i]);
            if (arg->version_id_copies[i]) S3_FREE(arg->version_id_copies[i]);
        }
        S3_FREE(arg->key_copies);
        S3_FREE(arg->version_id_copies);
        S3_FREE(arg->entries);
        S3_FREE(arg->bucket);
        S3_FREE(arg);
        s3_future_destroy(f);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    atomic_store(&f->state, S3_FUTURE_RUNNING);

    item->fn = s3__pool_delete_objects_fn;
    item->arg = arg;
    item->future = f;
    item->next = nullptr;

    s3__work_queue_enqueue(&pool->queue, item);

    *future = f;
    return S3_STATUS_OK;
}
