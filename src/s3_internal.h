/*
 * libs3 internal shared types and helpers
 * Not part of the public API.
 */

#ifndef S3_INTERNAL_H
#define S3_INTERNAL_H

#include "../s3.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdatomic.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Macros
 * ═══════════════════════════════════════════════════════════════════════════ */

#define S3_MIN(a, b) ((a) < (b) ? (a) : (b))
#define S3_MAX(a, b) ((a) > (b) ? (a) : (b))

#define S3_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define S3_UNUSED(x) ((void)(x))

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Growable Buffer
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_buf {
    char   *data;
    size_t  len;
    size_t  cap;
} s3_buf;

static inline void s3_buf_init(s3_buf *b) {
    b->data = nullptr;
    b->len = 0;
    b->cap = 0;
}

static inline void s3_buf_free(s3_buf *b) {
    S3_FREE(b->data);
    b->data = nullptr;
    b->len = 0;
    b->cap = 0;
}

static inline int s3_buf_ensure(s3_buf *b, size_t additional) {
    size_t needed = b->len + additional;
    if (needed <= b->cap) return 0;
    size_t new_cap = b->cap ? b->cap : 256;
    while (new_cap < needed) new_cap *= 2;
    char *p = (char *)S3_REALLOC(b->data, new_cap);
    if (!p) return -1;
    b->data = p;
    b->cap = new_cap;
    return 0;
}

static inline int s3_buf_append(s3_buf *b, const char *data, size_t len) {
    if (s3_buf_ensure(b, len + 1) < 0) return -1;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    b->data[b->len] = '\0';
    return 0;
}

static inline int s3_buf_append_str(s3_buf *b, const char *str) {
    return s3_buf_append(b, str, strlen(str));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Client Structure
 * ═══════════════════════════════════════════════════════════════════════════ */

struct s3_client {
    /* Config (deep-copied strings) */
    char           *access_key_id;
    char           *secret_access_key;
    char           *session_token;
    char           *region;
    char           *endpoint;
    char           *account_id;
    char           *user_agent;
    bool            use_path_style;
    bool            use_https;
    bool            use_transfer_acceleration;
    bool            use_dual_stack;
    bool            use_fips;
    long            connect_timeout_ms;
    long            request_timeout_ms;
    s3_retry_policy retry_policy;
    s3_log_fn       log_fn;
    void           *log_userdata;
    s3_log_level    log_level;
    s3_credential_provider_fn credential_provider;
    void           *credential_provider_userdata;

    /* curl handle (reused across requests) */
    CURL           *curl;
    char            curl_errbuf[CURL_ERROR_SIZE];

    /* Response buffer */
    s3_buf          response;

    /* Response headers captured during request */
    char            resp_etag[128];
    char            resp_version_id[128];
    char            resp_request_id[128];
    char            resp_host_id[256];
    char            resp_content_type[128];
    char            resp_last_modified[64];
    int64_t         resp_content_length;
    char            resp_storage_class[32];
    char            resp_server_side_encryption[32];
    char            resp_sse_kms_key_id[256];
    char            resp_sse_customer_algorithm[32];
    char            resp_sse_customer_key_md5[64];
    bool            resp_bucket_key_enabled;
    bool            resp_delete_marker;
    char            resp_expiration[256];
    char            resp_restore[256];
    char            resp_replication_status[32];
    int             resp_parts_count;
    char            resp_lock_mode[16];
    char            resp_lock_retain_until[64];
    char            resp_legal_hold[8];
    char            resp_checksum_crc32[16];
    char            resp_checksum_crc32c[16];
    char            resp_checksum_sha1[48];
    char            resp_checksum_sha256[72];
    char            resp_content_encoding[64];
    char            resp_content_language[64];
    char            resp_content_disposition[256];
    char            resp_cache_control[128];
    char            resp_expires_header[128];

    /* User metadata from response headers */
    s3_metadata    *resp_metadata;
    int             resp_metadata_count;
    int             resp_metadata_cap;

    /* Last error */
    s3_error        last_error;

    /* Signing key cache */
    uint8_t         signing_key[32];
    char            signing_key_date[9];     /* YYYYMMDD */
    char            signing_key_region[64];
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Event Loop Structure
 * ═══════════════════════════════════════════════════════════════════════════ */

struct s3_event_loop {
    CURLM              *multi;
    pthread_t           thread;
    pthread_mutex_t     lock;
    pthread_cond_t      cond;
    bool                running;
    s3_event_loop_mode  mode;
    int                 max_concurrent;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Future Structure
 * ═══════════════════════════════════════════════════════════════════════════ */

struct s3_future {
    _Atomic int         state;          /* s3_future_state */
    s3_status           status;
    void               *result;         /* Operation-specific result */
    size_t              result_size;
    s3_completion_fn    on_complete;
    void               *userdata;
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Thread Pool Structure
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_work_item {
    void (*fn)(s3_client *c, void *arg, s3_future *f);
    void               *arg;
    s3_future          *future;
    struct s3_work_item *next;
} s3_work_item;

typedef struct s3_work_queue {
    s3_work_item       *head;
    s3_work_item       *tail;
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;
    bool                shutdown;
} s3_work_queue;

struct s3_pool {
    s3_client         **workers;
    int                 num_workers;
    pthread_t          *threads;
    s3_work_queue       queue;
    bool                shutdown;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Crypto Function Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_sha256_ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} s3_sha256_ctx;

void s3__sha256_init(s3_sha256_ctx *ctx);
void s3__sha256_update(s3_sha256_ctx *ctx, const void *data, size_t len);
void s3__sha256_final(s3_sha256_ctx *ctx, uint8_t hash[32]);
void s3__sha256(const void *data, size_t len, uint8_t hash[32]);
void s3__sha256_hex(const void *data, size_t len, char hex[65]);

void s3__hmac_sha256(const void *key, size_t key_len,
                     const void *data, size_t data_len,
                     uint8_t out[32]);

typedef struct s3_sha1_ctx {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buf[64];
} s3_sha1_ctx;

void s3__sha1_init(s3_sha1_ctx *ctx);
void s3__sha1_update(s3_sha1_ctx *ctx, const void *data, size_t len);
void s3__sha1_final(s3_sha1_ctx *ctx, uint8_t hash[20]);
void s3__sha1(const void *data, size_t len, uint8_t hash[20]);

uint32_t s3__crc32(uint32_t crc, const void *data, size_t len);
uint32_t s3__crc32c(uint32_t crc, const void *data, size_t len);

size_t s3__base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size);
size_t s3__base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size);

size_t s3__uri_encode(const char *in, size_t in_len, char *out, size_t out_size, bool encode_slash);
size_t s3__uri_encode_path(const char *in, size_t in_len, char *out, size_t out_size);

void s3__hex_encode(const uint8_t *in, size_t in_len, char *out);
int  s3__hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — XML Function Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

bool s3__xml_find(const char *xml, size_t len,
                  const char *tag, const char **value, size_t *value_len);

bool s3__xml_find_in(const char *xml, size_t len,
                     const char *parent_tag,
                     const char *child_tag,
                     const char **value, size_t *value_len);

typedef int (*s3__xml_each_fn)(const char *element, size_t element_len, void *userdata);

int s3__xml_each(const char *xml, size_t len,
                 const char *tag,
                 s3__xml_each_fn fn, void *userdata);

void s3__xml_decode_entities(const char *in, size_t in_len, char *out, size_t out_size);

/* XML builder */
int s3__xml_buf_open(s3_buf *b, const char *tag);
int s3__xml_buf_close(s3_buf *b, const char *tag);
int s3__xml_buf_element(s3_buf *b, const char *tag, const char *text);
int s3__xml_buf_element_int(s3_buf *b, const char *tag, int64_t value);
int s3__xml_buf_element_bool(s3_buf *b, const char *tag, bool value);
int s3__xml_buf_declaration(s3_buf *b);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — SigV4 Function Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__derive_signing_key(const char *secret, const char *date_stamp,
                            const char *region, const char *service,
                            uint8_t key_out[32]);

int s3__sign_request(s3_client *c, const char *method,
                     const char *uri, const char *query,
                     struct curl_slist **headers,
                     const char *payload_hash);

int s3__presign_url(s3_client *c, const char *method,
                    const char *bucket, const char *key,
                    int expires, const char *content_type,
                    const char *extra_query,
                    char *url_buf, size_t url_buf_size);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — HTTP Function Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_request_params {
    const char         *method;         /* "GET", "PUT", "POST", "DELETE", "HEAD" */
    const char         *bucket;
    const char         *key;
    const char         *query_string;   /* e.g. "?versioning" or "tagging" (no leading ?) */
    struct curl_slist  *extra_headers;
    const void         *upload_data;
    size_t              upload_len;
    s3_read_fn          read_fn;
    void               *read_userdata;
    int64_t             content_length; /* -1 for chunked */
    s3_write_fn         write_fn;
    void               *write_userdata;
    s3_progress_fn      progress_fn;
    void               *progress_userdata;
    bool                collect_response;
    const char         *payload_hash;   /* nullptr = compute from upload_data */
    bool                use_control_endpoint;  /* For S3 Control API */
} s3_request_params;

s3_status s3__request(s3_client *c, const s3_request_params *params);

void s3__build_url(const s3_client *c, const char *bucket, const char *key,
                   const char *query, bool control_endpoint,
                   char *url, size_t url_size);

void s3__reset_response(s3_client *c);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Error Function Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3__parse_error_response(s3_client *c, long http_status);
s3_status s3__map_s3_error_code(const char *code);
s3_status s3__map_http_status(int http_status);
void s3__set_error(s3_client *c, s3_status status, int http_status,
                   const char *s3_code, const char *s3_message);
void s3__set_curl_error(s3_client *c, long curl_code);
void s3__clear_error(s3_client *c);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Logging
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__log(s3_client *c, s3_log_level level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define S3_LOG_TRACE_(c, ...) do { if ((c)->log_level <= S3_LOG_TRACE) s3__log(c, S3_LOG_TRACE, __VA_ARGS__); } while(0)
#define S3_LOG_DEBUG_(c, ...) do { if ((c)->log_level <= S3_LOG_DEBUG) s3__log(c, S3_LOG_DEBUG, __VA_ARGS__); } while(0)
#define S3_LOG_INFO_(c, ...)  do { if ((c)->log_level <= S3_LOG_INFO)  s3__log(c, S3_LOG_INFO,  __VA_ARGS__); } while(0)
#define S3_LOG_WARN_(c, ...)  do { if ((c)->log_level <= S3_LOG_WARN)  s3__log(c, S3_LOG_WARN,  __VA_ARGS__); } while(0)
#define S3_LOG_ERROR_(c, ...) do { if ((c)->log_level <= S3_LOG_ERROR) s3__log(c, S3_LOG_ERROR, __VA_ARGS__); } while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Retry
 * ═══════════════════════════════════════════════════════════════════════════ */

bool s3__should_retry(const s3_client *c, s3_status status, int attempt);
int  s3__retry_delay_ms(const s3_client *c, int attempt);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — SSE Header Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

struct curl_slist *s3__apply_sse_headers(struct curl_slist *headers,
                                         const s3_encryption *enc);
struct curl_slist *s3__apply_source_sse_headers(struct curl_slist *headers,
                                                const s3_encryption *enc);

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal — Utility
 * ═══════════════════════════════════════════════════════════════════════════ */

char *s3__strdup(const char *s);
char *s3__strndup(const char *s, size_t n);

const char *s3__storage_class_string(s3_storage_class sc);
s3_storage_class s3__storage_class_from_string(const char *s);

const char *s3__canned_acl_string(s3_canned_acl acl);

void s3__get_timestamp(char iso8601[17], char datestamp[9]);

#endif /* S3_INTERNAL_H */
