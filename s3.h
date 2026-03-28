/*
 * libs3 — Pure C23 Amazon S3 client library
 * Built on libcurl. No OpenSSL dependency.
 *
 * Usage:
 *   #include "s3.h"
 *   // Link with -lcurl -lpthread
 */

#ifndef S3_H
#define S3_H

/* ═══════════════════════════════════════════════════════════════════════════
 * C23 Detection & Compatibility
 * ═══════════════════════════════════════════════════════════════════════════ */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
  #define S3_C23 1
#else
  #define S3_C23 0
#endif

#if S3_C23
  #define S3_NODISCARD    [[nodiscard]]
  #define S3_MAYBE_UNUSED [[maybe_unused]]
  #define S3_DEPRECATED   [[deprecated]]
#elif defined(__GNUC__) || defined(__clang__)
  #define S3_NODISCARD    __attribute__((warn_unused_result))
  #define S3_MAYBE_UNUSED __attribute__((unused))
  #define S3_DEPRECATED   __attribute__((deprecated))
#elif defined(_MSC_VER)
  #define S3_NODISCARD    _Check_return_
  #define S3_MAYBE_UNUSED
  #define S3_DEPRECATED   __declspec(deprecated)
#else
  #define S3_NODISCARD
  #define S3_MAYBE_UNUSED
  #define S3_DEPRECATED
#endif

#if !S3_C23
  #include <stdbool.h>
  #ifndef nullptr
    #define nullptr NULL
  #endif
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Linkage
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef S3DEF
  #ifdef S3_STATIC
    #define S3DEF static
  #else
    #define S3DEF extern
  #endif
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Allocator Hooks
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef S3_MALLOC
  #define S3_MALLOC(sz)       malloc(sz)
  #define S3_REALLOC(p, sz)   realloc(p, sz)
  #define S3_FREE(p)          free(p)
  #define S3_CALLOC(n, sz)    calloc(n, sz)
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Includes
 * ═══════════════════════════════════════════════════════════════════════════ */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Forward Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_client       s3_client;
typedef struct s3_event_loop   s3_event_loop;
typedef struct s3_future       s3_future;
typedef struct s3_pool         s3_pool;

/* ═══════════════════════════════════════════════════════════════════════════
 * Status / Error Codes
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum s3_status {
    S3_STATUS_OK = 0,

    /* Client-side errors */
    S3_STATUS_INVALID_ARGUMENT,
    S3_STATUS_OUT_OF_MEMORY,
    S3_STATUS_INTERNAL_ERROR,
    S3_STATUS_NOT_INITIALIZED,
    S3_STATUS_ABORTED_BY_CALLBACK,

    /* Network / curl errors */
    S3_STATUS_CURL_ERROR,
    S3_STATUS_CONNECTION_FAILED,
    S3_STATUS_DNS_RESOLUTION_FAILED,
    S3_STATUS_TIMEOUT,
    S3_STATUS_SSL_ERROR,

    /* S3 service errors */
    S3_STATUS_ACCESS_DENIED,
    S3_STATUS_ACCOUNT_PROBLEM,
    S3_STATUS_ALL_ACCESS_DISABLED,
    S3_STATUS_BUCKET_ALREADY_EXISTS,
    S3_STATUS_BUCKET_ALREADY_OWNED_BY_YOU,
    S3_STATUS_BUCKET_NOT_EMPTY,
    S3_STATUS_CREDENTIALS_NOT_SUPPORTED,
    S3_STATUS_CROSS_LOCATION_LOGGING_PROHIBITED,
    S3_STATUS_ENTITY_TOO_SMALL,
    S3_STATUS_ENTITY_TOO_LARGE,
    S3_STATUS_EXPIRED_TOKEN,
    S3_STATUS_ILLEGAL_LOCATION_CONSTRAINT,
    S3_STATUS_ILLEGAL_VERSIONING_CONFIGURATION,
    S3_STATUS_INCOMPLETE_BODY,
    S3_STATUS_INCORRECT_NUMBER_OF_FILES_IN_POST,
    S3_STATUS_INLINE_DATA_TOO_LARGE,
    S3_STATUS_INVALID_ACCESS_KEY_ID,
    S3_STATUS_INVALID_ARGUMENT_S3,
    S3_STATUS_INVALID_BUCKET_NAME,
    S3_STATUS_INVALID_BUCKET_STATE,
    S3_STATUS_INVALID_DIGEST,
    S3_STATUS_INVALID_ENCRYPTION_ALGORITHM,
    S3_STATUS_INVALID_LOCATION_CONSTRAINT,
    S3_STATUS_INVALID_OBJECT_STATE,
    S3_STATUS_INVALID_PART,
    S3_STATUS_INVALID_PART_ORDER,
    S3_STATUS_INVALID_PAYER,
    S3_STATUS_INVALID_POLICY_DOCUMENT,
    S3_STATUS_INVALID_RANGE,
    S3_STATUS_INVALID_REQUEST,
    S3_STATUS_INVALID_SECURITY,
    S3_STATUS_INVALID_SOAP_REQUEST,
    S3_STATUS_INVALID_STORAGE_CLASS,
    S3_STATUS_INVALID_TARGET_BUCKET_FOR_LOGGING,
    S3_STATUS_INVALID_TOKEN,
    S3_STATUS_INVALID_URI,
    S3_STATUS_KEY_TOO_LONG,
    S3_STATUS_MALFORMED_ACL,
    S3_STATUS_MALFORMED_POST_REQUEST,
    S3_STATUS_MALFORMED_XML,
    S3_STATUS_MAX_MESSAGE_LENGTH_EXCEEDED,
    S3_STATUS_MAX_POST_PRE_DATA_LENGTH_EXCEEDED,
    S3_STATUS_METADATA_TOO_LARGE,
    S3_STATUS_METHOD_NOT_ALLOWED,
    S3_STATUS_MISSING_ATTACHMENT,
    S3_STATUS_MISSING_CONTENT_LENGTH,
    S3_STATUS_MISSING_REQUEST_BODY,
    S3_STATUS_MISSING_SECURITY_ELEMENT,
    S3_STATUS_MISSING_SECURITY_HEADER,
    S3_STATUS_NO_LOGGING_STATUS_FOR_KEY,
    S3_STATUS_NO_SUCH_BUCKET,
    S3_STATUS_NO_SUCH_BUCKET_POLICY,
    S3_STATUS_NO_SUCH_CORS_CONFIGURATION,
    S3_STATUS_NO_SUCH_KEY,
    S3_STATUS_NO_SUCH_LIFECYCLE_CONFIGURATION,
    S3_STATUS_NO_SUCH_UPLOAD,
    S3_STATUS_NO_SUCH_VERSION,
    S3_STATUS_NO_SUCH_WEBSITE_CONFIGURATION,
    S3_STATUS_NO_SUCH_TAG_SET,
    S3_STATUS_NO_SUCH_ACCESS_POINT,
    S3_STATUS_NOT_IMPLEMENTED_S3,
    S3_STATUS_NOT_SIGNED_UP,
    S3_STATUS_OPERATION_ABORTED,
    S3_STATUS_PERMANENT_REDIRECT,
    S3_STATUS_PRECONDITION_FAILED,
    S3_STATUS_REDIRECT,
    S3_STATUS_REQUEST_IS_NOT_MULTI_PART_CONTENT,
    S3_STATUS_REQUEST_TIMEOUT,
    S3_STATUS_REQUEST_TIME_TOO_SKEWED,
    S3_STATUS_REQUEST_TORRENT_OF_BUCKET,
    S3_STATUS_RESTORE_ALREADY_IN_PROGRESS,
    S3_STATUS_SERVER_SIDE_ENCRYPTION_CONFIG_NOT_FOUND,
    S3_STATUS_SERVICE_UNAVAILABLE,
    S3_STATUS_SIGNATURE_DOES_NOT_MATCH,
    S3_STATUS_SLOW_DOWN,
    S3_STATUS_TEMPORARY_REDIRECT,
    S3_STATUS_TOKEN_REFRESH_REQUIRED,
    S3_STATUS_TOO_MANY_BUCKETS,
    S3_STATUS_UNEXPECTED_CONTENT,
    S3_STATUS_UNRESOLVABLE_GRANT_BY_EMAIL,
    S3_STATUS_USER_KEY_MUST_BE_SPECIFIED,
    S3_STATUS_NOT_MODIFIED,
    S3_STATUS_INVALID_TAG,

    /* HTTP-only fallbacks */
    S3_STATUS_HTTP_BAD_REQUEST,
    S3_STATUS_HTTP_FORBIDDEN,
    S3_STATUS_HTTP_NOT_FOUND,
    S3_STATUS_HTTP_CONFLICT,
    S3_STATUS_HTTP_LENGTH_REQUIRED,
    S3_STATUS_HTTP_RANGE_NOT_SATISFIABLE,
    S3_STATUS_HTTP_INTERNAL_SERVER_ERROR,
    S3_STATUS_HTTP_NOT_IMPLEMENTED,
    S3_STATUS_HTTP_BAD_GATEWAY,
    S3_STATUS_HTTP_SERVICE_UNAVAILABLE,
    S3_STATUS_HTTP_GATEWAY_TIMEOUT,

    S3_STATUS_UNKNOWN_ERROR,
    S3_STATUS__COUNT
} s3_status;

/* ═══════════════════════════════════════════════════════════════════════════
 * Enumerations
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum s3_log_level {
    S3_LOG_TRACE = 0,
    S3_LOG_DEBUG,
    S3_LOG_INFO,
    S3_LOG_WARN,
    S3_LOG_ERROR,
    S3_LOG_NONE
} s3_log_level;

typedef enum s3_storage_class {
    S3_STORAGE_CLASS_STANDARD = 0,
    S3_STORAGE_CLASS_REDUCED_REDUNDANCY,
    S3_STORAGE_CLASS_STANDARD_IA,
    S3_STORAGE_CLASS_ONEZONE_IA,
    S3_STORAGE_CLASS_INTELLIGENT_TIERING,
    S3_STORAGE_CLASS_GLACIER,
    S3_STORAGE_CLASS_GLACIER_IR,
    S3_STORAGE_CLASS_DEEP_ARCHIVE,
    S3_STORAGE_CLASS_EXPRESS_ONEZONE,
} s3_storage_class;

typedef enum s3_sse_mode {
    S3_SSE_NONE = 0,
    S3_SSE_S3,      /* AES256 */
    S3_SSE_KMS,     /* aws:kms */
    S3_SSE_C,       /* Customer-provided key */
} s3_sse_mode;

typedef enum s3_checksum_algorithm {
    S3_CHECKSUM_NONE = 0,
    S3_CHECKSUM_CRC32,
    S3_CHECKSUM_CRC32C,
    S3_CHECKSUM_SHA1,
    S3_CHECKSUM_SHA256,
} s3_checksum_algorithm;

typedef enum s3_canned_acl {
    S3_ACL_PRIVATE = 0,
    S3_ACL_PUBLIC_READ,
    S3_ACL_PUBLIC_READ_WRITE,
    S3_ACL_AUTHENTICATED_READ,
    S3_ACL_AWS_EXEC_READ,
    S3_ACL_BUCKET_OWNER_READ,
    S3_ACL_BUCKET_OWNER_FULL_CONTROL,
    S3_ACL_LOG_DELIVERY_WRITE,
} s3_canned_acl;

typedef enum s3_metadata_directive {
    S3_METADATA_COPY = 0,
    S3_METADATA_REPLACE,
} s3_metadata_directive;

typedef enum s3_tagging_directive {
    S3_TAGGING_COPY = 0,
    S3_TAGGING_REPLACE,
} s3_tagging_directive;

typedef enum s3_object_lock_mode {
    S3_LOCK_NONE = 0,
    S3_LOCK_GOVERNANCE,
    S3_LOCK_COMPLIANCE,
} s3_object_lock_mode;

typedef enum s3_object_lock_legal_hold {
    S3_LEGAL_HOLD_OFF = 0,
    S3_LEGAL_HOLD_ON,
} s3_object_lock_legal_hold;

typedef enum s3_glacier_tier {
    S3_TIER_STANDARD = 0,
    S3_TIER_EXPEDITED,
    S3_TIER_BULK,
} s3_glacier_tier;

typedef enum s3_versioning_status {
    S3_VERSIONING_UNSET = 0,
    S3_VERSIONING_ENABLED,
    S3_VERSIONING_SUSPENDED,
} s3_versioning_status;

typedef enum s3_payer {
    S3_PAYER_BUCKET_OWNER = 0,
    S3_PAYER_REQUESTER,
} s3_payer;

typedef enum s3_object_ownership {
    S3_OWNERSHIP_BUCKET_OWNER_ENFORCED = 0,
    S3_OWNERSHIP_BUCKET_OWNER_PREFERRED,
    S3_OWNERSHIP_OBJECT_WRITER,
} s3_object_ownership;

typedef enum s3_event_loop_mode {
    S3_LOOP_AUTO = 0,   /* Library-managed background thread */
    S3_LOOP_MANUAL,     /* User calls s3_event_loop_poll() */
} s3_event_loop_mode;

typedef enum s3_future_state {
    S3_FUTURE_PENDING = 0,
    S3_FUTURE_RUNNING,
    S3_FUTURE_DONE,
    S3_FUTURE_FAILED,
} s3_future_state;

typedef enum s3_batch_job_operation {
    S3_JOB_OP_LAMBDA_INVOKE = 0,
    S3_JOB_OP_PUT_OBJECT_COPY,
    S3_JOB_OP_PUT_OBJECT_ACL,
    S3_JOB_OP_PUT_OBJECT_TAGGING,
    S3_JOB_OP_DELETE_OBJECT_TAGGING,
    S3_JOB_OP_INITIATE_RESTORE,
    S3_JOB_OP_PUT_OBJECT_LEGAL_HOLD,
    S3_JOB_OP_PUT_OBJECT_RETENTION,
    S3_JOB_OP_REPLICATE_OBJECT,
} s3_batch_job_operation;

typedef enum s3_batch_job_status {
    S3_JOB_STATUS_ACTIVE = 0,
    S3_JOB_STATUS_CANCELLED,
    S3_JOB_STATUS_CANCELLING,
    S3_JOB_STATUS_COMPLETE,
    S3_JOB_STATUS_COMPLETING,
    S3_JOB_STATUS_FAILED,
    S3_JOB_STATUS_FAILING,
    S3_JOB_STATUS_NEW,
    S3_JOB_STATUS_PAUSED,
    S3_JOB_STATUS_PAUSING,
    S3_JOB_STATUS_PREPARING,
    S3_JOB_STATUS_READY,
    S3_JOB_STATUS_SUSPENDED,
} s3_batch_job_status;

typedef enum s3_express_session_mode {
    S3_SESSION_READ_WRITE = 0,
    S3_SESSION_READ_ONLY,
} s3_express_session_mode;

typedef enum s3_vector_distance_metric {
    S3_VECTOR_EUCLIDEAN = 0,
    S3_VECTOR_COSINE,
    S3_VECTOR_DOT_PRODUCT,
} s3_vector_distance_metric;

/* ═══════════════════════════════════════════════════════════════════════════
 * Callback Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Read callback for streaming uploads. Return bytes written to buf, 0 for EOF, -1 to abort. */
typedef int64_t (*s3_read_fn)(void *buf, size_t buf_size, void *userdata);

/* Write callback for streaming downloads. Return 0 to continue, non-zero to abort. */
typedef int (*s3_write_fn)(const void *data, size_t len, void *userdata);

/* Progress callback. Return non-zero to abort. */
typedef int (*s3_progress_fn)(int64_t uploaded, int64_t total_upload,
                              int64_t downloaded, int64_t total_download,
                              void *userdata);

/* Logging callback. */
typedef void (*s3_log_fn)(s3_log_level level, const char *msg, void *userdata);

/* Future completion callback. */
typedef void (*s3_completion_fn)(s3_future *future, void *userdata);

/* Credential provider callback. Called before each request if set. */
typedef s3_status (*s3_credential_provider_fn)(
    const char **access_key_id_out,
    const char **secret_access_key_out,
    const char **session_token_out,
    void *userdata);

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_credentials {
    const char *access_key_id;
    const char *secret_access_key;
    const char *session_token;      /* Optional, for STS/assumed roles */
} s3_credentials;

typedef struct s3_retry_policy {
    int     max_retries;            /* default 3 */
    int     base_delay_ms;          /* default 100 */
    int     max_delay_ms;           /* default 20000 */
    double  backoff_multiplier;     /* default 2.0 */
    bool    jitter;                 /* default true */
    bool    retry_on_throttle;      /* default true */
    bool    retry_on_5xx;           /* default true */
    bool    retry_on_timeout;       /* default true */
} s3_retry_policy;

typedef struct s3_config {
    s3_credentials  credentials;
    const char     *region;                 /* e.g. "us-east-1" */
    const char     *endpoint;               /* nullptr for default AWS */
    const char     *account_id;             /* For S3 Control API operations */
    bool            use_path_style;         /* false = virtual-hosted (default) */
    bool            use_https;              /* default true */
    bool            use_transfer_acceleration;
    bool            use_dual_stack;
    bool            use_fips;
    long            connect_timeout_ms;     /* 0 = curl default */
    long            request_timeout_ms;     /* 0 = curl default */
    const char     *user_agent;             /* nullptr for "libs3/1.0" */
    s3_retry_policy retry_policy;
    s3_log_fn       log_fn;
    void           *log_userdata;
    s3_log_level    log_level;              /* default S3_LOG_NONE */
    s3_credential_provider_fn credential_provider;
    void           *credential_provider_userdata;
} s3_config;

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Encryption & Checksums
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_encryption {
    s3_sse_mode      mode;
    const char      *kms_key_id;        /* SSE-KMS: key ARN */
    const char      *kms_context;       /* SSE-KMS: base64-encoded JSON context */
    bool             bucket_key_enabled; /* SSE-KMS: use S3 Bucket Key */
    const uint8_t   *customer_key;      /* SSE-C: 32-byte AES-256 key */
    const uint8_t   *customer_key_md5;  /* SSE-C: 16-byte MD5 of key */
} s3_encryption;

typedef struct s3_checksum {
    s3_checksum_algorithm algorithm;
    const char           *value;        /* Precomputed value, or nullptr for auto */
} s3_checksum;

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Error Detail
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_error {
    s3_status   status;
    int         http_status;
    char        s3_code[64];
    char        s3_message[512];
    char        s3_request_id[128];
    char        s3_host_id[256];
    char        curl_error[256];
    long        curl_code;
} s3_error;

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Metadata Key-Value Pairs
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_metadata {
    const char *key;
    const char *value;
} s3_metadata;

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Tags
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_tag {
    char key[128];
    char value[256];
} s3_tag;

typedef struct s3_tag_set {
    s3_tag *tags;
    int     count;
} s3_tag_set;

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Request Options
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_put_object_opts {
    const char         *content_type;
    const char         *content_encoding;
    const char         *content_disposition;
    const char         *content_language;
    const char         *cache_control;
    const char         *expires;            /* HTTP Expires header value */
    s3_storage_class    storage_class;
    s3_canned_acl       acl;
    s3_encryption       encryption;
    s3_checksum         checksum;
    bool                compute_content_md5;
    const char         *tagging;            /* URL-encoded tag set */
    const s3_metadata  *metadata;           /* x-amz-meta-* */
    int                 metadata_count;
    s3_object_lock_mode      lock_mode;
    const char              *lock_retain_until;  /* ISO 8601 */
    s3_object_lock_legal_hold legal_hold;
    const char         *expected_bucket_owner;
    bool                request_payer;      /* x-amz-request-payer: requester */
    s3_progress_fn      progress_fn;
    void               *progress_userdata;
} s3_put_object_opts;

typedef struct s3_get_object_opts {
    const char         *range;              /* "bytes=0-99" */
    const char         *if_match;
    const char         *if_none_match;
    const char         *if_modified_since;
    const char         *if_unmodified_since;
    const char         *version_id;
    int                 part_number;        /* 0 = not set */
    s3_encryption       encryption;         /* SSE-C for encrypted objects */
    s3_checksum_algorithm checksum_mode;    /* ENABLED = any non-NONE value */
    const char         *expected_bucket_owner;
    bool                request_payer;
    s3_progress_fn      progress_fn;
    void               *progress_userdata;
} s3_get_object_opts;

typedef struct s3_delete_object_opts {
    const char *version_id;
    const char *mfa;                        /* For MFA Delete */
    const char *expected_bucket_owner;
    bool        request_payer;
} s3_delete_object_opts;

typedef struct s3_head_object_opts {
    const char *if_match;
    const char *if_none_match;
    const char *if_modified_since;
    const char *if_unmodified_since;
    const char *version_id;
    int         part_number;
    s3_encryption encryption;               /* SSE-C */
    const char *expected_bucket_owner;
    bool        request_payer;
    s3_checksum_algorithm checksum_mode;
} s3_head_object_opts;

typedef struct s3_copy_object_opts {
    const char             *version_id;     /* Source version */
    s3_metadata_directive   metadata_directive;
    s3_tagging_directive    tagging_directive;
    const char             *content_type;
    s3_storage_class        storage_class;
    s3_canned_acl           acl;
    s3_encryption           encryption;         /* Destination SSE */
    s3_encryption           source_encryption;  /* Source SSE-C */
    const char             *tagging;
    const s3_metadata      *metadata;
    int                     metadata_count;
    s3_object_lock_mode      lock_mode;
    const char              *lock_retain_until;
    s3_object_lock_legal_hold legal_hold;
    const char *if_match;
    const char *if_none_match;
    const char *if_modified_since;
    const char *if_unmodified_since;
    const char *expected_bucket_owner;
    const char *expected_source_bucket_owner;
    bool        request_payer;
} s3_copy_object_opts;

typedef struct s3_list_objects_opts {
    const char *prefix;
    const char *delimiter;
    const char *continuation_token;
    const char *start_after;
    int         max_keys;               /* 0 = default (1000) */
    bool        fetch_owner;
    const char *encoding_type;          /* "url" or nullptr */
    const char *expected_bucket_owner;
    bool        request_payer;
} s3_list_objects_opts;

typedef struct s3_list_object_versions_opts {
    const char *prefix;
    const char *delimiter;
    const char *key_marker;
    const char *version_id_marker;
    int         max_keys;
    const char *encoding_type;
    const char *expected_bucket_owner;
} s3_list_object_versions_opts;

typedef struct s3_create_multipart_upload_opts {
    const char         *content_type;
    const char         *content_encoding;
    const char         *content_disposition;
    const char         *content_language;
    const char         *cache_control;
    const char         *expires;
    s3_storage_class    storage_class;
    s3_canned_acl       acl;
    s3_encryption       encryption;
    s3_checksum_algorithm checksum_algorithm;
    const char         *tagging;
    const s3_metadata  *metadata;
    int                 metadata_count;
    s3_object_lock_mode      lock_mode;
    const char              *lock_retain_until;
    s3_object_lock_legal_hold legal_hold;
    const char         *expected_bucket_owner;
    bool                request_payer;
    bool                bucket_key_enabled;
} s3_create_multipart_upload_opts;

typedef struct s3_upload_part_opts {
    s3_encryption   encryption;         /* SSE-C must match create */
    s3_checksum     checksum;
    bool            compute_content_md5;
    const char     *expected_bucket_owner;
    bool            request_payer;
    s3_progress_fn  progress_fn;
    void           *progress_userdata;
} s3_upload_part_opts;

typedef struct s3_upload_part_copy_opts {
    const char      *copy_source_range;     /* "bytes=start-end" */
    const char      *if_match;
    const char      *if_none_match;
    const char      *if_modified_since;
    const char      *if_unmodified_since;
    s3_encryption    encryption;            /* Destination SSE-C */
    s3_encryption    source_encryption;     /* Source SSE-C */
    const char      *expected_bucket_owner;
    bool             request_payer;
} s3_upload_part_copy_opts;

typedef struct s3_restore_object_opts {
    int              days;
    s3_glacier_tier  tier;
    const char      *description;       /* For select restore */
    const char      *expected_bucket_owner;
    bool             request_payer;
} s3_restore_object_opts;

typedef struct s3_select_object_opts {
    const char *expression;             /* SQL expression */
    const char *input_format;           /* "CSV", "JSON", "Parquet" */
    const char *output_format;          /* "CSV", "JSON" */
    /* CSV input options */
    const char *csv_file_header_info;   /* "USE", "IGNORE", "NONE" */
    const char *csv_record_delimiter;
    const char *csv_field_delimiter;
    const char *csv_quote_character;
    const char *csv_quote_escape_character;
    const char *csv_comments;
    bool        csv_allow_quoted_record_delimiter;
    /* JSON input options */
    const char *json_type;              /* "DOCUMENT", "LINES" */
    /* CSV output options */
    const char *csv_out_record_delimiter;
    const char *csv_out_field_delimiter;
    const char *csv_out_quote_character;
    const char *csv_out_quote_escape_character;
    /* JSON output options */
    const char *json_out_record_delimiter;
    /* Scan range */
    int64_t     scan_start;
    int64_t     scan_end;
    const char *expected_bucket_owner;
    bool        request_payer;
} s3_select_object_opts;

typedef struct s3_get_object_attributes_opts {
    const char *version_id;
    const char *expected_bucket_owner;
    bool        request_payer;
    bool        attr_etag;
    bool        attr_checksum;
    bool        attr_object_parts;
    bool        attr_storage_class;
    bool        attr_object_size;
    int         max_parts;
    int         part_number_marker;
    s3_encryption encryption;           /* SSE-C */
} s3_get_object_attributes_opts;

typedef struct s3_upload_file_opts {
    size_t              part_size;           /* default 8MB, min 5MB */
    int                 max_concurrent_parts;/* default 4 */
    const char         *content_type;       /* nullptr = auto-detect */
    s3_storage_class    storage_class;
    s3_canned_acl       acl;
    s3_encryption       encryption;
    s3_checksum_algorithm checksum_algorithm;
    const char         *tagging;
    const s3_metadata  *metadata;
    int                 metadata_count;
    s3_progress_fn      progress_fn;
    void               *progress_userdata;
} s3_upload_file_opts;

typedef struct s3_download_file_opts {
    int                 max_concurrent_parts;/* For parallel range reads */
    s3_encryption       encryption;         /* SSE-C */
    const char         *version_id;
    s3_checksum_algorithm checksum_mode;
    s3_progress_fn      progress_fn;
    void               *progress_userdata;
} s3_download_file_opts;

typedef struct s3_sync_opts {
    const char         *prefix;
    const char        **include_patterns;   /* Glob patterns */
    int                 include_count;
    const char        **exclude_patterns;
    int                 exclude_count;
    bool                delete_removed;     /* Delete files not in source */
    bool                dry_run;
    size_t              part_size;
    int                 max_concurrent;
    s3_storage_class    storage_class;
    s3_encryption       encryption;
    s3_progress_fn      progress_fn;
    void               *progress_userdata;
} s3_sync_opts;

/* ═══════════════════════════════════════════════════════════════════════════
 * Compound Types — Results
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_put_object_result {
    char    etag[128];
    char    version_id[128];
    char    checksum_crc32[16];
    char    checksum_crc32c[16];
    char    checksum_sha1[48];
    char    checksum_sha256[72];
    char    request_id[128];
} s3_put_object_result;

typedef struct s3_head_object_result {
    int64_t     content_length;
    char        content_type[128];
    char        content_encoding[64];
    char        content_language[64];
    char        content_disposition[256];
    char        cache_control[128];
    char        etag[128];
    char        last_modified[64];
    char        storage_class[32];
    char        version_id[128];
    char        expiration[256];
    char        restore[256];
    char        replication_status[32];
    int         parts_count;
    char        server_side_encryption[32];
    char        sse_kms_key_id[256];
    char        sse_customer_algorithm[32];
    char        sse_customer_key_md5[64];
    bool        bucket_key_enabled;
    bool        delete_marker;
    s3_object_lock_mode       lock_mode;
    char        lock_retain_until[64];
    s3_object_lock_legal_hold legal_hold;
    char        checksum_crc32[16];
    char        checksum_crc32c[16];
    char        checksum_sha1[48];
    char        checksum_sha256[72];
    /* User metadata (library-allocated) */
    s3_metadata *metadata;
    int          metadata_count;
} s3_head_object_result;

typedef struct s3_delete_object_result {
    bool    delete_marker;
    char    version_id[128];
    char    request_id[128];
} s3_delete_object_result;

typedef struct s3_copy_object_result {
    char    etag[128];
    char    last_modified[64];
    char    version_id[128];
    char    request_id[128];
} s3_copy_object_result;

typedef struct s3_object_info {
    char        key[1024];
    char        etag[128];
    char        last_modified[64];
    char        storage_class[32];
    int64_t     size;
    char        owner_id[128];
    char        owner_display_name[128];
    char        checksum_algorithm[16];
} s3_object_info;

typedef struct s3_list_objects_result {
    s3_object_info *objects;
    int             object_count;
    char          **common_prefixes;
    int             prefix_count;
    bool            is_truncated;
    char            name[64];
    char            prefix[1024];
    char            delimiter[16];
    int             max_keys;
    int             key_count;
    char            next_continuation_token[1024];
    char            encoding_type[16];
    char            start_after[1024];
} s3_list_objects_result;

typedef struct s3_version_info {
    char        key[1024];
    char        version_id[128];
    bool        is_latest;
    char        last_modified[64];
    char        etag[128];
    int64_t     size;
    char        storage_class[32];
    char        owner_id[128];
    char        owner_display_name[128];
    bool        is_delete_marker;
} s3_version_info;

typedef struct s3_list_object_versions_result {
    s3_version_info *versions;
    int              version_count;
    char           **common_prefixes;
    int              prefix_count;
    bool             is_truncated;
    char             next_key_marker[1024];
    char             next_version_id_marker[128];
} s3_list_object_versions_result;

typedef struct s3_bucket_info {
    char    name[64];
    char    creation_date[64];
} s3_bucket_info;

typedef struct s3_list_buckets_result {
    s3_bucket_info *buckets;
    int             bucket_count;
    char            owner_id[128];
    char            owner_display_name[128];
    char            continuation_token[1024];
    bool            is_truncated;
} s3_list_buckets_result;

typedef struct s3_multipart_upload {
    char    upload_id[256];
    char    key[1024];
    char    bucket[64];
} s3_multipart_upload;

typedef struct s3_upload_part_result {
    char    etag[128];
    int     part_number;
    char    checksum_crc32[16];
    char    checksum_crc32c[16];
    char    checksum_sha1[48];
    char    checksum_sha256[72];
} s3_upload_part_result;

typedef struct s3_complete_multipart_result {
    char    location[1024];
    char    bucket[64];
    char    key[1024];
    char    etag[128];
    char    version_id[128];
    char    checksum_crc32[16];
    char    checksum_crc32c[16];
    char    checksum_sha1[48];
    char    checksum_sha256[72];
} s3_complete_multipart_result;

typedef struct s3_part_info {
    int     part_number;
    char    last_modified[64];
    char    etag[128];
    int64_t size;
    char    checksum_crc32[16];
    char    checksum_crc32c[16];
    char    checksum_sha1[48];
    char    checksum_sha256[72];
} s3_part_info;

typedef struct s3_list_parts_result {
    s3_part_info   *parts;
    int             part_count;
    bool            is_truncated;
    int             next_part_number_marker;
    int             max_parts;
    char            upload_id[256];
    char            key[1024];
    char            storage_class[32];
    char            initiator_id[128];
    char            initiator_display_name[128];
    char            owner_id[128];
    char            owner_display_name[128];
} s3_list_parts_result;

typedef struct s3_multipart_upload_info {
    char    key[1024];
    char    upload_id[256];
    char    initiated[64];
    char    storage_class[32];
    char    initiator_id[128];
    char    initiator_display_name[128];
    char    owner_id[128];
    char    owner_display_name[128];
} s3_multipart_upload_info;

typedef struct s3_list_multipart_uploads_result {
    s3_multipart_upload_info *uploads;
    int                       upload_count;
    char                    **common_prefixes;
    int                       prefix_count;
    bool                      is_truncated;
    char                      next_key_marker[1024];
    char                      next_upload_id_marker[256];
    int                       max_uploads;
} s3_list_multipart_uploads_result;

typedef struct s3_delete_object_entry {
    const char *key;
    const char *version_id;     /* nullable */
} s3_delete_object_entry;

typedef struct s3_deleted_object {
    char    key[1024];
    char    version_id[128];
    bool    delete_marker;
    char    delete_marker_version_id[128];
} s3_deleted_object;

typedef struct s3_delete_error {
    char    key[1024];
    char    version_id[128];
    char    code[64];
    char    message[256];
} s3_delete_error;

typedef struct s3_delete_objects_result {
    s3_deleted_object *deleted;
    int                deleted_count;
    s3_delete_error   *errors;
    int                error_count;
} s3_delete_objects_result;

typedef struct s3_object_attributes_result {
    char        etag[128];
    int64_t     object_size;
    char        storage_class[32];
    char        checksum_crc32[16];
    char        checksum_crc32c[16];
    char        checksum_sha1[48];
    char        checksum_sha256[72];
    int         total_parts_count;
    int         part_number_marker;
    int         next_part_number_marker;
    int         max_parts;
    bool        is_truncated;
    s3_part_info *parts;
    int          part_count;
} s3_object_attributes_result;

/* ACL types */
typedef struct s3_grantee {
    char    type[32];           /* "CanonicalUser", "Group", "AmazonCustomerByEmail" */
    char    id[128];
    char    display_name[128];
    char    email[128];
    char    uri[256];
} s3_grantee;

typedef struct s3_grant {
    s3_grantee grantee;
    char       permission[32];  /* "FULL_CONTROL", "WRITE", "READ", "READ_ACP", "WRITE_ACP" */
} s3_grant;

typedef struct s3_acl {
    char       owner_id[128];
    char       owner_display_name[128];
    s3_grant  *grants;
    int        grant_count;
} s3_acl;

/* Express One Zone session */
typedef struct s3_session_credentials {
    char    access_key_id[128];
    char    secret_access_key[256];
    char    session_token[2048];
    char    expiration[64];
} s3_session_credentials;

/* Presigned URL result */
typedef struct s3_presigned_url {
    char   *url;                /* Library-allocated, caller frees with s3_free() */
    size_t  url_len;
} s3_presigned_url;

/* Sync result */
typedef struct s3_sync_result {
    int     uploaded;
    int     downloaded;
    int     deleted;
    int     skipped;
    int     failed;
    int64_t bytes_transferred;
} s3_sync_result;

/* Batch job */
typedef struct s3_job {
    char                job_id[128];
    s3_batch_job_status status;
    char                description[256];
    int                 priority;
    char                creation_time[64];
    char                termination_date[64];
    int64_t             total_objects;
    int64_t             succeeded;
    int64_t             failed;
} s3_job;

typedef struct s3_list_jobs_result {
    s3_job *jobs;
    int     job_count;
    char    next_token[1024];
} s3_list_jobs_result;

/* Access Point */
typedef struct s3_access_point {
    char    name[64];
    char    bucket[64];
    char    network_origin[32];
    char    access_point_arn[256];
    char    alias[64];
    char    creation_date[64];
} s3_access_point;

typedef struct s3_list_access_points_result {
    s3_access_point *access_points;
    int              count;
    char             next_token[1024];
} s3_list_access_points_result;

/* Storage Lens */
typedef struct s3_storage_lens_config_entry {
    char    id[64];
    char    arn[256];
    char    home_region[32];
    bool    is_enabled;
} s3_storage_lens_config_entry;

typedef struct s3_list_storage_lens_result {
    s3_storage_lens_config_entry *configs;
    int                           count;
    char                          next_token[1024];
} s3_list_storage_lens_result;

/* Multi-Region Access Point */
typedef struct s3_mrap {
    char    name[64];
    char    alias[64];
    char    arn[256];
    char    status[32];
    char    created_at[64];
} s3_mrap;

typedef struct s3_list_mrap_result {
    s3_mrap *mraps;
    int      count;
    char     next_token[1024];
} s3_list_mrap_result;

/* S3 Tables */
typedef struct s3_table_bucket {
    char    arn[256];
    char    name[64];
    char    owner_account_id[32];
    char    created_at[64];
} s3_table_bucket;

typedef struct s3_table {
    char    name[256];
    char    namespace_name[256];       /* renamed from namespace to avoid C++ keyword */
    char    arn[256];
    char    type[32];
    char    created_at[64];
    char    modified_at[64];
    char    metadata_location[1024];
    char    warehouse_location[1024];
} s3_table;

typedef struct s3_namespace {
    char    name[256];
    char    arn[256];
    char    created_at[64];
} s3_namespace;

/* S3 Vectors */
typedef struct s3_vector_bucket {
    char    name[64];
    char    arn[256];
    char    created_at[64];
    char    encryption_type[32];
} s3_vector_bucket;

typedef struct s3_vector_index {
    char                     name[256];
    char                     arn[256];
    int                      dimension;
    s3_vector_distance_metric distance_metric;
    char                     created_at[64];
} s3_vector_index;

typedef struct s3_vector {
    char      *key;
    float     *data;
    int        dimension;
    s3_metadata *metadata;
    int         metadata_count;
} s3_vector;

typedef struct s3_vector_query_result {
    s3_vector *vectors;
    float     *distances;
    int        count;
} s3_vector_query_result;

/* Event loop options */
typedef struct s3_event_loop_opts {
    s3_event_loop_mode mode;
    int                max_concurrent;  /* default 64 */
} s3_event_loop_opts;

/* Thread pool options */
typedef struct s3_pool_opts {
    int num_workers;                    /* default 4 */
} s3_pool_opts;

/* ═══════════════════════════════════════════════════════════════════════════
 * Bucket Configuration Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/* CORS */
typedef struct s3_cors_rule {
    char  **allowed_origins;    int allowed_origin_count;
    char  **allowed_methods;    int allowed_method_count;
    char  **allowed_headers;    int allowed_header_count;
    char  **expose_headers;     int expose_header_count;
    int     max_age_seconds;
    char    id[128];
} s3_cors_rule;

typedef struct s3_cors_configuration {
    s3_cors_rule *rules;
    int           rule_count;
} s3_cors_configuration;

/* Lifecycle */
typedef struct s3_lifecycle_transition {
    int          days;
    char         date[64];
    char         storage_class[32];
} s3_lifecycle_transition;

typedef struct s3_lifecycle_expiration {
    int          days;
    char         date[64];
    bool         expired_object_delete_marker;
} s3_lifecycle_expiration;

typedef struct s3_lifecycle_noncurrent_transition {
    int          noncurrent_days;
    int          newer_noncurrent_versions;
    char         storage_class[32];
} s3_lifecycle_noncurrent_transition;

typedef struct s3_lifecycle_noncurrent_expiration {
    int          noncurrent_days;
    int          newer_noncurrent_versions;
} s3_lifecycle_noncurrent_expiration;

typedef struct s3_lifecycle_abort_incomplete_mpu {
    int          days_after_initiation;
} s3_lifecycle_abort_incomplete_mpu;

typedef struct s3_lifecycle_filter {
    char         prefix[1024];
    s3_tag      *tags;
    int          tag_count;
    int64_t      object_size_greater_than;
    int64_t      object_size_less_than;
    bool         has_and;       /* true if filter uses <And> */
} s3_lifecycle_filter;

typedef struct s3_lifecycle_rule {
    char                                id[128];
    char                                prefix[1024]; /* Deprecated, use filter */
    s3_lifecycle_filter                 filter;
    bool                                enabled;
    s3_lifecycle_expiration             expiration;
    s3_lifecycle_transition            *transitions;
    int                                 transition_count;
    s3_lifecycle_noncurrent_transition *noncurrent_transitions;
    int                                 noncurrent_transition_count;
    s3_lifecycle_noncurrent_expiration  noncurrent_expiration;
    s3_lifecycle_abort_incomplete_mpu   abort_incomplete_mpu;
} s3_lifecycle_rule;

typedef struct s3_lifecycle_configuration {
    s3_lifecycle_rule *rules;
    int                rule_count;
} s3_lifecycle_configuration;

/* Encryption configuration */
typedef struct s3_bucket_encryption {
    s3_sse_mode  default_sse;
    char         kms_key_id[256];
    bool         bucket_key_enabled;
} s3_bucket_encryption;

/* Logging */
typedef struct s3_bucket_logging {
    bool    enabled;
    char    target_bucket[64];
    char    target_prefix[256];
} s3_bucket_logging;

/* Website */
typedef struct s3_website_redirect_rule {
    char    condition_key_prefix[256];
    int     condition_http_error_code;
    char    redirect_hostname[256];
    char    redirect_protocol[16];
    char    redirect_replace_key_prefix[256];
    char    redirect_replace_key[1024];
    int     redirect_http_code;
} s3_website_redirect_rule;

typedef struct s3_website_configuration {
    char                        index_document[256];
    char                        error_document[256];
    char                        redirect_hostname[256];
    char                        redirect_protocol[16];
    s3_website_redirect_rule   *routing_rules;
    int                         routing_rule_count;
} s3_website_configuration;

/* Notification */
typedef struct s3_filter_rule {
    char    name[16];       /* "prefix" or "suffix" */
    char    value[256];
} s3_filter_rule;

typedef struct s3_notification_config {
    char            id[128];
    char            arn[256];
    char          **events;
    int             event_count;
    s3_filter_rule *filter_rules;
    int             filter_rule_count;
} s3_notification_config;

typedef struct s3_notification_configuration {
    s3_notification_config *topic_configs;       int topic_count;
    s3_notification_config *queue_configs;       int queue_count;
    s3_notification_config *lambda_configs;      int lambda_count;
} s3_notification_configuration;

/* Replication */
typedef struct s3_replication_destination {
    char    bucket[256];
    char    account[32];
    char    storage_class[32];
    bool    replicate_kms;
    char    kms_key_id[256];
} s3_replication_destination;

typedef struct s3_replication_rule {
    char                        id[128];
    int                         priority;
    char                        prefix[1024];
    bool                        enabled;
    s3_replication_destination  destination;
    bool                        delete_marker_replication;
    bool                        existing_object_replication;
} s3_replication_rule;

typedef struct s3_replication_configuration {
    char                  role[256];
    s3_replication_rule  *rules;
    int                   rule_count;
} s3_replication_configuration;

/* Public Access Block */
typedef struct s3_public_access_block {
    bool block_public_acls;
    bool ignore_public_acls;
    bool block_public_policy;
    bool restrict_public_buckets;
} s3_public_access_block;

/* Intelligent-Tiering */
typedef struct s3_tiering {
    char    access_tier[32];    /* "ARCHIVE_ACCESS" or "DEEP_ARCHIVE_ACCESS" */
    int     days;
} s3_tiering;

typedef struct s3_intelligent_tiering_config {
    char        id[128];
    bool        enabled;
    char        prefix[1024];
    s3_tag     *tags;
    int         tag_count;
    s3_tiering *tierings;
    int         tiering_count;
} s3_intelligent_tiering_config;

/* Inventory */
typedef struct s3_inventory_config {
    char    id[128];
    bool    enabled;
    char    destination_bucket[256];
    char    destination_prefix[256];
    char    destination_format[16];  /* "CSV", "ORC", "Parquet" */
    char    destination_account[32];
    char    schedule[16];           /* "Daily", "Weekly" */
    char    included_versions[16];  /* "All", "Current" */
    char  **optional_fields;
    int     field_count;
    char    prefix[1024];
} s3_inventory_config;

typedef struct s3_list_inventory_result {
    s3_inventory_config *configs;
    int                  count;
    char                 continuation_token[1024];
    bool                 is_truncated;
} s3_list_inventory_result;

/* Analytics */
typedef struct s3_analytics_config {
    char    id[128];
    char    prefix[1024];
    s3_tag *tags;
    int     tag_count;
    char    export_bucket[256];
    char    export_prefix[256];
    char    export_format[16];
} s3_analytics_config;

typedef struct s3_list_analytics_result {
    s3_analytics_config *configs;
    int                  count;
    char                 continuation_token[1024];
    bool                 is_truncated;
} s3_list_analytics_result;

/* Metrics */
typedef struct s3_metrics_config {
    char    id[128];
    char    prefix[1024];
    s3_tag *tags;
    int     tag_count;
} s3_metrics_config;

typedef struct s3_list_metrics_result {
    s3_metrics_config *configs;
    int                count;
    char               continuation_token[1024];
    bool               is_truncated;
} s3_list_metrics_result;

/* Object Lock Configuration */
typedef struct s3_object_lock_config {
    bool                 enabled;
    s3_object_lock_mode  default_mode;
    int                  default_days;
    int                  default_years;
} s3_object_lock_config;

/* ═══════════════════════════════════════════════════════════════════════════
 * Access Grants Types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_access_grants_instance {
    char    instance_arn[256];
    char    instance_id[128];
    char    identity_center_arn[256];
    char    created_at[64];
} s3_access_grants_instance;

typedef struct s3_access_grants_location {
    char    location_id[128];
    char    location_scope[1024];
    char    iam_role_arn[256];
    char    created_at[64];
} s3_access_grants_location;

typedef struct s3_access_grant {
    char    grant_id[128];
    char    grant_arn[256];
    char    grantee_type[32];
    char    grantee_id[256];
    char    permission[32];
    char    location_id[128];
    char    location_scope[1024];
    char    created_at[64];
} s3_access_grant;

/* ═══════════════════════════════════════════════════════════════════════════
 * S3 Outposts Types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct s3_outpost_endpoint {
    char    endpoint_arn[256];
    char    outpost_id[64];
    char    cidr_block[32];
    char    status[32];
    char    network_interfaces[512];
    char    creation_time[64];
    char    access_type[32];
    char    subnet_id[64];
    char    security_group_id[64];
} s3_outpost_endpoint;

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Client Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_client_create(s3_client **out, const s3_config *config);
S3DEF void s3_client_destroy(s3_client *client);
S3DEF const s3_error *s3_client_last_error(const s3_client *client);
S3DEF const char *s3_status_string(s3_status status);
S3DEF void s3_free(void *ptr);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Object Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_put_object(
    s3_client *c, const char *bucket, const char *key,
    const void *data, size_t data_len,
    const s3_put_object_opts *opts,
    s3_put_object_result *result);

S3_NODISCARD S3DEF s3_status s3_put_object_stream(
    s3_client *c, const char *bucket, const char *key,
    s3_read_fn read_fn, void *userdata, int64_t content_length,
    const s3_put_object_opts *opts,
    s3_put_object_result *result);

S3_NODISCARD S3DEF s3_status s3_get_object(
    s3_client *c, const char *bucket, const char *key,
    void **data_out, size_t *data_len_out,
    const s3_get_object_opts *opts);

S3_NODISCARD S3DEF s3_status s3_get_object_stream(
    s3_client *c, const char *bucket, const char *key,
    s3_write_fn write_fn, void *userdata,
    const s3_get_object_opts *opts);

S3_NODISCARD S3DEF s3_status s3_head_object(
    s3_client *c, const char *bucket, const char *key,
    const s3_head_object_opts *opts,
    s3_head_object_result *result);

S3_NODISCARD S3DEF s3_status s3_delete_object(
    s3_client *c, const char *bucket, const char *key,
    const s3_delete_object_opts *opts,
    s3_delete_object_result *result);

S3_NODISCARD S3DEF s3_status s3_delete_objects(
    s3_client *c, const char *bucket,
    const s3_delete_object_entry *entries, int entry_count,
    bool quiet,
    s3_delete_objects_result *result);

S3_NODISCARD S3DEF s3_status s3_copy_object(
    s3_client *c,
    const char *src_bucket, const char *src_key,
    const char *dst_bucket, const char *dst_key,
    const s3_copy_object_opts *opts,
    s3_copy_object_result *result);

S3_NODISCARD S3DEF s3_status s3_rename_object(
    s3_client *c, const char *bucket,
    const char *src_key, const char *dst_key);

S3_NODISCARD S3DEF s3_status s3_get_object_attributes(
    s3_client *c, const char *bucket, const char *key,
    const s3_get_object_attributes_opts *opts,
    s3_object_attributes_result *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Object Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_get_object_tagging(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, s3_tag_set *result);

S3_NODISCARD S3DEF s3_status s3_put_object_tagging(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, const s3_tag *tags, int tag_count);

S3_NODISCARD S3DEF s3_status s3_delete_object_tagging(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id);

S3_NODISCARD S3DEF s3_status s3_get_object_acl(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, s3_acl *result);

S3_NODISCARD S3DEF s3_status s3_put_object_acl(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, const s3_acl *acl);

S3_NODISCARD S3DEF s3_status s3_put_object_acl_canned(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, s3_canned_acl acl);

S3_NODISCARD S3DEF s3_status s3_get_object_legal_hold(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, s3_object_lock_legal_hold *result);

S3_NODISCARD S3DEF s3_status s3_put_object_legal_hold(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, s3_object_lock_legal_hold hold);

typedef struct s3_object_retention {
    s3_object_lock_mode mode;
    char                retain_until[64];
} s3_object_retention;

S3_NODISCARD S3DEF s3_status s3_get_object_retention(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, s3_object_retention *result);

S3_NODISCARD S3DEF s3_status s3_put_object_retention(
    s3_client *c, const char *bucket, const char *key,
    const char *version_id, const s3_object_retention *retention,
    bool bypass_governance);

S3_NODISCARD S3DEF s3_status s3_restore_object(
    s3_client *c, const char *bucket, const char *key,
    const s3_restore_object_opts *opts);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — List Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_list_objects_v2(
    s3_client *c, const char *bucket,
    const s3_list_objects_opts *opts,
    s3_list_objects_result *result);

S3_NODISCARD S3DEF s3_status s3_list_objects_v1(
    s3_client *c, const char *bucket,
    const char *prefix, const char *delimiter,
    const char *marker, int max_keys,
    s3_list_objects_result *result);

S3_NODISCARD S3DEF s3_status s3_list_object_versions(
    s3_client *c, const char *bucket,
    const s3_list_object_versions_opts *opts,
    s3_list_object_versions_result *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Multipart Upload
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_multipart_upload(
    s3_client *c, const char *bucket, const char *key,
    const s3_create_multipart_upload_opts *opts,
    s3_multipart_upload *result);

S3_NODISCARD S3DEF s3_status s3_upload_part(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int part_number,
    const void *data, size_t data_len,
    const s3_upload_part_opts *opts,
    s3_upload_part_result *result);

S3_NODISCARD S3DEF s3_status s3_upload_part_stream(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int part_number,
    s3_read_fn read_fn, void *userdata, int64_t content_length,
    const s3_upload_part_opts *opts,
    s3_upload_part_result *result);

S3_NODISCARD S3DEF s3_status s3_upload_part_copy(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int part_number,
    const char *src_bucket, const char *src_key,
    const s3_upload_part_copy_opts *opts,
    s3_upload_part_result *result);

S3_NODISCARD S3DEF s3_status s3_complete_multipart_upload(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id,
    const s3_upload_part_result *parts, int part_count,
    s3_complete_multipart_result *result);

S3_NODISCARD S3DEF s3_status s3_abort_multipart_upload(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id);

S3_NODISCARD S3DEF s3_status s3_list_parts(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int max_parts, int part_number_marker,
    s3_list_parts_result *result);

S3_NODISCARD S3DEF s3_status s3_list_multipart_uploads(
    s3_client *c, const char *bucket,
    const char *prefix, const char *delimiter,
    const char *key_marker, const char *upload_id_marker,
    int max_uploads,
    s3_list_multipart_uploads_result *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Bucket Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_bucket(
    s3_client *c, const char *bucket,
    s3_canned_acl acl, bool object_lock_enabled);

S3_NODISCARD S3DEF s3_status s3_delete_bucket(s3_client *c, const char *bucket);

S3_NODISCARD S3DEF s3_status s3_head_bucket(
    s3_client *c, const char *bucket,
    const char *expected_bucket_owner);

S3_NODISCARD S3DEF s3_status s3_list_buckets(
    s3_client *c, const char *prefix, const char *continuation_token,
    int max_buckets, s3_list_buckets_result *result);

S3_NODISCARD S3DEF s3_status s3_get_bucket_location(
    s3_client *c, const char *bucket,
    char *region_out, size_t region_out_size);

S3_NODISCARD S3DEF s3_status s3_list_directory_buckets(
    s3_client *c, const char *continuation_token, int max_buckets,
    s3_list_buckets_result *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Bucket Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Versioning */
S3_NODISCARD S3DEF s3_status s3_get_bucket_versioning(
    s3_client *c, const char *bucket, s3_versioning_status *status, bool *mfa_delete);
S3_NODISCARD S3DEF s3_status s3_put_bucket_versioning(
    s3_client *c, const char *bucket, s3_versioning_status status,
    bool mfa_delete, const char *mfa);

/* Lifecycle */
S3_NODISCARD S3DEF s3_status s3_get_bucket_lifecycle(
    s3_client *c, const char *bucket, s3_lifecycle_configuration *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_lifecycle(
    s3_client *c, const char *bucket, const s3_lifecycle_configuration *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_lifecycle(
    s3_client *c, const char *bucket);

/* Policy */
S3_NODISCARD S3DEF s3_status s3_get_bucket_policy(
    s3_client *c, const char *bucket, char **policy_json_out);
S3_NODISCARD S3DEF s3_status s3_put_bucket_policy(
    s3_client *c, const char *bucket, const char *policy_json);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_policy(
    s3_client *c, const char *bucket);
S3_NODISCARD S3DEF s3_status s3_get_bucket_policy_status(
    s3_client *c, const char *bucket, bool *is_public);

/* CORS */
S3_NODISCARD S3DEF s3_status s3_get_bucket_cors(
    s3_client *c, const char *bucket, s3_cors_configuration *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_cors(
    s3_client *c, const char *bucket, const s3_cors_configuration *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_cors(
    s3_client *c, const char *bucket);

/* Encryption */
S3_NODISCARD S3DEF s3_status s3_get_bucket_encryption(
    s3_client *c, const char *bucket, s3_bucket_encryption *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_encryption(
    s3_client *c, const char *bucket, const s3_bucket_encryption *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_encryption(
    s3_client *c, const char *bucket);

/* Logging */
S3_NODISCARD S3DEF s3_status s3_get_bucket_logging(
    s3_client *c, const char *bucket, s3_bucket_logging *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_logging(
    s3_client *c, const char *bucket, const s3_bucket_logging *config);

/* Tagging */
S3_NODISCARD S3DEF s3_status s3_get_bucket_tagging(
    s3_client *c, const char *bucket, s3_tag_set *tags);
S3_NODISCARD S3DEF s3_status s3_put_bucket_tagging(
    s3_client *c, const char *bucket, const s3_tag *tags, int tag_count);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_tagging(
    s3_client *c, const char *bucket);

/* Website */
S3_NODISCARD S3DEF s3_status s3_get_bucket_website(
    s3_client *c, const char *bucket, s3_website_configuration *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_website(
    s3_client *c, const char *bucket, const s3_website_configuration *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_website(
    s3_client *c, const char *bucket);

/* Notification */
S3_NODISCARD S3DEF s3_status s3_get_bucket_notification(
    s3_client *c, const char *bucket, s3_notification_configuration *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_notification(
    s3_client *c, const char *bucket, const s3_notification_configuration *config);

/* Replication */
S3_NODISCARD S3DEF s3_status s3_get_bucket_replication(
    s3_client *c, const char *bucket, s3_replication_configuration *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_replication(
    s3_client *c, const char *bucket, const s3_replication_configuration *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_replication(
    s3_client *c, const char *bucket);

/* Accelerate */
S3_NODISCARD S3DEF s3_status s3_get_bucket_accelerate(
    s3_client *c, const char *bucket, bool *enabled);
S3_NODISCARD S3DEF s3_status s3_put_bucket_accelerate(
    s3_client *c, const char *bucket, bool enabled);

/* Request Payment */
S3_NODISCARD S3DEF s3_status s3_get_bucket_request_payment(
    s3_client *c, const char *bucket, s3_payer *payer);
S3_NODISCARD S3DEF s3_status s3_put_bucket_request_payment(
    s3_client *c, const char *bucket, s3_payer payer);

/* Object Lock Configuration */
S3_NODISCARD S3DEF s3_status s3_get_object_lock_configuration(
    s3_client *c, const char *bucket, s3_object_lock_config *config);
S3_NODISCARD S3DEF s3_status s3_put_object_lock_configuration(
    s3_client *c, const char *bucket, const s3_object_lock_config *config);

/* ACL */
S3_NODISCARD S3DEF s3_status s3_get_bucket_acl(
    s3_client *c, const char *bucket, s3_acl *acl);
S3_NODISCARD S3DEF s3_status s3_put_bucket_acl(
    s3_client *c, const char *bucket, const s3_acl *acl);
S3_NODISCARD S3DEF s3_status s3_put_bucket_acl_canned(
    s3_client *c, const char *bucket, s3_canned_acl acl);

/* Intelligent-Tiering */
S3_NODISCARD S3DEF s3_status s3_get_bucket_intelligent_tiering(
    s3_client *c, const char *bucket, const char *id,
    s3_intelligent_tiering_config *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_intelligent_tiering(
    s3_client *c, const char *bucket, const s3_intelligent_tiering_config *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_intelligent_tiering(
    s3_client *c, const char *bucket, const char *id);
S3_NODISCARD S3DEF s3_status s3_list_bucket_intelligent_tiering(
    s3_client *c, const char *bucket,
    s3_intelligent_tiering_config **configs, int *count);

/* Metrics */
S3_NODISCARD S3DEF s3_status s3_get_bucket_metrics(
    s3_client *c, const char *bucket, const char *id,
    s3_metrics_config *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_metrics(
    s3_client *c, const char *bucket, const s3_metrics_config *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_metrics(
    s3_client *c, const char *bucket, const char *id);
S3_NODISCARD S3DEF s3_status s3_list_bucket_metrics(
    s3_client *c, const char *bucket, const char *continuation_token,
    s3_list_metrics_result *result);

/* Inventory */
S3_NODISCARD S3DEF s3_status s3_get_bucket_inventory(
    s3_client *c, const char *bucket, const char *id,
    s3_inventory_config *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_inventory(
    s3_client *c, const char *bucket, const s3_inventory_config *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_inventory(
    s3_client *c, const char *bucket, const char *id);
S3_NODISCARD S3DEF s3_status s3_list_bucket_inventory(
    s3_client *c, const char *bucket, const char *continuation_token,
    s3_list_inventory_result *result);

/* Analytics */
S3_NODISCARD S3DEF s3_status s3_get_bucket_analytics(
    s3_client *c, const char *bucket, const char *id,
    s3_analytics_config *config);
S3_NODISCARD S3DEF s3_status s3_put_bucket_analytics(
    s3_client *c, const char *bucket, const s3_analytics_config *config);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_analytics(
    s3_client *c, const char *bucket, const char *id);
S3_NODISCARD S3DEF s3_status s3_list_bucket_analytics(
    s3_client *c, const char *bucket, const char *continuation_token,
    s3_list_analytics_result *result);

/* Public Access Block */
S3_NODISCARD S3DEF s3_status s3_get_public_access_block(
    s3_client *c, const char *bucket, s3_public_access_block *config);
S3_NODISCARD S3DEF s3_status s3_put_public_access_block(
    s3_client *c, const char *bucket, const s3_public_access_block *config);
S3_NODISCARD S3DEF s3_status s3_delete_public_access_block(
    s3_client *c, const char *bucket);

/* Ownership Controls */
S3_NODISCARD S3DEF s3_status s3_get_bucket_ownership_controls(
    s3_client *c, const char *bucket, s3_object_ownership *ownership);
S3_NODISCARD S3DEF s3_status s3_put_bucket_ownership_controls(
    s3_client *c, const char *bucket, s3_object_ownership ownership);
S3_NODISCARD S3DEF s3_status s3_delete_bucket_ownership_controls(
    s3_client *c, const char *bucket);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Presigned URLs
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_presign_get(
    s3_client *c, const char *bucket, const char *key,
    int expires_seconds, char *url_buf, size_t url_buf_size);
S3_NODISCARD S3DEF s3_status s3_presign_put(
    s3_client *c, const char *bucket, const char *key,
    int expires_seconds, const char *content_type,
    char *url_buf, size_t url_buf_size);
S3_NODISCARD S3DEF s3_status s3_presign_delete(
    s3_client *c, const char *bucket, const char *key,
    int expires_seconds, char *url_buf, size_t url_buf_size);
S3_NODISCARD S3DEF s3_status s3_presign_head(
    s3_client *c, const char *bucket, const char *key,
    int expires_seconds, char *url_buf, size_t url_buf_size);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Select
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_select_object_content(
    s3_client *c, const char *bucket, const char *key,
    const s3_select_object_opts *opts,
    s3_write_fn write_fn, void *userdata);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Async / Event Loop
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_event_loop_create(
    s3_event_loop **out, const s3_event_loop_opts *opts);
S3DEF void s3_event_loop_destroy(s3_event_loop *loop);
S3_NODISCARD S3DEF s3_status s3_event_loop_poll(
    s3_event_loop *loop, int timeout_ms);

/* Future */
S3DEF s3_future_state s3_future_state_get(const s3_future *f);
S3DEF bool s3_future_is_done(const s3_future *f);
S3_NODISCARD S3DEF s3_status s3_future_wait(s3_future *f);
S3DEF s3_status s3_future_status(const s3_future *f);
S3DEF void *s3_future_result(const s3_future *f);
S3DEF void s3_future_on_complete(s3_future *f, s3_completion_fn fn, void *userdata);
S3DEF void s3_future_destroy(s3_future *f);

/* Async variants of operations */
S3_NODISCARD S3DEF s3_status s3_put_object_async(
    s3_client *c, const char *bucket, const char *key,
    const void *data, size_t data_len,
    const s3_put_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_get_object_async(
    s3_client *c, const char *bucket, const char *key,
    const s3_get_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_delete_object_async(
    s3_client *c, const char *bucket, const char *key,
    const s3_delete_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_head_object_async(
    s3_client *c, const char *bucket, const char *key,
    const s3_head_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_copy_object_async(
    s3_client *c,
    const char *src_bucket, const char *src_key,
    const char *dst_bucket, const char *dst_key,
    const s3_copy_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_list_objects_async(
    s3_client *c, const char *bucket,
    const s3_list_objects_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_delete_objects_async(
    s3_client *c, const char *bucket,
    const s3_delete_object_entry *entries, int entry_count,
    bool quiet, s3_future **future);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — Thread Pool
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_pool_create(
    s3_pool **out, const s3_config *config, const s3_pool_opts *opts);
S3DEF void s3_pool_destroy(s3_pool *pool);

S3_NODISCARD S3DEF s3_status s3_pool_put_object(
    s3_pool *pool, const char *bucket, const char *key,
    const void *data, size_t data_len,
    const s3_put_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_pool_get_object(
    s3_pool *pool, const char *bucket, const char *key,
    const s3_get_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_pool_delete_object(
    s3_pool *pool, const char *bucket, const char *key,
    const s3_delete_object_opts *opts, s3_future **future);
S3_NODISCARD S3DEF s3_status s3_pool_delete_objects(
    s3_pool *pool, const char *bucket,
    const s3_delete_object_entry *entries, int entry_count,
    bool quiet, s3_future **future);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — High-Level Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_upload_file(
    s3_client *c, const char *bucket, const char *key,
    const char *filepath, const s3_upload_file_opts *opts,
    s3_put_object_result *result);

S3_NODISCARD S3DEF s3_status s3_upload_file_parallel(
    s3_pool *pool, const char *bucket, const char *key,
    const char *filepath, const s3_upload_file_opts *opts,
    s3_future **future);

S3_NODISCARD S3DEF s3_status s3_download_file(
    s3_client *c, const char *bucket, const char *key,
    const char *filepath, const s3_download_file_opts *opts);

S3_NODISCARD S3DEF s3_status s3_download_file_parallel(
    s3_pool *pool, const char *bucket, const char *key,
    const char *filepath, const s3_download_file_opts *opts,
    s3_future **future);

S3_NODISCARD S3DEF s3_status s3_object_exists(
    s3_client *c, const char *bucket, const char *key, bool *exists);

S3_NODISCARD S3DEF s3_status s3_list_all_objects(
    s3_client *c, const char *bucket,
    const s3_list_objects_opts *opts,
    s3_object_info **objects_out, int *count_out);

S3_NODISCARD S3DEF s3_status s3_copy_large_object(
    s3_pool *pool,
    const char *src_bucket, const char *src_key,
    const char *dst_bucket, const char *dst_key,
    size_t part_size, int max_concurrent,
    const s3_copy_object_opts *opts, s3_future **future);

S3_NODISCARD S3DEF s3_status s3_sync_upload(
    s3_client *c, const char *bucket,
    const char *local_dir, const s3_sync_opts *opts,
    s3_sync_result *result);

S3_NODISCARD S3DEF s3_status s3_sync_download(
    s3_client *c, const char *bucket,
    const char *local_dir, const s3_sync_opts *opts,
    s3_sync_result *result);

S3_NODISCARD S3DEF s3_status s3_delete_all_objects(
    s3_client *c, const char *bucket, const char *prefix,
    bool include_versions, int *deleted_count);

S3_NODISCARD S3DEF s3_status s3_delete_bucket_force(
    s3_client *c, const char *bucket);

/* MIME type detection */
S3DEF const char *s3_detect_content_type(const char *filename);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Control: Access Points
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_access_point(
    s3_client *c, const char *name, const char *bucket,
    const s3_public_access_block *block_config);
S3_NODISCARD S3DEF s3_status s3_delete_access_point(
    s3_client *c, const char *name);
S3_NODISCARD S3DEF s3_status s3_get_access_point(
    s3_client *c, const char *name, s3_access_point *result);
S3_NODISCARD S3DEF s3_status s3_list_access_points(
    s3_client *c, const char *bucket, const char *next_token, int max_results,
    s3_list_access_points_result *result);
S3_NODISCARD S3DEF s3_status s3_get_access_point_policy(
    s3_client *c, const char *name, char **policy_json_out);
S3_NODISCARD S3DEF s3_status s3_put_access_point_policy(
    s3_client *c, const char *name, const char *policy_json);
S3_NODISCARD S3DEF s3_status s3_delete_access_point_policy(
    s3_client *c, const char *name);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Control: Object Lambda Access Points
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_access_point_for_object_lambda(
    s3_client *c, const char *name, const char *supporting_access_point,
    const char *configuration_xml);
S3_NODISCARD S3DEF s3_status s3_delete_access_point_for_object_lambda(
    s3_client *c, const char *name);
S3_NODISCARD S3DEF s3_status s3_get_access_point_for_object_lambda(
    s3_client *c, const char *name, char **config_xml_out);
S3_NODISCARD S3DEF s3_status s3_list_access_points_for_object_lambda(
    s3_client *c, const char *next_token, int max_results,
    s3_list_access_points_result *result);
S3_NODISCARD S3DEF s3_status s3_get_access_point_policy_for_object_lambda(
    s3_client *c, const char *name, char **policy_json_out);
S3_NODISCARD S3DEF s3_status s3_put_access_point_policy_for_object_lambda(
    s3_client *c, const char *name, const char *policy_json);
S3_NODISCARD S3DEF s3_status s3_delete_access_point_policy_for_object_lambda(
    s3_client *c, const char *name);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Control: Access Grants
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_access_grants_instance(
    s3_client *c, const char *identity_center_arn,
    s3_access_grants_instance *result);
S3_NODISCARD S3DEF s3_status s3_delete_access_grants_instance(s3_client *c);
S3_NODISCARD S3DEF s3_status s3_get_access_grants_instance(
    s3_client *c, s3_access_grants_instance *result);

S3_NODISCARD S3DEF s3_status s3_create_access_grants_location(
    s3_client *c, const char *location_scope, const char *iam_role_arn,
    s3_access_grants_location *result);
S3_NODISCARD S3DEF s3_status s3_delete_access_grants_location(
    s3_client *c, const char *location_id);
S3_NODISCARD S3DEF s3_status s3_get_access_grants_location(
    s3_client *c, const char *location_id, s3_access_grants_location *result);

S3_NODISCARD S3DEF s3_status s3_create_access_grant(
    s3_client *c, const char *location_id,
    const char *grantee_type, const char *grantee_id,
    const char *permission, s3_access_grant *result);
S3_NODISCARD S3DEF s3_status s3_delete_access_grant(
    s3_client *c, const char *grant_id);
S3_NODISCARD S3DEF s3_status s3_get_access_grant(
    s3_client *c, const char *grant_id, s3_access_grant *result);

S3_NODISCARD S3DEF s3_status s3_get_data_access(
    s3_client *c, const char *target, const char *permission,
    int duration_seconds, s3_session_credentials *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Control: Multi-Region Access Points
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_multi_region_access_point(
    s3_client *c, const char *name,
    const char *const *regions, const char *const *buckets, int count,
    char *request_token_out, size_t token_buf_size);
S3_NODISCARD S3DEF s3_status s3_delete_multi_region_access_point(
    s3_client *c, const char *name,
    char *request_token_out, size_t token_buf_size);
S3_NODISCARD S3DEF s3_status s3_get_multi_region_access_point(
    s3_client *c, const char *name, s3_mrap *result);
S3_NODISCARD S3DEF s3_status s3_list_multi_region_access_points(
    s3_client *c, const char *next_token, int max_results,
    s3_list_mrap_result *result);
S3_NODISCARD S3DEF s3_status s3_describe_multi_region_access_point_operation(
    s3_client *c, const char *request_token, char *status_out, size_t status_buf_size);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Control: Batch Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_job(
    s3_client *c, const char *manifest_xml, const char *operation_xml,
    const char *report_xml, const char *role_arn,
    int priority, bool confirmation_required,
    const char *description, char *job_id_out, size_t job_id_buf_size);
S3_NODISCARD S3DEF s3_status s3_describe_job(
    s3_client *c, const char *job_id, s3_job *result);
S3_NODISCARD S3DEF s3_status s3_list_jobs(
    s3_client *c, const char *const *statuses, int status_count,
    const char *next_token, int max_results, s3_list_jobs_result *result);
S3_NODISCARD S3DEF s3_status s3_update_job_priority(
    s3_client *c, const char *job_id, int priority);
S3_NODISCARD S3DEF s3_status s3_update_job_status(
    s3_client *c, const char *job_id, const char *requested_status,
    const char *reason);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Control: Storage Lens
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_get_storage_lens_configuration(
    s3_client *c, const char *id, char **config_xml_out);
S3_NODISCARD S3DEF s3_status s3_put_storage_lens_configuration(
    s3_client *c, const char *id, const char *config_xml);
S3_NODISCARD S3DEF s3_status s3_delete_storage_lens_configuration(
    s3_client *c, const char *id);
S3_NODISCARD S3DEF s3_status s3_list_storage_lens_configurations(
    s3_client *c, const char *next_token,
    s3_list_storage_lens_result *result);

S3_NODISCARD S3DEF s3_status s3_tag_resource(
    s3_client *c, const char *resource_arn,
    const s3_tag *tags, int tag_count);
S3_NODISCARD S3DEF s3_status s3_untag_resource(
    s3_client *c, const char *resource_arn,
    const char *const *tag_keys, int key_count);
S3_NODISCARD S3DEF s3_status s3_list_tags_for_resource(
    s3_client *c, const char *resource_arn, s3_tag_set *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Express One Zone
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_session(
    s3_client *c, const char *bucket,
    s3_express_session_mode mode,
    s3_session_credentials *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Tables
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_table_bucket(
    s3_client *c, const char *name, s3_table_bucket *result);
S3_NODISCARD S3DEF s3_status s3_delete_table_bucket(
    s3_client *c, const char *table_bucket_arn);
S3_NODISCARD S3DEF s3_status s3_get_table_bucket(
    s3_client *c, const char *table_bucket_arn, s3_table_bucket *result);
S3_NODISCARD S3DEF s3_status s3_list_table_buckets(
    s3_client *c, const char *continuation_token, int max_buckets,
    s3_table_bucket **buckets_out, int *count_out);

S3_NODISCARD S3DEF s3_status s3_create_namespace(
    s3_client *c, const char *table_bucket_arn, const char *name,
    s3_namespace *result);
S3_NODISCARD S3DEF s3_status s3_delete_namespace(
    s3_client *c, const char *table_bucket_arn, const char *name);
S3_NODISCARD S3DEF s3_status s3_get_namespace(
    s3_client *c, const char *table_bucket_arn, const char *name,
    s3_namespace *result);
S3_NODISCARD S3DEF s3_status s3_list_namespaces(
    s3_client *c, const char *table_bucket_arn,
    const char *continuation_token, int max_namespaces,
    s3_namespace **namespaces_out, int *count_out);

S3_NODISCARD S3DEF s3_status s3_create_table(
    s3_client *c, const char *table_bucket_arn,
    const char *namespace_name, const char *name,
    const char *format, s3_table *result);
S3_NODISCARD S3DEF s3_status s3_delete_table(
    s3_client *c, const char *table_bucket_arn,
    const char *namespace_name, const char *name, const char *version_token);
S3_NODISCARD S3DEF s3_status s3_get_table(
    s3_client *c, const char *table_bucket_arn,
    const char *namespace_name, const char *name,
    s3_table *result);
S3_NODISCARD S3DEF s3_status s3_list_tables(
    s3_client *c, const char *table_bucket_arn,
    const char *namespace_name, const char *continuation_token,
    int max_tables, s3_table **tables_out, int *count_out);
S3_NODISCARD S3DEF s3_status s3_rename_table(
    s3_client *c, const char *table_bucket_arn,
    const char *namespace_name, const char *name,
    const char *new_namespace_name, const char *new_name,
    const char *version_token);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 Vectors
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_vector_bucket(
    s3_client *c, const char *name, s3_vector_bucket *result);
S3_NODISCARD S3DEF s3_status s3_delete_vector_bucket(
    s3_client *c, const char *name);
S3_NODISCARD S3DEF s3_status s3_get_vector_bucket(
    s3_client *c, const char *name, s3_vector_bucket *result);
S3_NODISCARD S3DEF s3_status s3_list_vector_buckets(
    s3_client *c, const char *continuation_token, int max_buckets,
    s3_vector_bucket **buckets_out, int *count_out);

S3_NODISCARD S3DEF s3_status s3_create_index(
    s3_client *c, const char *vector_bucket, const char *index_name,
    int dimension, s3_vector_distance_metric metric,
    s3_vector_index *result);
S3_NODISCARD S3DEF s3_status s3_delete_index(
    s3_client *c, const char *vector_bucket, const char *index_name);
S3_NODISCARD S3DEF s3_status s3_get_index(
    s3_client *c, const char *vector_bucket, const char *index_name,
    s3_vector_index *result);
S3_NODISCARD S3DEF s3_status s3_list_indexes(
    s3_client *c, const char *vector_bucket,
    const char *continuation_token, int max_indexes,
    s3_vector_index **indexes_out, int *count_out);

S3_NODISCARD S3DEF s3_status s3_put_vectors(
    s3_client *c, const char *vector_bucket, const char *index_name,
    const s3_vector *vectors, int vector_count);
S3_NODISCARD S3DEF s3_status s3_get_vectors(
    s3_client *c, const char *vector_bucket, const char *index_name,
    const char *const *keys, int key_count,
    s3_vector **vectors_out, int *count_out);
S3_NODISCARD S3DEF s3_status s3_delete_vectors(
    s3_client *c, const char *vector_bucket, const char *index_name,
    const char *const *keys, int key_count);
S3_NODISCARD S3DEF s3_status s3_list_vectors(
    s3_client *c, const char *vector_bucket, const char *index_name,
    const char *continuation_token, int max_vectors,
    s3_vector **vectors_out, int *count_out);
S3_NODISCARD S3DEF s3_status s3_query_vectors(
    s3_client *c, const char *vector_bucket, const char *index_name,
    const float *query_vector, int dimension, int top_k,
    const char *filter_expression,
    s3_vector_query_result *result);

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API — S3 on Outposts
 * ═══════════════════════════════════════════════════════════════════════════ */

S3_NODISCARD S3DEF s3_status s3_create_outpost_endpoint(
    s3_client *c, const char *outpost_id,
    const char *subnet_id, const char *security_group_id,
    const char *access_type, s3_outpost_endpoint *result);
S3_NODISCARD S3DEF s3_status s3_delete_outpost_endpoint(
    s3_client *c, const char *endpoint_id, const char *outpost_id);
S3_NODISCARD S3DEF s3_status s3_list_outpost_endpoints(
    s3_client *c, const char *outpost_id,
    const char *next_token, int max_results,
    s3_outpost_endpoint **endpoints_out, int *count_out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Free Functions for Library-Allocated Results
 * ═══════════════════════════════════════════════════════════════════════════ */

S3DEF void s3_head_object_result_free(s3_head_object_result *r);
S3DEF void s3_list_objects_result_free(s3_list_objects_result *r);
S3DEF void s3_list_object_versions_result_free(s3_list_object_versions_result *r);
S3DEF void s3_list_buckets_result_free(s3_list_buckets_result *r);
S3DEF void s3_list_parts_result_free(s3_list_parts_result *r);
S3DEF void s3_list_multipart_uploads_result_free(s3_list_multipart_uploads_result *r);
S3DEF void s3_delete_objects_result_free(s3_delete_objects_result *r);
S3DEF void s3_object_attributes_result_free(s3_object_attributes_result *r);
S3DEF void s3_tag_set_free(s3_tag_set *r);
S3DEF void s3_acl_free(s3_acl *r);
S3DEF void s3_cors_configuration_free(s3_cors_configuration *r);
S3DEF void s3_lifecycle_configuration_free(s3_lifecycle_configuration *r);
S3DEF void s3_website_configuration_free(s3_website_configuration *r);
S3DEF void s3_notification_configuration_free(s3_notification_configuration *r);
S3DEF void s3_replication_configuration_free(s3_replication_configuration *r);
S3DEF void s3_list_access_points_result_free(s3_list_access_points_result *r);
S3DEF void s3_list_jobs_result_free(s3_list_jobs_result *r);
S3DEF void s3_list_storage_lens_result_free(s3_list_storage_lens_result *r);
S3DEF void s3_list_mrap_result_free(s3_list_mrap_result *r);
S3DEF void s3_vector_query_result_free(s3_vector_query_result *r);
S3DEF void s3_sync_result_free(s3_sync_result *r);

#endif /* S3_H */
