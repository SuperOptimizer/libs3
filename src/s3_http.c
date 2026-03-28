/*
 * libs3 -- HTTP / libcurl integration layer
 *
 * This is the backbone of every S3 operation: URL construction,
 * response parsing, curl callback plumbing, retry logic.
 */

#define _POSIX_C_SOURCE 200809L
#include "s3_internal.h"
#include <ctype.h>
#include <strings.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * URL Construction
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__build_url(const s3_client *c, const char *bucket, const char *key,
                   const char *query, bool control_endpoint,
                   char *url, size_t url_size)
{
    const char *scheme = c->use_https ? "https" : "http";

    /* Encode the key (preserving slashes) if present */
    char encoded_key[4096] = "";
    if (key && key[0]) {
        s3__uri_encode_path(key, strlen(key), encoded_key, sizeof(encoded_key));
    }

    /* Build the query suffix */
    char query_suffix[4096] = "";
    if (query && query[0]) {
        snprintf(query_suffix, sizeof(query_suffix), "?%s", query);
    }

    /* S3 Control API endpoint: {account_id}.s3-control.{region}.amazonaws.com */
    if (control_endpoint) {
        const char *acct = c->account_id ? c->account_id : "";
        snprintf(url, url_size, "%s://%s.s3-control.%s.amazonaws.com/%s%s",
                 scheme, acct, c->region, encoded_key, query_suffix);
        return;
    }

    /* No bucket (e.g. ListBuckets) */
    if (!bucket || !bucket[0]) {
        const char *host;
        char host_buf[512];
        if (c->endpoint && c->endpoint[0]) {
            host = c->endpoint;
        } else {
            snprintf(host_buf, sizeof(host_buf), "s3.%s.amazonaws.com", c->region);
            host = host_buf;
        }
        snprintf(url, url_size, "%s://%s/%s%s",
                 scheme, host, encoded_key, query_suffix);
        return;
    }

    /* Custom endpoint */
    if (c->endpoint && c->endpoint[0]) {
        if (c->use_path_style) {
            snprintf(url, url_size, "%s://%s/%s/%s%s",
                     scheme, c->endpoint, bucket, encoded_key, query_suffix);
        } else {
            snprintf(url, url_size, "%s://%s.%s/%s%s",
                     scheme, bucket, c->endpoint, encoded_key, query_suffix);
        }
        return;
    }

    /* Transfer acceleration */
    if (c->use_transfer_acceleration) {
        snprintf(url, url_size, "%s://%s.s3-accelerate.amazonaws.com/%s%s",
                 scheme, bucket, encoded_key, query_suffix);
        return;
    }

    /* FIPS */
    if (c->use_fips) {
        snprintf(url, url_size, "%s://%s.s3-fips.%s.amazonaws.com/%s%s",
                 scheme, bucket, c->region, encoded_key, query_suffix);
        return;
    }

    /* Dual-stack */
    if (c->use_dual_stack) {
        snprintf(url, url_size, "%s://%s.s3.dualstack.%s.amazonaws.com/%s%s",
                 scheme, bucket, c->region, encoded_key, query_suffix);
        return;
    }

    /* Standard AWS S3 */
    if (c->use_path_style) {
        snprintf(url, url_size, "%s://s3.%s.amazonaws.com/%s/%s%s",
                 scheme, c->region, bucket, encoded_key, query_suffix);
    } else {
        /* Virtual-hosted style (default) */
        snprintf(url, url_size, "%s://%s.s3.%s.amazonaws.com/%s%s",
                 scheme, bucket, c->region, encoded_key, query_suffix);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Response Reset
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__reset_response(s3_client *c)
{
    /* Clear the response buffer */
    c->response.len = 0;
    if (c->response.data)
        c->response.data[0] = '\0';

    /* Clear all response header fields */
    c->resp_etag[0] = '\0';
    c->resp_version_id[0] = '\0';
    c->resp_request_id[0] = '\0';
    c->resp_host_id[0] = '\0';
    c->resp_content_type[0] = '\0';
    c->resp_last_modified[0] = '\0';
    c->resp_content_length = -1;
    c->resp_storage_class[0] = '\0';
    c->resp_server_side_encryption[0] = '\0';
    c->resp_sse_kms_key_id[0] = '\0';
    c->resp_sse_customer_algorithm[0] = '\0';
    c->resp_sse_customer_key_md5[0] = '\0';
    c->resp_bucket_key_enabled = false;
    c->resp_delete_marker = false;
    c->resp_expiration[0] = '\0';
    c->resp_restore[0] = '\0';
    c->resp_replication_status[0] = '\0';
    c->resp_parts_count = 0;
    c->resp_lock_mode[0] = '\0';
    c->resp_lock_retain_until[0] = '\0';
    c->resp_legal_hold[0] = '\0';
    c->resp_checksum_crc32[0] = '\0';
    c->resp_checksum_crc32c[0] = '\0';
    c->resp_checksum_sha1[0] = '\0';
    c->resp_checksum_sha256[0] = '\0';
    c->resp_content_encoding[0] = '\0';
    c->resp_content_language[0] = '\0';
    c->resp_content_disposition[0] = '\0';
    c->resp_cache_control[0] = '\0';
    c->resp_expires_header[0] = '\0';

    /* Free user metadata */
    if (c->resp_metadata) {
        for (int i = 0; i < c->resp_metadata_count; i++) {
            S3_FREE((void *)c->resp_metadata[i].key);
            S3_FREE((void *)c->resp_metadata[i].value);
        }
        S3_FREE(c->resp_metadata);
        c->resp_metadata = nullptr;
    }
    c->resp_metadata_count = 0;
    c->resp_metadata_cap = 0;

    /* Reset curl error buffer */
    c->curl_errbuf[0] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Curl Callbacks
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * s3__curl_write_cb — CURLOPT_WRITEFUNCTION
 *
 * If the user set a write_fn, delegate to it. Otherwise, append the
 * received data into the client's response buffer.
 */
typedef struct s3_write_ctx {
    s3_client   *client;
    s3_write_fn  write_fn;
    void        *write_userdata;
} s3_write_ctx;

static size_t s3__curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t bytes = size * nmemb;
    s3_write_ctx *ctx = (s3_write_ctx *)userdata;

    if (ctx->write_fn) {
        int rc = ctx->write_fn(ptr, bytes, ctx->write_userdata);
        return rc == 0 ? bytes : 0;
    }

    /* Append to internal response buffer */
    if (s3_buf_append(&ctx->client->response, ptr, bytes) < 0)
        return 0;

    return bytes;
}

/*
 * s3__curl_read_cb — CURLOPT_READFUNCTION
 *
 * Delegates to the user's s3_read_fn for streaming uploads.
 */
typedef struct s3_read_ctx {
    s3_read_fn  read_fn;
    void       *read_userdata;
} s3_read_ctx;

static size_t s3__curl_read_cb(char *buf, size_t size, size_t nmemb, void *userdata)
{
    s3_read_ctx *ctx = (s3_read_ctx *)userdata;
    if (!ctx->read_fn)
        return 0;

    int64_t n = ctx->read_fn(buf, size * nmemb, ctx->read_userdata);
    if (n < 0)
        return CURL_READFUNC_ABORT;
    return (size_t)n;
}

/*
 * Case-insensitive header name comparison helper.
 * Returns true if the first `name_len` bytes of `header` match `name`
 * (case-insensitive) and header[name_len] == ':'.
 */
static bool header_name_eq(const char *header, const char *name, size_t name_len)
{
    if (strncasecmp(header, name, name_len) != 0)
        return false;
    return header[name_len] == ':';
}

/*
 * Extract the trimmed value from a header line "Name: value\r\n".
 * Writes into dst (up to dst_size - 1 chars).  Returns the value pointer
 * within the original header (for callers that need it).
 */
static const char *header_value(const char *header, size_t name_len,
                                char *dst, size_t dst_size)
{
    const char *val = header + name_len + 1; /* skip past ':' */
    while (*val == ' ' || *val == '\t') val++;

    /* Find end (strip trailing \r\n) */
    const char *end = val;
    while (*end && *end != '\r' && *end != '\n') end++;

    size_t vlen = (size_t)(end - val);
    if (vlen >= dst_size) vlen = dst_size - 1;
    memcpy(dst, val, vlen);
    dst[vlen] = '\0';
    return val;
}

/*
 * Store a user-metadata key/value (from x-amz-meta-* headers).
 */
static void store_metadata(s3_client *c, const char *key, size_t key_len,
                           const char *val, size_t val_len)
{
    if (c->resp_metadata_count >= c->resp_metadata_cap) {
        int new_cap = c->resp_metadata_cap ? c->resp_metadata_cap * 2 : 8;
        s3_metadata *p = (s3_metadata *)S3_REALLOC(c->resp_metadata,
                                                    (size_t)new_cap * sizeof(s3_metadata));
        if (!p) return;
        c->resp_metadata = p;
        c->resp_metadata_cap = new_cap;
    }
    int idx = c->resp_metadata_count++;
    c->resp_metadata[idx].key = s3__strndup(key, key_len);
    c->resp_metadata[idx].value = s3__strndup(val, val_len);
}

/*
 * s3__curl_header_cb — CURLOPT_HEADERFUNCTION
 *
 * Parse response headers and store into the client's resp_* fields.
 */
static size_t s3__curl_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    size_t bytes = size * nitems;
    s3_client *c = (s3_client *)userdata;

    /* Ignore lines that don't have a colon (status line, blank line) */
    const char *colon = memchr(buffer, ':', bytes);
    if (!colon) return bytes;

    size_t name_len = (size_t)(colon - buffer);

    /* Scratch buffer for values */
    char val[512];

#define CHECK_HDR(hdr, field) \
    if (header_name_eq(buffer, hdr, name_len)) { \
        header_value(buffer, name_len, field, sizeof(field)); \
        return bytes; \
    }

    CHECK_HDR("ETag",                                          c->resp_etag);
    CHECK_HDR("x-amz-request-id",                              c->resp_request_id);
    CHECK_HDR("x-amz-id-2",                                    c->resp_host_id);
    CHECK_HDR("Content-Type",                                   c->resp_content_type);
    CHECK_HDR("Last-Modified",                                  c->resp_last_modified);
    CHECK_HDR("x-amz-version-id",                              c->resp_version_id);
    CHECK_HDR("x-amz-storage-class",                           c->resp_storage_class);
    CHECK_HDR("x-amz-server-side-encryption",                  c->resp_server_side_encryption);
    CHECK_HDR("x-amz-server-side-encryption-aws-kms-key-id",   c->resp_sse_kms_key_id);
    CHECK_HDR("x-amz-server-side-encryption-customer-algorithm", c->resp_sse_customer_algorithm);
    CHECK_HDR("x-amz-server-side-encryption-customer-key-MD5", c->resp_sse_customer_key_md5);
    CHECK_HDR("x-amz-expiration",                              c->resp_expiration);
    CHECK_HDR("x-amz-restore",                                 c->resp_restore);
    CHECK_HDR("x-amz-replication-status",                      c->resp_replication_status);
    CHECK_HDR("x-amz-object-lock-mode",                        c->resp_lock_mode);
    CHECK_HDR("x-amz-object-lock-retain-until-date",           c->resp_lock_retain_until);
    CHECK_HDR("x-amz-object-lock-legal-hold",                  c->resp_legal_hold);
    CHECK_HDR("x-amz-checksum-crc32",                          c->resp_checksum_crc32);
    CHECK_HDR("x-amz-checksum-crc32c",                         c->resp_checksum_crc32c);
    CHECK_HDR("x-amz-checksum-sha1",                           c->resp_checksum_sha1);
    CHECK_HDR("x-amz-checksum-sha256",                         c->resp_checksum_sha256);
    CHECK_HDR("Content-Encoding",                               c->resp_content_encoding);
    CHECK_HDR("Content-Language",                               c->resp_content_language);
    CHECK_HDR("Content-Disposition",                            c->resp_content_disposition);
    CHECK_HDR("Cache-Control",                                  c->resp_cache_control);
    CHECK_HDR("Expires",                                        c->resp_expires_header);

#undef CHECK_HDR

    /* Content-Length (integer) */
    if (header_name_eq(buffer, "Content-Length", name_len)) {
        header_value(buffer, name_len, val, sizeof(val));
        c->resp_content_length = strtoll(val, nullptr, 10);
        return bytes;
    }

    /* x-amz-delete-marker (boolean) */
    if (header_name_eq(buffer, "x-amz-delete-marker", name_len)) {
        header_value(buffer, name_len, val, sizeof(val));
        c->resp_delete_marker = (strncasecmp(val, "true", 4) == 0);
        return bytes;
    }

    /* x-amz-server-side-encryption-bucket-key-enabled (boolean) */
    if (header_name_eq(buffer, "x-amz-server-side-encryption-bucket-key-enabled", name_len)) {
        header_value(buffer, name_len, val, sizeof(val));
        c->resp_bucket_key_enabled = (strncasecmp(val, "true", 4) == 0);
        return bytes;
    }

    /* x-amz-mp-parts-count (integer) */
    if (header_name_eq(buffer, "x-amz-mp-parts-count", name_len)) {
        header_value(buffer, name_len, val, sizeof(val));
        c->resp_parts_count = (int)strtol(val, nullptr, 10);
        return bytes;
    }

    /* x-amz-meta-* user metadata */
    static const char meta_prefix[] = "x-amz-meta-";
    static const size_t meta_prefix_len = sizeof(meta_prefix) - 1;

    if (name_len > meta_prefix_len && strncasecmp(buffer, meta_prefix, meta_prefix_len) == 0) {
        /* Key is the part after "x-amz-meta-" */
        const char *meta_key = buffer + meta_prefix_len;
        size_t meta_key_len = name_len - meta_prefix_len;

        /* Extract value */
        const char *v = buffer + name_len + 1;
        while (*v == ' ' || *v == '\t') v++;
        const char *vend = v;
        while (*vend && *vend != '\r' && *vend != '\n') vend++;

        store_metadata(c, meta_key, meta_key_len, v, (size_t)(vend - v));
        return bytes;
    }

    return bytes;
}

/*
 * s3__curl_progress_cb — CURLOPT_XFERINFOFUNCTION
 *
 * Delegates to the user's s3_progress_fn.
 */
typedef struct s3_progress_ctx {
    s3_progress_fn  progress_fn;
    void           *progress_userdata;
} s3_progress_ctx;

static int s3__curl_progress_cb(void *userdata,
                                curl_off_t dltotal, curl_off_t dlnow,
                                curl_off_t ultotal, curl_off_t ulnow)
{
    s3_progress_ctx *ctx = (s3_progress_ctx *)userdata;
    if (!ctx->progress_fn)
        return 0;
    return ctx->progress_fn((int64_t)ulnow, (int64_t)ultotal,
                            (int64_t)dlnow, (int64_t)dltotal,
                            ctx->progress_userdata);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Extract host from URL (for Host header)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void extract_host(const char *url, char *host, size_t host_size)
{
    /* Skip scheme */
    const char *p = strstr(url, "://");
    if (p) p += 3; else p = url;

    /* Find end of host (/ or end) */
    const char *end = p;
    while (*end && *end != '/' && *end != '?') end++;

    size_t len = (size_t)(end - p);
    if (len >= host_size) len = host_size - 1;
    memcpy(host, p, len);
    host[len] = '\0';
}

/*
 * Extract URI path from URL (everything from first / after host).
 */
static void extract_uri(const char *url, char *uri, size_t uri_size)
{
    const char *p = strstr(url, "://");
    if (p) p += 3; else p = url;

    /* Skip host */
    const char *slash = strchr(p, '/');
    if (!slash) {
        snprintf(uri, uri_size, "/");
        return;
    }

    /* Find end of path (before query) */
    const char *end = strchr(slash, '?');
    if (!end) end = slash + strlen(slash);

    size_t len = (size_t)(end - slash);
    if (len >= uri_size) len = uri_size - 1;
    memcpy(uri, slash, len);
    uri[len] = '\0';

    if (len == 0) {
        uri[0] = '/';
        uri[1] = '\0';
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Sleep helper (milliseconds, using nanosleep)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Central HTTP Request Dispatcher
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3__request(s3_client *c, const s3_request_params *params)
{
    if (!c || !params || !params->method)
        return S3_STATUS_INVALID_ARGUMENT;

    /* (a) Reset response state */
    s3__reset_response(c);
    s3__clear_error(c);

    /* (b) Compute payload hash */
    char payload_hash_buf[65];
    const char *payload_hash;

    if (params->payload_hash) {
        payload_hash = params->payload_hash;
    } else if (params->upload_data && params->upload_len > 0) {
        s3__sha256_hex(params->upload_data, params->upload_len, payload_hash_buf);
        payload_hash = payload_hash_buf;
    } else if (params->read_fn) {
        payload_hash = "UNSIGNED-PAYLOAD";
    } else {
        /* Empty payload */
        s3__sha256_hex("", 0, payload_hash_buf);
        payload_hash = payload_hash_buf;
    }

    /* (c) Build URL */
    char url[4096];
    s3__build_url(c, params->bucket, params->key, params->query_string,
                  params->use_control_endpoint, url, sizeof(url));

    S3_LOG_DEBUG_(c, "s3__request: %s %s", params->method, url);

    /* Extract URI and host from the built URL */
    char uri[4096];
    char host[512];
    extract_uri(url, uri, sizeof(uri));
    extract_host(url, host, sizeof(host));

    /* (d) Build initial header list */
    struct curl_slist *headers = nullptr;

    /* Host header */
    char host_hdr[600];
    snprintf(host_hdr, sizeof(host_hdr), "Host: %s", host);
    headers = curl_slist_append(headers, host_hdr);

    /* (e) Apply extra headers from params */
    for (struct curl_slist *h = params->extra_headers; h; h = h->next) {
        headers = curl_slist_append(headers, h->data);
    }

    /* (f) Sign the request (adds Authorization, x-amz-date, x-amz-content-sha256, etc.) */
    if (s3__sign_request(c, params->method, uri, params->query_string,
                         &headers, payload_hash) != 0) {
        curl_slist_free_all(headers);
        return S3_STATUS_INTERNAL_ERROR;
    }

    /* Set up callback contexts */
    s3_write_ctx write_ctx = {
        .client = c,
        .write_fn = params->write_fn,
        .write_userdata = params->write_userdata,
    };

    s3_read_ctx read_ctx = {
        .read_fn = params->read_fn,
        .read_userdata = params->read_userdata,
    };

    s3_progress_ctx progress_ctx = {
        .progress_fn = params->progress_fn,
        .progress_userdata = params->progress_userdata,
    };

    /* (g) Configure CURL */
    CURL *curl = c->curl;
    curl_easy_reset(curl);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, params->method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Write callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3__curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);

    /* Header callback */
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, s3__curl_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, c);

    /* Error buffer */
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, c->curl_errbuf);

    /* PUT/POST with streaming read function */
    if (params->read_fn &&
        (strcmp(params->method, "PUT") == 0 || strcmp(params->method, "POST") == 0)) {
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, s3__curl_read_cb);
        curl_easy_setopt(curl, CURLOPT_READDATA, &read_ctx);
        if (params->content_length >= 0) {
            curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                             (curl_off_t)params->content_length);
        }
    }
    /* PUT/POST with in-memory buffer */
    else if (params->upload_data &&
             (strcmp(params->method, "PUT") == 0 || strcmp(params->method, "POST") == 0)) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params->upload_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)params->upload_len);
    }

    /* HEAD */
    if (strcmp(params->method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }

    /* Timeouts */
    if (c->connect_timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, c->connect_timeout_ms);
    if (c->request_timeout_ms > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, c->request_timeout_ms);

    /* User agent */
    const char *ua = c->user_agent ? c->user_agent : "libs3/1.0";
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua);

    /* Progress callback */
    if (params->progress_fn) {
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, s3__curl_progress_cb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress_ctx);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    }

    /* Thread safety: do not install signal handlers */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    /* (h) Retry loop */
    s3_status status = S3_STATUS_UNKNOWN_ERROR;
    int max_attempts = c->retry_policy.max_retries + 1;

    for (int attempt = 0; attempt < max_attempts; attempt++) {
        if (attempt > 0) {
            /* Reset response state for retry */
            s3__reset_response(c);
            S3_LOG_DEBUG_(c, "Retry attempt %d for %s %s", attempt, params->method, url);
        }

        CURLcode res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            long http_status = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

            S3_LOG_DEBUG_(c, "HTTP %ld for %s %s", http_status, params->method, url);

            if (http_status >= 200 && http_status < 300) {
                status = S3_STATUS_OK;
                break;
            }

            /* HTTP error — parse the XML error response */
            status = s3__parse_error_response(c, http_status);
        } else {
            /* Curl-level error */
            s3__set_curl_error(c, (long)res);

            switch (res) {
            case CURLE_COULDNT_CONNECT:
                status = S3_STATUS_CONNECTION_FAILED;
                break;
            case CURLE_COULDNT_RESOLVE_HOST:
            case CURLE_COULDNT_RESOLVE_PROXY:
                status = S3_STATUS_DNS_RESOLUTION_FAILED;
                break;
            case CURLE_OPERATION_TIMEDOUT:
                status = S3_STATUS_TIMEOUT;
                break;
            case CURLE_SSL_CONNECT_ERROR:
            case CURLE_SSL_CERTPROBLEM:
            case CURLE_SSL_CIPHER:
            case CURLE_SSL_CACERT:
#if LIBCURL_VERSION_NUM < 0x073E00
            case CURLE_SSL_CACERT_BADFILE:
#endif
                status = S3_STATUS_SSL_ERROR;
                break;
            case CURLE_ABORTED_BY_CALLBACK:
                status = S3_STATUS_ABORTED_BY_CALLBACK;
                break;
            default:
                status = S3_STATUS_CURL_ERROR;
                break;
            }
        }

        /* Check if we should retry */
        if (attempt + 1 < max_attempts && s3__should_retry(c, status, attempt)) {
            int delay = s3__retry_delay_ms(c, attempt);
            S3_LOG_WARN_(c, "Request failed (status=%d), retrying in %d ms", status, delay);
            sleep_ms(delay);
        } else {
            break;
        }
    }

    /* (i) Clean up header list */
    curl_slist_free_all(headers);

    /* (j) Return final status */
    return status;
}
