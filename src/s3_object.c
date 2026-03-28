/*
 * libs3 -- Core object CRUD operations
 *
 * Implements: put, get, head, delete, copy, rename, batch delete,
 * and get-object-attributes.
 */

#define _POSIX_C_SOURCE 200809L
#include "s3_internal.h"
#include <inttypes.h>
#include <strings.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Local Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Append a single "Name: Value" header to a curl_slist.
 * Returns the (possibly new) list head.
 */
static struct curl_slist *add_header(struct curl_slist *h,
                                     const char *name, const char *value)
{
    char buf[16384];
    snprintf(buf, sizeof(buf), "%s: %s", name, value);
    return curl_slist_append(h, buf);
}

/*
 * Append a header only if `value` is non-null and non-empty.
 */
static struct curl_slist *add_header_if(struct curl_slist *h,
                                        const char *name, const char *value)
{
    if (value && value[0])
        return add_header(h, name, value);
    return h;
}

/*
 * Return the S3 checksum algorithm header value string.
 */
static const char *checksum_algorithm_string(s3_checksum_algorithm alg)
{
    switch (alg) {
    case S3_CHECKSUM_CRC32:  return "CRC32";
    case S3_CHECKSUM_CRC32C: return "CRC32C";
    case S3_CHECKSUM_SHA1:   return "SHA1";
    case S3_CHECKSUM_SHA256: return "SHA256";
    default:                 return nullptr;
    }
}

/*
 * Return the lock mode string for x-amz-object-lock-mode.
 */
static const char *lock_mode_string(s3_object_lock_mode mode)
{
    switch (mode) {
    case S3_LOCK_GOVERNANCE: return "GOVERNANCE";
    case S3_LOCK_COMPLIANCE: return "COMPLIANCE";
    default:                 return nullptr;
    }
}

/*
 * Return the legal hold string for x-amz-object-lock-legal-hold.
 */
static const char *legal_hold_string(s3_object_lock_legal_hold hold)
{
    switch (hold) {
    case S3_LEGAL_HOLD_ON: return "ON";
    default:               return nullptr;
    }
}

/*
 * Parse an s3_object_lock_mode from a string.
 */
static s3_object_lock_mode lock_mode_from_string(const char *s)
{
    if (!s || !s[0]) return S3_LOCK_NONE;
    if (strcasecmp(s, "GOVERNANCE") == 0) return S3_LOCK_GOVERNANCE;
    if (strcasecmp(s, "COMPLIANCE") == 0) return S3_LOCK_COMPLIANCE;
    return S3_LOCK_NONE;
}

/*
 * Parse an s3_object_lock_legal_hold from a string.
 */
static s3_object_lock_legal_hold legal_hold_from_string(const char *s)
{
    if (!s || !s[0]) return S3_LEGAL_HOLD_OFF;
    if (strcasecmp(s, "ON") == 0) return S3_LEGAL_HOLD_ON;
    return S3_LEGAL_HOLD_OFF;
}

/*
 * Safely copy a C string into a fixed-size buffer.
 */
static void copy_str(char *dst, size_t dst_size, const char *src)
{
    if (!src || !src[0]) {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Copy from an XML value (pointer + length) into a fixed-size buffer.
 */
static void copy_xml_val(char *dst, size_t dst_size,
                         const char *val, size_t val_len)
{
    if (val_len >= dst_size) val_len = dst_size - 1;
    memcpy(dst, val, val_len);
    dst[val_len] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Build common PUT-object headers from s3_put_object_opts
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *build_put_headers(struct curl_slist *headers,
                                            const s3_put_object_opts *opts)
{
    if (!opts) return headers;

    headers = add_header_if(headers, "Content-Type", opts->content_type);
    headers = add_header_if(headers, "Cache-Control", opts->cache_control);
    headers = add_header_if(headers, "Content-Disposition", opts->content_disposition);
    headers = add_header_if(headers, "Content-Encoding", opts->content_encoding);
    headers = add_header_if(headers, "Content-Language", opts->content_language);
    headers = add_header_if(headers, "Expires", opts->expires);

    if (opts->storage_class != S3_STORAGE_CLASS_STANDARD) {
        headers = add_header(headers, "x-amz-storage-class",
                             s3__storage_class_string(opts->storage_class));
    }

    if (opts->acl != S3_ACL_PRIVATE) {
        headers = add_header(headers, "x-amz-acl",
                             s3__canned_acl_string(opts->acl));
    }

    headers = add_header_if(headers, "x-amz-tagging", opts->tagging);

    /* User metadata */
    for (int i = 0; i < opts->metadata_count; i++) {
        if (!opts->metadata[i].key || !opts->metadata[i].value) continue;
        char hdr[1024];
        snprintf(hdr, sizeof(hdr), "x-amz-meta-%s: %s",
                 opts->metadata[i].key, opts->metadata[i].value);
        headers = curl_slist_append(headers, hdr);
    }

    /* Object Lock */
    const char *lm = lock_mode_string(opts->lock_mode);
    if (lm) headers = add_header(headers, "x-amz-object-lock-mode", lm);
    headers = add_header_if(headers, "x-amz-object-lock-retain-until-date",
                            opts->lock_retain_until);
    const char *lh = legal_hold_string(opts->legal_hold);
    if (lh) headers = add_header(headers, "x-amz-object-lock-legal-hold", lh);

    headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                            opts->expected_bucket_owner);

    if (opts->request_payer)
        headers = add_header(headers, "x-amz-request-payer", "requester");

    /* SSE */
    headers = s3__apply_sse_headers(headers, &opts->encryption);

    /* Checksum */
    if (opts->checksum.algorithm != S3_CHECKSUM_NONE) {
        const char *alg = checksum_algorithm_string(opts->checksum.algorithm);
        if (alg) {
            headers = add_header(headers, "x-amz-checksum-algorithm", alg);
            if (opts->checksum.value && opts->checksum.value[0]) {
                char hn[64];
                snprintf(hn, sizeof(hn), "x-amz-checksum-%s", alg);
                /* Convert algorithm name to lowercase for the header */
                for (char *p = hn + strlen("x-amz-checksum-"); *p; p++)
                    *p = (char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
                headers = add_header(headers, hn, opts->checksum.value);
            }
        }
    }

    return headers;
}

/*
 * Populate s3_put_object_result from client response headers.
 */
static void fill_put_result(const s3_client *c, s3_put_object_result *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
    copy_str(r->etag,             sizeof(r->etag),             c->resp_etag);
    copy_str(r->version_id,       sizeof(r->version_id),       c->resp_version_id);
    copy_str(r->checksum_crc32,   sizeof(r->checksum_crc32),   c->resp_checksum_crc32);
    copy_str(r->checksum_crc32c,  sizeof(r->checksum_crc32c),  c->resp_checksum_crc32c);
    copy_str(r->checksum_sha1,    sizeof(r->checksum_sha1),    c->resp_checksum_sha1);
    copy_str(r->checksum_sha256,  sizeof(r->checksum_sha256),  c->resp_checksum_sha256);
    copy_str(r->request_id,       sizeof(r->request_id),       c->resp_request_id);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Build common GET / HEAD headers from option structs
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *build_get_headers(struct curl_slist *headers,
                                            const s3_get_object_opts *opts)
{
    if (!opts) return headers;

    headers = add_header_if(headers, "Range", opts->range);
    headers = add_header_if(headers, "If-Match", opts->if_match);
    headers = add_header_if(headers, "If-None-Match", opts->if_none_match);
    headers = add_header_if(headers, "If-Modified-Since", opts->if_modified_since);
    headers = add_header_if(headers, "If-Unmodified-Since", opts->if_unmodified_since);

    if (opts->checksum_mode != S3_CHECKSUM_NONE)
        headers = add_header(headers, "x-amz-checksum-mode", "ENABLED");

    headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                            opts->expected_bucket_owner);

    if (opts->request_payer)
        headers = add_header(headers, "x-amz-request-payer", "requester");

    /* SSE-C for reading encrypted objects */
    if (opts->encryption.mode == S3_SSE_C)
        headers = s3__apply_sse_headers(headers, &opts->encryption);

    return headers;
}

static void build_get_query(const s3_get_object_opts *opts,
                            char *query, size_t query_size)
{
    query[0] = '\0';
    if (!opts) return;

    char *p = query;
    size_t remaining = query_size;
    int n;

    if (opts->version_id && opts->version_id[0]) {
        n = snprintf(p, remaining, "versionId=%s", opts->version_id);
        if (n > 0 && (size_t)n < remaining) { p += n; remaining -= (size_t)n; }
    }

    if (opts->part_number > 0) {
        n = snprintf(p, remaining, "%spartNumber=%d",
                     (p != query) ? "&" : "", opts->part_number);
        if (n > 0 && (size_t)n < remaining) { p += n; remaining -= (size_t)n; }
    }

    (void)p;
    (void)remaining;
}

static struct curl_slist *build_head_headers(struct curl_slist *headers,
                                             const s3_head_object_opts *opts)
{
    if (!opts) return headers;

    headers = add_header_if(headers, "If-Match", opts->if_match);
    headers = add_header_if(headers, "If-None-Match", opts->if_none_match);
    headers = add_header_if(headers, "If-Modified-Since", opts->if_modified_since);
    headers = add_header_if(headers, "If-Unmodified-Since", opts->if_unmodified_since);

    if (opts->checksum_mode != S3_CHECKSUM_NONE)
        headers = add_header(headers, "x-amz-checksum-mode", "ENABLED");

    headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                            opts->expected_bucket_owner);

    if (opts->request_payer)
        headers = add_header(headers, "x-amz-request-payer", "requester");

    if (opts->encryption.mode == S3_SSE_C)
        headers = s3__apply_sse_headers(headers, &opts->encryption);

    return headers;
}

static void build_head_query(const s3_head_object_opts *opts,
                             char *query, size_t query_size)
{
    query[0] = '\0';
    if (!opts) return;

    char *p = query;
    size_t remaining = query_size;
    int n;

    if (opts->version_id && opts->version_id[0]) {
        n = snprintf(p, remaining, "versionId=%s", opts->version_id);
        if (n > 0 && (size_t)n < remaining) { p += n; remaining -= (size_t)n; }
    }

    if (opts->part_number > 0) {
        n = snprintf(p, remaining, "%spartNumber=%d",
                     (p != query) ? "&" : "", opts->part_number);
        if (n > 0 && (size_t)n < remaining) { p += n; remaining -= (size_t)n; }
    }

    (void)p;
    (void)remaining;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_put_object
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_put_object(s3_client *c, const char *bucket, const char *key,
                        const void *data, size_t data_len,
                        const s3_put_object_opts *opts,
                        s3_put_object_result *result)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *headers = nullptr;
    headers = build_put_headers(headers, opts);

    s3_request_params params = {
        .method          = "PUT",
        .bucket          = bucket,
        .key             = key,
        .extra_headers   = headers,
        .upload_data     = data,
        .upload_len      = data_len,
        .content_length  = -1,
        .progress_fn     = opts ? opts->progress_fn : nullptr,
        .progress_userdata = opts ? opts->progress_userdata : nullptr,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status == S3_STATUS_OK)
        fill_put_result(c, result);

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_put_object_stream
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_put_object_stream(s3_client *c, const char *bucket, const char *key,
                               s3_read_fn read_fn, void *userdata,
                               int64_t content_length,
                               const s3_put_object_opts *opts,
                               s3_put_object_result *result)
{
    if (!c || !bucket || !key || !read_fn)
        return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *headers = nullptr;
    headers = build_put_headers(headers, opts);

    s3_request_params params = {
        .method          = "PUT",
        .bucket          = bucket,
        .key             = key,
        .extra_headers   = headers,
        .read_fn         = read_fn,
        .read_userdata   = userdata,
        .content_length  = content_length,
        .progress_fn     = opts ? opts->progress_fn : nullptr,
        .progress_userdata = opts ? opts->progress_userdata : nullptr,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status == S3_STATUS_OK)
        fill_put_result(c, result);

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_object
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_object(s3_client *c, const char *bucket, const char *key,
                        void **data_out, size_t *data_len_out,
                        const s3_get_object_opts *opts)
{
    if (!c || !bucket || !key || !data_out || !data_len_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *data_out = nullptr;
    *data_len_out = 0;

    char query[512];
    build_get_query(opts, query, sizeof(query));

    struct curl_slist *headers = nullptr;
    headers = build_get_headers(headers, opts);

    s3_request_params params = {
        .method            = "GET",
        .bucket            = bucket,
        .key               = key,
        .query_string      = query[0] ? query : nullptr,
        .extra_headers     = headers,
        .content_length    = -1,
        .collect_response  = true,
        .progress_fn       = opts ? opts->progress_fn : nullptr,
        .progress_userdata = opts ? opts->progress_userdata : nullptr,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status == S3_STATUS_OK && c->response.len > 0) {
        void *buf = S3_MALLOC(c->response.len);
        if (!buf) return S3_STATUS_OUT_OF_MEMORY;
        memcpy(buf, c->response.data, c->response.len);
        *data_out = buf;
        *data_len_out = c->response.len;
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_object_stream
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_object_stream(s3_client *c, const char *bucket, const char *key,
                               s3_write_fn write_fn, void *userdata,
                               const s3_get_object_opts *opts)
{
    if (!c || !bucket || !key || !write_fn)
        return S3_STATUS_INVALID_ARGUMENT;

    char query[512];
    build_get_query(opts, query, sizeof(query));

    struct curl_slist *headers = nullptr;
    headers = build_get_headers(headers, opts);

    s3_request_params params = {
        .method          = "GET",
        .bucket          = bucket,
        .key             = key,
        .query_string    = query[0] ? query : nullptr,
        .extra_headers   = headers,
        .content_length  = -1,
        .write_fn        = write_fn,
        .write_userdata  = userdata,
        .progress_fn     = opts ? opts->progress_fn : nullptr,
        .progress_userdata = opts ? opts->progress_userdata : nullptr,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_head_object
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_head_object(s3_client *c, const char *bucket, const char *key,
                         const s3_head_object_opts *opts,
                         s3_head_object_result *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char query[512];
    build_head_query(opts, query, sizeof(query));

    struct curl_slist *headers = nullptr;
    headers = build_head_headers(headers, opts);

    s3_request_params params = {
        .method        = "HEAD",
        .bucket        = bucket,
        .key           = key,
        .query_string  = query[0] ? query : nullptr,
        .extra_headers = headers,
        .content_length = -1,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    /* Populate result from response headers captured by the header callback */
    result->content_length = c->resp_content_length;
    copy_str(result->content_type,          sizeof(result->content_type),          c->resp_content_type);
    copy_str(result->content_encoding,      sizeof(result->content_encoding),      c->resp_content_encoding);
    copy_str(result->content_language,      sizeof(result->content_language),      c->resp_content_language);
    copy_str(result->content_disposition,   sizeof(result->content_disposition),   c->resp_content_disposition);
    copy_str(result->cache_control,         sizeof(result->cache_control),         c->resp_cache_control);
    copy_str(result->etag,                  sizeof(result->etag),                  c->resp_etag);
    copy_str(result->last_modified,         sizeof(result->last_modified),         c->resp_last_modified);
    copy_str(result->storage_class,         sizeof(result->storage_class),         c->resp_storage_class);
    copy_str(result->version_id,            sizeof(result->version_id),            c->resp_version_id);
    copy_str(result->expiration,            sizeof(result->expiration),            c->resp_expiration);
    copy_str(result->restore,               sizeof(result->restore),              c->resp_restore);
    copy_str(result->replication_status,    sizeof(result->replication_status),    c->resp_replication_status);
    result->parts_count = c->resp_parts_count;
    copy_str(result->server_side_encryption,  sizeof(result->server_side_encryption), c->resp_server_side_encryption);
    copy_str(result->sse_kms_key_id,          sizeof(result->sse_kms_key_id),         c->resp_sse_kms_key_id);
    copy_str(result->sse_customer_algorithm,  sizeof(result->sse_customer_algorithm),  c->resp_sse_customer_algorithm);
    copy_str(result->sse_customer_key_md5,    sizeof(result->sse_customer_key_md5),    c->resp_sse_customer_key_md5);
    result->bucket_key_enabled = c->resp_bucket_key_enabled;
    result->delete_marker      = c->resp_delete_marker;

    result->lock_mode    = lock_mode_from_string(c->resp_lock_mode);
    copy_str(result->lock_retain_until, sizeof(result->lock_retain_until), c->resp_lock_retain_until);
    result->legal_hold   = legal_hold_from_string(c->resp_legal_hold);

    copy_str(result->checksum_crc32,    sizeof(result->checksum_crc32),    c->resp_checksum_crc32);
    copy_str(result->checksum_crc32c,   sizeof(result->checksum_crc32c),   c->resp_checksum_crc32c);
    copy_str(result->checksum_sha1,     sizeof(result->checksum_sha1),     c->resp_checksum_sha1);
    copy_str(result->checksum_sha256,   sizeof(result->checksum_sha256),   c->resp_checksum_sha256);

    /* Deep-copy user metadata from the client */
    result->metadata = nullptr;
    result->metadata_count = 0;

    if (c->resp_metadata_count > 0) {
        result->metadata = (s3_metadata *)S3_CALLOC(
            (size_t)c->resp_metadata_count, sizeof(s3_metadata));
        if (result->metadata) {
            result->metadata_count = c->resp_metadata_count;
            for (int i = 0; i < c->resp_metadata_count; i++) {
                result->metadata[i].key   = s3__strdup(c->resp_metadata[i].key);
                result->metadata[i].value = s3__strdup(c->resp_metadata[i].value);
            }
        }
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_head_object_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_head_object_result_free(s3_head_object_result *r)
{
    if (!r) return;
    if (r->metadata) {
        for (int i = 0; i < r->metadata_count; i++) {
            S3_FREE((void *)r->metadata[i].key);
            S3_FREE((void *)r->metadata[i].value);
        }
        S3_FREE(r->metadata);
        r->metadata = nullptr;
    }
    r->metadata_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_object
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_object(s3_client *c, const char *bucket, const char *key,
                           const s3_delete_object_opts *opts,
                           s3_delete_object_result *result)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Query string */
    char query[512] = "";
    if (opts && opts->version_id && opts->version_id[0])
        snprintf(query, sizeof(query), "versionId=%s", opts->version_id);

    /* Headers */
    struct curl_slist *headers = nullptr;
    if (opts) {
        headers = add_header_if(headers, "x-amz-mfa", opts->mfa);
        headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                                opts->expected_bucket_owner);
        if (opts->request_payer)
            headers = add_header(headers, "x-amz-request-payer", "requester");
    }

    s3_request_params params = {
        .method        = "DELETE",
        .bucket        = bucket,
        .key           = key,
        .query_string  = query[0] ? query : nullptr,
        .extra_headers = headers,
        .content_length = -1,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status == S3_STATUS_OK && result) {
        memset(result, 0, sizeof(*result));
        result->delete_marker = c->resp_delete_marker;
        copy_str(result->version_id, sizeof(result->version_id), c->resp_version_id);
        copy_str(result->request_id, sizeof(result->request_id), c->resp_request_id);
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_objects  (batch / multi-object delete)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Callback context for parsing <Deleted> elements.
 */
typedef struct {
    s3_deleted_object *items;
    int                count;
    int                cap;
} deleted_parse_ctx;

static int parse_deleted_cb(const char *element, size_t element_len, void *userdata)
{
    deleted_parse_ctx *ctx = (deleted_parse_ctx *)userdata;

    /* Grow array if needed */
    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        s3_deleted_object *p = (s3_deleted_object *)S3_REALLOC(
            ctx->items, (size_t)new_cap * sizeof(s3_deleted_object));
        if (!p) return -1;
        ctx->items = p;
        ctx->cap = new_cap;
    }

    s3_deleted_object *d = &ctx->items[ctx->count];
    memset(d, 0, sizeof(*d));

    const char *val;
    size_t val_len;

    if (s3__xml_find(element, element_len, "Key", &val, &val_len))
        s3__xml_decode_entities(val, val_len, d->key, sizeof(d->key));

    if (s3__xml_find(element, element_len, "VersionId", &val, &val_len))
        copy_xml_val(d->version_id, sizeof(d->version_id), val, val_len);

    if (s3__xml_find(element, element_len, "DeleteMarker", &val, &val_len))
        d->delete_marker = (val_len >= 4 && strncasecmp(val, "true", 4) == 0);

    if (s3__xml_find(element, element_len, "DeleteMarkerVersionId", &val, &val_len))
        copy_xml_val(d->delete_marker_version_id, sizeof(d->delete_marker_version_id),
                     val, val_len);

    ctx->count++;
    return 0;
}

/*
 * Callback context for parsing <Error> elements.
 */
typedef struct {
    s3_delete_error *items;
    int              count;
    int              cap;
} error_parse_ctx;

static int parse_error_cb(const char *element, size_t element_len, void *userdata)
{
    error_parse_ctx *ctx = (error_parse_ctx *)userdata;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        s3_delete_error *p = (s3_delete_error *)S3_REALLOC(
            ctx->items, (size_t)new_cap * sizeof(s3_delete_error));
        if (!p) return -1;
        ctx->items = p;
        ctx->cap = new_cap;
    }

    s3_delete_error *e = &ctx->items[ctx->count];
    memset(e, 0, sizeof(*e));

    const char *val;
    size_t val_len;

    if (s3__xml_find(element, element_len, "Key", &val, &val_len))
        s3__xml_decode_entities(val, val_len, e->key, sizeof(e->key));

    if (s3__xml_find(element, element_len, "VersionId", &val, &val_len))
        copy_xml_val(e->version_id, sizeof(e->version_id), val, val_len);

    if (s3__xml_find(element, element_len, "Code", &val, &val_len))
        copy_xml_val(e->code, sizeof(e->code), val, val_len);

    if (s3__xml_find(element, element_len, "Message", &val, &val_len))
        s3__xml_decode_entities(val, val_len, e->message, sizeof(e->message));

    ctx->count++;
    return 0;
}

s3_status s3_delete_objects(s3_client *c, const char *bucket,
                            const s3_delete_object_entry *entries, int entry_count,
                            bool quiet,
                            s3_delete_objects_result *result)
{
    if (!c || !bucket || !entries || entry_count <= 0 || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);

    if (s3__xml_buf_declaration(&body) < 0) goto oom;
    if (s3__xml_buf_open(&body, "Delete") < 0) goto oom;
    if (s3__xml_buf_element_bool(&body, "Quiet", quiet) < 0) goto oom;

    for (int i = 0; i < entry_count; i++) {
        if (!entries[i].key) continue;
        if (s3__xml_buf_open(&body, "Object") < 0) goto oom;
        if (s3__xml_buf_element(&body, "Key", entries[i].key) < 0) goto oom;
        if (entries[i].version_id && entries[i].version_id[0]) {
            if (s3__xml_buf_element(&body, "VersionId", entries[i].version_id) < 0)
                goto oom;
        }
        if (s3__xml_buf_close(&body, "Object") < 0) goto oom;
    }

    if (s3__xml_buf_close(&body, "Delete") < 0) goto oom;

    /* Compute SHA-256 of the body for x-amz-content-sha256 (s3__request does
     * this automatically for upload_data, so we just pass the body through). */

    /* Headers: Content-Type is XML */
    struct curl_slist *headers = nullptr;
    headers = add_header(headers, "Content-Type", "application/xml");

    /* S3 requires Content-MD5 for DeleteObjects. */
    {
        uint8_t md5[16];
        s3__md5(body.data, body.len, md5);
        char md5_b64[32];
        s3__base64_encode(md5, 16, md5_b64, sizeof(md5_b64));
        headers = add_header(headers, "Content-MD5", md5_b64);
        fprintf(stderr, "[DEBUG] Content-MD5: %s (body_len=%zu)\n", md5_b64, body.len);
    }

    s3_request_params params = {
        .method            = "POST",
        .bucket            = bucket,
        .query_string      = "delete",
        .extra_headers     = headers,
        .upload_data       = body.data,
        .upload_len        = body.len,
        .collect_response  = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);
    s3_buf_free(&body);

    if (status != S3_STATUS_OK)
        return status;

    /* Parse response XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    if (!xml || xml_len == 0)
        return S3_STATUS_OK;

    /* Parse <Deleted> elements */
    deleted_parse_ctx dctx = {0};
    s3__xml_each(xml, xml_len, "Deleted", parse_deleted_cb, &dctx);
    result->deleted       = dctx.items;
    result->deleted_count = dctx.count;

    /* Parse <Error> elements */
    error_parse_ctx ectx = {0};
    s3__xml_each(xml, xml_len, "Error", parse_error_cb, &ectx);
    result->errors      = ectx.items;
    result->error_count = ectx.count;

    return S3_STATUS_OK;

oom:
    s3_buf_free(&body);
    return S3_STATUS_OUT_OF_MEMORY;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_objects_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_delete_objects_result_free(s3_delete_objects_result *r)
{
    if (!r) return;
    S3_FREE(r->deleted);
    r->deleted = nullptr;
    r->deleted_count = 0;
    S3_FREE(r->errors);
    r->errors = nullptr;
    r->error_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_copy_object
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_copy_object(s3_client *c,
                         const char *src_bucket, const char *src_key,
                         const char *dst_bucket, const char *dst_key,
                         const s3_copy_object_opts *opts,
                         s3_copy_object_result *result)
{
    if (!c || !src_bucket || !src_key || !dst_bucket || !dst_key)
        return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *headers = nullptr;

    /* x-amz-copy-source: /{bucket}/{key}[?versionId=...] */
    {
        /* URI-encode the source key (preserving slashes) */
        char encoded_key[4096];
        s3__uri_encode_path(src_key, strlen(src_key),
                            encoded_key, sizeof(encoded_key));

        char copy_source[8192];
        if (opts && opts->version_id && opts->version_id[0]) {
            snprintf(copy_source, sizeof(copy_source),
                     "/%s/%s?versionId=%s", src_bucket, encoded_key,
                     opts->version_id);
        } else {
            snprintf(copy_source, sizeof(copy_source),
                     "/%s/%s", src_bucket, encoded_key);
        }
        headers = add_header(headers, "x-amz-copy-source", copy_source);
    }

    if (opts) {
        /* Metadata directive */
        if (opts->metadata_directive == S3_METADATA_REPLACE)
            headers = add_header(headers, "x-amz-metadata-directive", "REPLACE");

        /* Tagging directive */
        if (opts->tagging_directive == S3_TAGGING_REPLACE)
            headers = add_header(headers, "x-amz-tagging-directive", "REPLACE");

        /* Destination headers */
        headers = add_header_if(headers, "Content-Type", opts->content_type);

        if (opts->storage_class != S3_STORAGE_CLASS_STANDARD) {
            headers = add_header(headers, "x-amz-storage-class",
                                 s3__storage_class_string(opts->storage_class));
        }

        if (opts->acl != S3_ACL_PRIVATE) {
            headers = add_header(headers, "x-amz-acl",
                                 s3__canned_acl_string(opts->acl));
        }

        headers = add_header_if(headers, "x-amz-tagging", opts->tagging);

        /* User metadata */
        for (int i = 0; i < opts->metadata_count; i++) {
            if (!opts->metadata[i].key || !opts->metadata[i].value) continue;
            char hdr[1024];
            snprintf(hdr, sizeof(hdr), "x-amz-meta-%s: %s",
                     opts->metadata[i].key, opts->metadata[i].value);
            headers = curl_slist_append(headers, hdr);
        }

        /* Object Lock */
        const char *lm = lock_mode_string(opts->lock_mode);
        if (lm) headers = add_header(headers, "x-amz-object-lock-mode", lm);
        headers = add_header_if(headers, "x-amz-object-lock-retain-until-date",
                                opts->lock_retain_until);
        const char *lh = legal_hold_string(opts->legal_hold);
        if (lh) headers = add_header(headers, "x-amz-object-lock-legal-hold", lh);

        /* Conditional headers on source */
        headers = add_header_if(headers, "x-amz-copy-source-if-match",
                                opts->if_match);
        headers = add_header_if(headers, "x-amz-copy-source-if-none-match",
                                opts->if_none_match);
        headers = add_header_if(headers, "x-amz-copy-source-if-modified-since",
                                opts->if_modified_since);
        headers = add_header_if(headers, "x-amz-copy-source-if-unmodified-since",
                                opts->if_unmodified_since);

        headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                                opts->expected_bucket_owner);
        headers = add_header_if(headers, "x-amz-source-expected-bucket-owner",
                                opts->expected_source_bucket_owner);

        if (opts->request_payer)
            headers = add_header(headers, "x-amz-request-payer", "requester");

        /* Destination SSE */
        headers = s3__apply_sse_headers(headers, &opts->encryption);

        /* Source SSE-C */
        headers = s3__apply_source_sse_headers(headers, &opts->source_encryption);
    }

    s3_request_params params = {
        .method           = "PUT",
        .bucket           = dst_bucket,
        .key              = dst_key,
        .extra_headers    = headers,
        .content_length   = -1,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    /* Parse the CopyObjectResult XML response */
    if (result) {
        memset(result, 0, sizeof(*result));

        const char *xml = c->response.data;
        size_t xml_len = c->response.len;

        if (xml && xml_len > 0) {
            const char *val;
            size_t val_len;

            if (s3__xml_find(xml, xml_len, "ETag", &val, &val_len))
                copy_xml_val(result->etag, sizeof(result->etag), val, val_len);

            if (s3__xml_find(xml, xml_len, "LastModified", &val, &val_len))
                copy_xml_val(result->last_modified, sizeof(result->last_modified),
                             val, val_len);
        }

        /* Version ID and request ID come from response headers */
        copy_str(result->version_id, sizeof(result->version_id),
                 c->resp_version_id);
        copy_str(result->request_id, sizeof(result->request_id),
                 c->resp_request_id);
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_rename_object — copy + delete
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_rename_object(s3_client *c, const char *bucket,
                           const char *src_key, const char *dst_key)
{
    if (!c || !bucket || !src_key || !dst_key)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Step 1: Copy source to destination within the same bucket */
    s3_status status = s3_copy_object(c, bucket, src_key,
                                      bucket, dst_key,
                                      nullptr, nullptr);
    if (status != S3_STATUS_OK)
        return status;

    /* Step 2: Delete the source object */
    status = s3_delete_object(c, bucket, src_key, nullptr, nullptr);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_object_attributes
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Callback for parsing <Part> elements within <ObjectParts>.
 */
typedef struct {
    s3_part_info *items;
    int           count;
    int           cap;
} parts_parse_ctx;

static int parse_part_cb(const char *element, size_t element_len, void *userdata)
{
    parts_parse_ctx *ctx = (parts_parse_ctx *)userdata;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        s3_part_info *p = (s3_part_info *)S3_REALLOC(
            ctx->items, (size_t)new_cap * sizeof(s3_part_info));
        if (!p) return -1;
        ctx->items = p;
        ctx->cap = new_cap;
    }

    s3_part_info *pi = &ctx->items[ctx->count];
    memset(pi, 0, sizeof(*pi));

    const char *val;
    size_t val_len;

    if (s3__xml_find(element, element_len, "PartNumber", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        pi->part_number = (int)strtol(tmp, nullptr, 10);
    }

    if (s3__xml_find(element, element_len, "Size", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        pi->size = strtoll(tmp, nullptr, 10);
    }

    if (s3__xml_find(element, element_len, "ChecksumCRC32", &val, &val_len))
        copy_xml_val(pi->checksum_crc32, sizeof(pi->checksum_crc32), val, val_len);
    if (s3__xml_find(element, element_len, "ChecksumCRC32C", &val, &val_len))
        copy_xml_val(pi->checksum_crc32c, sizeof(pi->checksum_crc32c), val, val_len);
    if (s3__xml_find(element, element_len, "ChecksumSHA1", &val, &val_len))
        copy_xml_val(pi->checksum_sha1, sizeof(pi->checksum_sha1), val, val_len);
    if (s3__xml_find(element, element_len, "ChecksumSHA256", &val, &val_len))
        copy_xml_val(pi->checksum_sha256, sizeof(pi->checksum_sha256), val, val_len);

    ctx->count++;
    return 0;
}

s3_status s3_get_object_attributes(s3_client *c, const char *bucket, const char *key,
                                   const s3_get_object_attributes_opts *opts,
                                   s3_object_attributes_result *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Query string */
    char query[512] = "attributes";
    if (opts && opts->version_id && opts->version_id[0]) {
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "attributes&versionId=%s", opts->version_id);
        memcpy(query, tmp, strlen(tmp) + 1);
    }

    /* Build x-amz-object-attributes header */
    struct curl_slist *headers = nullptr;

    if (opts) {
        char attr_buf[256] = "";
        char *p = attr_buf;
        size_t rem = sizeof(attr_buf);
        bool first = true;

#define APPEND_ATTR(flag, name) do { \
    if (flag) { \
        int n = snprintf(p, rem, "%s%s", first ? "" : ",", name); \
        if (n > 0 && (size_t)n < rem) { p += n; rem -= (size_t)n; first = false; } \
    } \
} while (0)

        APPEND_ATTR(opts->attr_etag,         "ETag");
        APPEND_ATTR(opts->attr_checksum,     "Checksum");
        APPEND_ATTR(opts->attr_object_parts, "ObjectParts");
        APPEND_ATTR(opts->attr_storage_class,"StorageClass");
        APPEND_ATTR(opts->attr_object_size,  "ObjectSize");

#undef APPEND_ATTR

        if (attr_buf[0])
            headers = add_header(headers, "x-amz-object-attributes", attr_buf);

        if (opts->max_parts > 0) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%d", opts->max_parts);
            headers = add_header(headers, "x-amz-max-parts", tmp);
        }

        if (opts->part_number_marker > 0) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%d", opts->part_number_marker);
            headers = add_header(headers, "x-amz-part-number-marker", tmp);
        }

        headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                                opts->expected_bucket_owner);

        if (opts->request_payer)
            headers = add_header(headers, "x-amz-request-payer", "requester");

        if (opts->encryption.mode == S3_SSE_C)
            headers = s3__apply_sse_headers(headers, &opts->encryption);
    }

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .key              = key,
        .query_string     = query,
        .extra_headers    = headers,
        .content_length   = -1,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    /* Parse the GetObjectAttributesResponse XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0)
        return S3_STATUS_OK;

    const char *val;
    size_t val_len;

    if (s3__xml_find(xml, xml_len, "ETag", &val, &val_len))
        copy_xml_val(result->etag, sizeof(result->etag), val, val_len);

    if (s3__xml_find(xml, xml_len, "ObjectSize", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->object_size = strtoll(tmp, nullptr, 10);
    }

    if (s3__xml_find(xml, xml_len, "StorageClass", &val, &val_len))
        copy_xml_val(result->storage_class, sizeof(result->storage_class),
                     val, val_len);

    /* Checksum */
    if (s3__xml_find_in(xml, xml_len, "Checksum", "ChecksumCRC32", &val, &val_len))
        copy_xml_val(result->checksum_crc32, sizeof(result->checksum_crc32),
                     val, val_len);
    if (s3__xml_find_in(xml, xml_len, "Checksum", "ChecksumCRC32C", &val, &val_len))
        copy_xml_val(result->checksum_crc32c, sizeof(result->checksum_crc32c),
                     val, val_len);
    if (s3__xml_find_in(xml, xml_len, "Checksum", "ChecksumSHA1", &val, &val_len))
        copy_xml_val(result->checksum_sha1, sizeof(result->checksum_sha1),
                     val, val_len);
    if (s3__xml_find_in(xml, xml_len, "Checksum", "ChecksumSHA256", &val, &val_len))
        copy_xml_val(result->checksum_sha256, sizeof(result->checksum_sha256),
                     val, val_len);

    /* ObjectParts */
    if (s3__xml_find_in(xml, xml_len, "ObjectParts", "TotalPartsCount", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->total_parts_count = (int)strtol(tmp, nullptr, 10);
    }

    if (s3__xml_find_in(xml, xml_len, "ObjectParts", "PartNumberMarker", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->part_number_marker = (int)strtol(tmp, nullptr, 10);
    }

    if (s3__xml_find_in(xml, xml_len, "ObjectParts", "NextPartNumberMarker", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->next_part_number_marker = (int)strtol(tmp, nullptr, 10);
    }

    if (s3__xml_find_in(xml, xml_len, "ObjectParts", "MaxParts", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->max_parts = (int)strtol(tmp, nullptr, 10);
    }

    if (s3__xml_find_in(xml, xml_len, "ObjectParts", "IsTruncated", &val, &val_len))
        result->is_truncated = (val_len >= 4 && strncasecmp(val, "true", 4) == 0);

    /* Parse individual <Part> elements within <ObjectParts> */
    const char *parts_val;
    size_t parts_val_len;
    if (s3__xml_find(xml, xml_len, "ObjectParts", &parts_val, &parts_val_len)) {
        /* parts_val points to the content of <ObjectParts>...</ObjectParts> */
        parts_parse_ctx pctx = {0};
        s3__xml_each(parts_val, parts_val_len, "Part", parse_part_cb, &pctx);
        result->parts      = pctx.items;
        result->part_count = pctx.count;
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_object_attributes_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_object_attributes_result_free(s3_object_attributes_result *r)
{
    if (!r) return;
    S3_FREE(r->parts);
    r->parts = nullptr;
    r->part_count = 0;
}
