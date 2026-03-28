/*
 * libs3 -- Multipart upload operations
 *
 * Implements: create, upload-part, upload-part-stream, upload-part-copy,
 * complete, abort, list-parts, list-multipart-uploads, and free helpers.
 */

#define _POSIX_C_SOURCE 200809L
#include "s3_internal.h"
#include <inttypes.h>
#include <strings.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Local Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *add_header(struct curl_slist *h,
                                     const char *name, const char *value)
{
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s: %s", name, value);
    return curl_slist_append(h, buf);
}

static struct curl_slist *add_header_if(struct curl_slist *h,
                                        const char *name, const char *value)
{
    if (value && value[0])
        return add_header(h, name, value);
    return h;
}

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

static const char *lock_mode_string(s3_object_lock_mode mode)
{
    switch (mode) {
    case S3_LOCK_GOVERNANCE: return "GOVERNANCE";
    case S3_LOCK_COMPLIANCE: return "COMPLIANCE";
    default:                 return nullptr;
    }
}

static const char *legal_hold_string(s3_object_lock_legal_hold hold)
{
    switch (hold) {
    case S3_LEGAL_HOLD_ON: return "ON";
    default:               return nullptr;
    }
}

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

static void copy_xml_val(char *dst, size_t dst_size,
                         const char *val, size_t val_len)
{
    if (val_len >= dst_size) val_len = dst_size - 1;
    memcpy(dst, val, val_len);
    dst[val_len] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_multipart_upload
 * POST /{key}?uploads
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_multipart_upload(
    s3_client *c, const char *bucket, const char *key,
    const s3_create_multipart_upload_opts *opts,
    s3_multipart_upload *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    struct curl_slist *headers = nullptr;

    if (opts) {
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

        if (opts->bucket_key_enabled)
            headers = add_header(headers, "x-amz-server-side-encryption-bucket-key-enabled", "true");

        /* SSE */
        headers = s3__apply_sse_headers(headers, &opts->encryption);

        /* Checksum algorithm */
        if (opts->checksum_algorithm != S3_CHECKSUM_NONE) {
            const char *alg = checksum_algorithm_string(opts->checksum_algorithm);
            if (alg)
                headers = add_header(headers, "x-amz-checksum-algorithm", alg);
        }
    }

    s3_request_params params = {
        .method          = "POST",
        .bucket          = bucket,
        .key             = key,
        .query_string    = "uploads",
        .extra_headers   = headers,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    /* Parse InitiateMultipartUploadResult XML for UploadId */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    const char *val;
    size_t val_len;

    if (s3__xml_find(xml, xml_len, "UploadId", &val, &val_len))
        copy_xml_val(result->upload_id, sizeof(result->upload_id), val, val_len);

    copy_str(result->key, sizeof(result->key), key);
    copy_str(result->bucket, sizeof(result->bucket), bucket);

    S3_LOG_DEBUG_(c, "Created multipart upload: %s", result->upload_id);

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Upload part helpers: build headers, fill result
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *build_upload_part_headers(struct curl_slist *headers,
                                                    const s3_upload_part_opts *opts)
{
    if (!opts) return headers;

    /* SSE-C (must match create) */
    if (opts->encryption.mode == S3_SSE_C)
        headers = s3__apply_sse_headers(headers, &opts->encryption);

    /* Checksum */
    if (opts->checksum.algorithm != S3_CHECKSUM_NONE) {
        const char *alg = checksum_algorithm_string(opts->checksum.algorithm);
        if (alg) {
            headers = add_header(headers, "x-amz-checksum-algorithm", alg);
            if (opts->checksum.value && opts->checksum.value[0]) {
                char hn[64];
                snprintf(hn, sizeof(hn), "x-amz-checksum-%s", alg);
                for (char *p = hn + strlen("x-amz-checksum-"); *p; p++)
                    *p = (char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
                headers = add_header(headers, hn, opts->checksum.value);
            }
        }
    }

    headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                            opts->expected_bucket_owner);

    if (opts->request_payer)
        headers = add_header(headers, "x-amz-request-payer", "requester");

    return headers;
}

static void fill_upload_part_result(const s3_client *c, int part_number,
                                    s3_upload_part_result *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->part_number = part_number;
    copy_str(r->etag,             sizeof(r->etag),             c->resp_etag);
    copy_str(r->checksum_crc32,   sizeof(r->checksum_crc32),   c->resp_checksum_crc32);
    copy_str(r->checksum_crc32c,  sizeof(r->checksum_crc32c),  c->resp_checksum_crc32c);
    copy_str(r->checksum_sha1,    sizeof(r->checksum_sha1),    c->resp_checksum_sha1);
    copy_str(r->checksum_sha256,  sizeof(r->checksum_sha256),  c->resp_checksum_sha256);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_upload_part
 * PUT /{key}?partNumber=N&uploadId=ID
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_upload_part(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int part_number,
    const void *data, size_t data_len,
    const s3_upload_part_opts *opts,
    s3_upload_part_result *result)
{
    if (!c || !bucket || !key || !upload_id || part_number < 1)
        return S3_STATUS_INVALID_ARGUMENT;
    if (!data && data_len > 0)
        return S3_STATUS_INVALID_ARGUMENT;

    char query[2048];
    snprintf(query, sizeof(query), "partNumber=%d&uploadId=%s",
             part_number, upload_id);

    struct curl_slist *headers = nullptr;
    headers = build_upload_part_headers(headers, opts);

    s3_request_params params = {
        .method          = "PUT",
        .bucket          = bucket,
        .key             = key,
        .query_string    = query,
        .extra_headers   = headers,
        .upload_data     = data,
        .upload_len      = data_len,
        .progress_fn     = opts ? opts->progress_fn : nullptr,
        .progress_userdata = opts ? opts->progress_userdata : nullptr,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    fill_upload_part_result(c, part_number, result);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_upload_part_stream
 * PUT /{key}?partNumber=N&uploadId=ID with read_fn, UNSIGNED-PAYLOAD
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_upload_part_stream(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int part_number,
    s3_read_fn read_fn, void *userdata, int64_t content_length,
    const s3_upload_part_opts *opts,
    s3_upload_part_result *result)
{
    if (!c || !bucket || !key || !upload_id || part_number < 1 || !read_fn)
        return S3_STATUS_INVALID_ARGUMENT;

    char query[2048];
    snprintf(query, sizeof(query), "partNumber=%d&uploadId=%s",
             part_number, upload_id);

    struct curl_slist *headers = nullptr;
    headers = build_upload_part_headers(headers, opts);

    s3_request_params params = {
        .method          = "PUT",
        .bucket          = bucket,
        .key             = key,
        .query_string    = query,
        .extra_headers   = headers,
        .read_fn         = read_fn,
        .read_userdata   = userdata,
        .content_length  = content_length,
        .progress_fn     = opts ? opts->progress_fn : nullptr,
        .progress_userdata = opts ? opts->progress_userdata : nullptr,
        .collect_response = true,
        .payload_hash    = "UNSIGNED-PAYLOAD",
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    fill_upload_part_result(c, part_number, result);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_upload_part_copy
 * PUT /{key}?partNumber=N&uploadId=ID with x-amz-copy-source
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_upload_part_copy(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int part_number,
    const char *src_bucket, const char *src_key,
    const s3_upload_part_copy_opts *opts,
    s3_upload_part_result *result)
{
    if (!c || !bucket || !key || !upload_id || part_number < 1 ||
        !src_bucket || !src_key)
        return S3_STATUS_INVALID_ARGUMENT;

    char query[2048];
    snprintf(query, sizeof(query), "partNumber=%d&uploadId=%s",
             part_number, upload_id);

    /* Build x-amz-copy-source header: /bucket/key */
    char copy_source[2048];
    snprintf(copy_source, sizeof(copy_source), "/%s/%s", src_bucket, src_key);

    struct curl_slist *headers = nullptr;
    headers = add_header(headers, "x-amz-copy-source", copy_source);

    if (opts) {
        headers = add_header_if(headers, "x-amz-copy-source-range",
                                opts->copy_source_range);
        headers = add_header_if(headers, "x-amz-copy-source-if-match",
                                opts->if_match);
        headers = add_header_if(headers, "x-amz-copy-source-if-none-match",
                                opts->if_none_match);
        headers = add_header_if(headers, "x-amz-copy-source-if-modified-since",
                                opts->if_modified_since);
        headers = add_header_if(headers, "x-amz-copy-source-if-unmodified-since",
                                opts->if_unmodified_since);

        /* Destination SSE-C */
        if (opts->encryption.mode == S3_SSE_C)
            headers = s3__apply_sse_headers(headers, &opts->encryption);

        /* Source SSE-C */
        if (opts->source_encryption.mode == S3_SSE_C)
            headers = s3__apply_source_sse_headers(headers, &opts->source_encryption);

        headers = add_header_if(headers, "x-amz-expected-bucket-owner",
                                opts->expected_bucket_owner);

        if (opts->request_payer)
            headers = add_header(headers, "x-amz-request-payer", "requester");
    }

    s3_request_params params = {
        .method          = "PUT",
        .bucket          = bucket,
        .key             = key,
        .query_string    = query,
        .extra_headers   = headers,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);

    if (status != S3_STATUS_OK)
        return status;

    /* Parse CopyPartResult XML for ETag */
    if (result) {
        memset(result, 0, sizeof(*result));
        result->part_number = part_number;

        const char *xml = c->response.data;
        size_t xml_len = c->response.len;
        const char *val;
        size_t val_len;

        if (s3__xml_find(xml, xml_len, "ETag", &val, &val_len))
            copy_xml_val(result->etag, sizeof(result->etag), val, val_len);

        /* Also pick up checksums from response headers */
        copy_str(result->checksum_crc32,  sizeof(result->checksum_crc32),  c->resp_checksum_crc32);
        copy_str(result->checksum_crc32c, sizeof(result->checksum_crc32c), c->resp_checksum_crc32c);
        copy_str(result->checksum_sha1,   sizeof(result->checksum_sha1),   c->resp_checksum_sha1);
        copy_str(result->checksum_sha256, sizeof(result->checksum_sha256), c->resp_checksum_sha256);
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_complete_multipart_upload
 * POST /{key}?uploadId=ID
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_complete_multipart_upload(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id,
    const s3_upload_part_result *parts, int part_count,
    s3_complete_multipart_result *result)
{
    if (!c || !bucket || !key || !upload_id || !parts || part_count < 1)
        return S3_STATUS_INVALID_ARGUMENT;

    if (result)
        memset(result, 0, sizeof(*result));

    /* Build CompleteMultipartUpload XML body */
    s3_buf body;
    s3_buf_init(&body);

    if (s3__xml_buf_declaration(&body) < 0) goto oom;
    if (s3__xml_buf_open(&body, "CompleteMultipartUpload") < 0) goto oom;

    for (int i = 0; i < part_count; i++) {
        if (s3__xml_buf_open(&body, "Part") < 0) goto oom;
        if (s3__xml_buf_element_int(&body, "PartNumber", parts[i].part_number) < 0) goto oom;
        if (s3__xml_buf_element(&body, "ETag", parts[i].etag) < 0) goto oom;

        /* Include checksum values if present */
        if (parts[i].checksum_crc32[0])
            if (s3__xml_buf_element(&body, "ChecksumCRC32", parts[i].checksum_crc32) < 0) goto oom;
        if (parts[i].checksum_crc32c[0])
            if (s3__xml_buf_element(&body, "ChecksumCRC32C", parts[i].checksum_crc32c) < 0) goto oom;
        if (parts[i].checksum_sha1[0])
            if (s3__xml_buf_element(&body, "ChecksumSHA1", parts[i].checksum_sha1) < 0) goto oom;
        if (parts[i].checksum_sha256[0])
            if (s3__xml_buf_element(&body, "ChecksumSHA256", parts[i].checksum_sha256) < 0) goto oom;

        if (s3__xml_buf_close(&body, "Part") < 0) goto oom;
    }

    if (s3__xml_buf_close(&body, "CompleteMultipartUpload") < 0) goto oom;

    /* Build query string */
    char query[512];
    snprintf(query, sizeof(query), "uploadId=%s", upload_id);

    struct curl_slist *headers = nullptr;
    headers = add_header(headers, "Content-Type", "application/xml");

    s3_request_params params = {
        .method          = "POST",
        .bucket          = bucket,
        .key             = key,
        .query_string    = query,
        .extra_headers   = headers,
        .upload_data     = body.data,
        .upload_len      = body.len,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);
    s3_buf_free(&body);

    if (status != S3_STATUS_OK)
        return status;

    /*
     * IMPORTANT: S3 can return HTTP 200 but with an Error element in the body.
     * Check for this before parsing the success result.
     */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    const char *val;
    size_t val_len;

    if (s3__xml_find(xml, xml_len, "Error", &val, &val_len)) {
        /* There is an Error element -- parse and return error */
        return s3__parse_error_response(c, 200);
    }

    /* Parse CompleteMultipartUploadResult */
    if (result) {
        if (s3__xml_find(xml, xml_len, "Location", &val, &val_len))
            copy_xml_val(result->location, sizeof(result->location), val, val_len);
        if (s3__xml_find(xml, xml_len, "Bucket", &val, &val_len))
            copy_xml_val(result->bucket, sizeof(result->bucket), val, val_len);
        if (s3__xml_find(xml, xml_len, "Key", &val, &val_len))
            copy_xml_val(result->key, sizeof(result->key), val, val_len);
        if (s3__xml_find(xml, xml_len, "ETag", &val, &val_len))
            copy_xml_val(result->etag, sizeof(result->etag), val, val_len);

        /* Checksums from XML */
        if (s3__xml_find(xml, xml_len, "ChecksumCRC32", &val, &val_len))
            copy_xml_val(result->checksum_crc32, sizeof(result->checksum_crc32), val, val_len);
        if (s3__xml_find(xml, xml_len, "ChecksumCRC32C", &val, &val_len))
            copy_xml_val(result->checksum_crc32c, sizeof(result->checksum_crc32c), val, val_len);
        if (s3__xml_find(xml, xml_len, "ChecksumSHA1", &val, &val_len))
            copy_xml_val(result->checksum_sha1, sizeof(result->checksum_sha1), val, val_len);
        if (s3__xml_find(xml, xml_len, "ChecksumSHA256", &val, &val_len))
            copy_xml_val(result->checksum_sha256, sizeof(result->checksum_sha256), val, val_len);

        /* version-id comes from response header */
        copy_str(result->version_id, sizeof(result->version_id), c->resp_version_id);
    }

    return S3_STATUS_OK;

oom:
    s3_buf_free(&body);
    return S3_STATUS_OUT_OF_MEMORY;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_abort_multipart_upload
 * DELETE /{key}?uploadId=ID
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_abort_multipart_upload(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id)
{
    if (!c || !bucket || !key || !upload_id)
        return S3_STATUS_INVALID_ARGUMENT;

    char query[512];
    snprintf(query, sizeof(query), "uploadId=%s", upload_id);

    s3_request_params params = {
        .method       = "DELETE",
        .bucket       = bucket,
        .key          = key,
        .query_string = query,
    };

    return s3__request(c, &params);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_parts
 * GET /{key}?uploadId=ID&max-parts=N&part-number-marker=M
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Callback for s3__xml_each to parse each <Part> element.
 */
typedef struct list_parts_ctx {
    s3_part_info *parts;
    int           count;
    int           cap;
} list_parts_ctx;

static int parse_part_element(const char *element, size_t element_len, void *userdata)
{
    list_parts_ctx *ctx = (list_parts_ctx *)userdata;

    /* Grow array if needed */
    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        s3_part_info *p = (s3_part_info *)S3_REALLOC(ctx->parts,
                                                      (size_t)new_cap * sizeof(s3_part_info));
        if (!p) return -1;
        ctx->parts = p;
        ctx->cap = new_cap;
    }

    s3_part_info *part = &ctx->parts[ctx->count];
    memset(part, 0, sizeof(*part));

    const char *val;
    size_t val_len;

    if (s3__xml_find(element, element_len, "PartNumber", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        part->part_number = (int)strtol(tmp, nullptr, 10);
    }
    if (s3__xml_find(element, element_len, "LastModified", &val, &val_len))
        copy_xml_val(part->last_modified, sizeof(part->last_modified), val, val_len);
    if (s3__xml_find(element, element_len, "ETag", &val, &val_len))
        copy_xml_val(part->etag, sizeof(part->etag), val, val_len);
    if (s3__xml_find(element, element_len, "Size", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        part->size = strtoll(tmp, nullptr, 10);
    }
    if (s3__xml_find(element, element_len, "ChecksumCRC32", &val, &val_len))
        copy_xml_val(part->checksum_crc32, sizeof(part->checksum_crc32), val, val_len);
    if (s3__xml_find(element, element_len, "ChecksumCRC32C", &val, &val_len))
        copy_xml_val(part->checksum_crc32c, sizeof(part->checksum_crc32c), val, val_len);
    if (s3__xml_find(element, element_len, "ChecksumSHA1", &val, &val_len))
        copy_xml_val(part->checksum_sha1, sizeof(part->checksum_sha1), val, val_len);
    if (s3__xml_find(element, element_len, "ChecksumSHA256", &val, &val_len))
        copy_xml_val(part->checksum_sha256, sizeof(part->checksum_sha256), val, val_len);

    ctx->count++;
    return 0;
}

s3_status s3_list_parts(
    s3_client *c, const char *bucket, const char *key,
    const char *upload_id, int max_parts, int part_number_marker,
    s3_list_parts_result *result)
{
    if (!c || !bucket || !key || !upload_id || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    char query[2048];
    int qlen = snprintf(query, sizeof(query), "uploadId=%s", upload_id);
    if (max_parts > 0)
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&max-parts=%d", max_parts);
    if (part_number_marker > 0)
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&part-number-marker=%d", part_number_marker);
    S3_UNUSED(qlen);

    s3_request_params params = {
        .method          = "GET",
        .bucket          = bucket,
        .key             = key,
        .query_string    = query,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    /* Parse ListPartsResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    const char *val;
    size_t val_len;

    if (s3__xml_find(xml, xml_len, "UploadId", &val, &val_len))
        copy_xml_val(result->upload_id, sizeof(result->upload_id), val, val_len);
    if (s3__xml_find(xml, xml_len, "Key", &val, &val_len))
        copy_xml_val(result->key, sizeof(result->key), val, val_len);
    if (s3__xml_find(xml, xml_len, "StorageClass", &val, &val_len))
        copy_xml_val(result->storage_class, sizeof(result->storage_class), val, val_len);
    if (s3__xml_find(xml, xml_len, "IsTruncated", &val, &val_len))
        result->is_truncated = (val_len >= 4 && strncasecmp(val, "true", 4) == 0);
    if (s3__xml_find(xml, xml_len, "NextPartNumberMarker", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->next_part_number_marker = (int)strtol(tmp, nullptr, 10);
    }
    if (s3__xml_find(xml, xml_len, "MaxParts", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->max_parts = (int)strtol(tmp, nullptr, 10);
    }

    /* Initiator */
    if (s3__xml_find_in(xml, xml_len, "Initiator", "ID", &val, &val_len))
        copy_xml_val(result->initiator_id, sizeof(result->initiator_id), val, val_len);
    if (s3__xml_find_in(xml, xml_len, "Initiator", "DisplayName", &val, &val_len))
        copy_xml_val(result->initiator_display_name, sizeof(result->initiator_display_name), val, val_len);

    /* Owner */
    if (s3__xml_find_in(xml, xml_len, "Owner", "ID", &val, &val_len))
        copy_xml_val(result->owner_id, sizeof(result->owner_id), val, val_len);
    if (s3__xml_find_in(xml, xml_len, "Owner", "DisplayName", &val, &val_len))
        copy_xml_val(result->owner_display_name, sizeof(result->owner_display_name), val, val_len);

    /* Parse Part elements */
    list_parts_ctx ctx = { .parts = nullptr, .count = 0, .cap = 0 };
    int rc = s3__xml_each(xml, xml_len, "Part", parse_part_element, &ctx);
    if (rc < 0) {
        S3_FREE(ctx.parts);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    result->parts = ctx.parts;
    result->part_count = ctx.count;

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_multipart_uploads
 * GET /?uploads with prefix/delimiter/key-marker/upload-id-marker/max-uploads
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct list_uploads_ctx {
    s3_multipart_upload_info *uploads;
    int                       count;
    int                       cap;
} list_uploads_ctx;

static int parse_upload_element(const char *element, size_t element_len, void *userdata)
{
    list_uploads_ctx *ctx = (list_uploads_ctx *)userdata;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        s3_multipart_upload_info *p = (s3_multipart_upload_info *)S3_REALLOC(
            ctx->uploads, (size_t)new_cap * sizeof(s3_multipart_upload_info));
        if (!p) return -1;
        ctx->uploads = p;
        ctx->cap = new_cap;
    }

    s3_multipart_upload_info *u = &ctx->uploads[ctx->count];
    memset(u, 0, sizeof(*u));

    const char *val;
    size_t val_len;

    if (s3__xml_find(element, element_len, "Key", &val, &val_len))
        copy_xml_val(u->key, sizeof(u->key), val, val_len);
    if (s3__xml_find(element, element_len, "UploadId", &val, &val_len))
        copy_xml_val(u->upload_id, sizeof(u->upload_id), val, val_len);
    if (s3__xml_find(element, element_len, "Initiated", &val, &val_len))
        copy_xml_val(u->initiated, sizeof(u->initiated), val, val_len);
    if (s3__xml_find(element, element_len, "StorageClass", &val, &val_len))
        copy_xml_val(u->storage_class, sizeof(u->storage_class), val, val_len);

    if (s3__xml_find_in(element, element_len, "Initiator", "ID", &val, &val_len))
        copy_xml_val(u->initiator_id, sizeof(u->initiator_id), val, val_len);
    if (s3__xml_find_in(element, element_len, "Initiator", "DisplayName", &val, &val_len))
        copy_xml_val(u->initiator_display_name, sizeof(u->initiator_display_name), val, val_len);

    if (s3__xml_find_in(element, element_len, "Owner", "ID", &val, &val_len))
        copy_xml_val(u->owner_id, sizeof(u->owner_id), val, val_len);
    if (s3__xml_find_in(element, element_len, "Owner", "DisplayName", &val, &val_len))
        copy_xml_val(u->owner_display_name, sizeof(u->owner_display_name), val, val_len);

    ctx->count++;
    return 0;
}

typedef struct list_prefixes_ctx {
    char **prefixes;
    int     count;
    int     cap;
} list_prefixes_ctx;

static int parse_common_prefix(const char *element, size_t element_len, void *userdata)
{
    list_prefixes_ctx *ctx = (list_prefixes_ctx *)userdata;

    const char *val;
    size_t val_len;

    if (!s3__xml_find(element, element_len, "Prefix", &val, &val_len))
        return 0;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        char **p = (char **)S3_REALLOC(ctx->prefixes, (size_t)new_cap * sizeof(char *));
        if (!p) return -1;
        ctx->prefixes = p;
        ctx->cap = new_cap;
    }

    ctx->prefixes[ctx->count] = s3__strndup(val, val_len);
    if (!ctx->prefixes[ctx->count]) return -1;
    ctx->count++;
    return 0;
}

s3_status s3_list_multipart_uploads(
    s3_client *c, const char *bucket,
    const char *prefix, const char *delimiter,
    const char *key_marker, const char *upload_id_marker,
    int max_uploads,
    s3_list_multipart_uploads_result *result)
{
    if (!c || !bucket || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    char query[4096];
    int qlen = snprintf(query, sizeof(query), "uploads");

    if (prefix && prefix[0]) {
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&prefix=%s", prefix);
    }
    if (delimiter && delimiter[0]) {
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&delimiter=%s", delimiter);
    }
    if (key_marker && key_marker[0]) {
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&key-marker=%s", key_marker);
    }
    if (upload_id_marker && upload_id_marker[0])
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&upload-id-marker=%s", upload_id_marker);
    if (max_uploads > 0)
        qlen += snprintf(query + qlen, sizeof(query) - (size_t)qlen,
                         "&max-uploads=%d", max_uploads);
    S3_UNUSED(qlen);

    s3_request_params params = {
        .method          = "GET",
        .bucket          = bucket,
        .query_string    = query,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    /* Parse ListMultipartUploadsResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    const char *val;
    size_t val_len;

    if (s3__xml_find(xml, xml_len, "IsTruncated", &val, &val_len))
        result->is_truncated = (val_len >= 4 && strncasecmp(val, "true", 4) == 0);
    if (s3__xml_find(xml, xml_len, "NextKeyMarker", &val, &val_len))
        copy_xml_val(result->next_key_marker, sizeof(result->next_key_marker), val, val_len);
    if (s3__xml_find(xml, xml_len, "NextUploadIdMarker", &val, &val_len))
        copy_xml_val(result->next_upload_id_marker, sizeof(result->next_upload_id_marker), val, val_len);
    if (s3__xml_find(xml, xml_len, "MaxUploads", &val, &val_len)) {
        char tmp[32];
        copy_xml_val(tmp, sizeof(tmp), val, val_len);
        result->max_uploads = (int)strtol(tmp, nullptr, 10);
    }

    /* Parse Upload elements */
    list_uploads_ctx uctx = { .uploads = nullptr, .count = 0, .cap = 0 };
    int rc = s3__xml_each(xml, xml_len, "Upload", parse_upload_element, &uctx);
    if (rc < 0) {
        S3_FREE(uctx.uploads);
        return S3_STATUS_OUT_OF_MEMORY;
    }
    result->uploads = uctx.uploads;
    result->upload_count = uctx.count;

    /* Parse CommonPrefixes elements */
    list_prefixes_ctx pctx = { .prefixes = nullptr, .count = 0, .cap = 0 };
    rc = s3__xml_each(xml, xml_len, "CommonPrefixes", parse_common_prefix, &pctx);
    if (rc < 0) {
        /* Clean up uploads too */
        S3_FREE(uctx.uploads);
        result->uploads = nullptr;
        result->upload_count = 0;
        for (int i = 0; i < pctx.count; i++)
            S3_FREE(pctx.prefixes[i]);
        S3_FREE(pctx.prefixes);
        return S3_STATUS_OUT_OF_MEMORY;
    }
    result->common_prefixes = pctx.prefixes;
    result->prefix_count = pctx.count;

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Free helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_parts_result_free(s3_list_parts_result *r)
{
    if (!r) return;
    S3_FREE(r->parts);
    r->parts = nullptr;
    r->part_count = 0;
}

void s3_list_multipart_uploads_result_free(s3_list_multipart_uploads_result *r)
{
    if (!r) return;
    S3_FREE(r->uploads);
    r->uploads = nullptr;
    r->upload_count = 0;

    for (int i = 0; i < r->prefix_count; i++)
        S3_FREE(r->common_prefixes[i]);
    S3_FREE(r->common_prefixes);
    r->common_prefixes = nullptr;
    r->prefix_count = 0;
}
