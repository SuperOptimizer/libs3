/*
 * libs3 -- Bucket operations
 *
 * CreateBucket, DeleteBucket, HeadBucket, ListBuckets,
 * GetBucketLocation, ListDirectoryBuckets, result free.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_bucket — PUT / with LocationConstraint XML
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_bucket(s3_client *c, const char *bucket,
                           s3_canned_acl acl, bool object_lock_enabled)
{
    if (!c || !bucket || !bucket[0])
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build LocationConstraint XML body (only for non-us-east-1) */
    s3_buf body;
    s3_buf_init(&body);

    bool need_body = (c->region && c->region[0] &&
                      strcmp(c->region, "us-east-1") != 0);

    if (need_body) {
        s3__xml_buf_declaration(&body);
        s3_buf_append_str(&body,
            "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
        s3__xml_buf_element(&body, "LocationConstraint", c->region);
        s3_buf_append_str(&body, "</CreateBucketConfiguration>");
    }

    /* Build extra headers */
    struct curl_slist *hdrs = nullptr;

    /* x-amz-acl */
    const char *acl_str = s3__canned_acl_string(acl);
    if (acl_str && acl_str[0]) {
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "x-amz-acl: %s", acl_str);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    /* x-amz-bucket-object-lock-enabled */
    if (object_lock_enabled) {
        hdrs = curl_slist_append(hdrs, "x-amz-bucket-object-lock-enabled: true");
    }

    s3_request_params params = {
        .method          = "PUT",
        .bucket          = bucket,
        .key             = nullptr,
        .query_string    = nullptr,
        .extra_headers   = hdrs,
        .upload_data     = need_body ? body.data : nullptr,
        .upload_len      = need_body ? body.len : 0,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_bucket — DELETE /
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_bucket(s3_client *c, const char *bucket)
{
    if (!c || !bucket || !bucket[0])
        return S3_STATUS_INVALID_ARGUMENT;

    s3_request_params params = {
        .method = "DELETE",
        .bucket = bucket,
    };

    return s3__request(c, &params);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_head_bucket — HEAD /
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_head_bucket(s3_client *c, const char *bucket,
                         const char *expected_bucket_owner)
{
    if (!c || !bucket || !bucket[0])
        return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *hdrs = nullptr;

    if (expected_bucket_owner && expected_bucket_owner[0]) {
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "x-amz-expected-bucket-owner: %s",
                 expected_bucket_owner);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    s3_request_params params = {
        .method        = "HEAD",
        .bucket        = bucket,
        .extra_headers = hdrs,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_buckets — GET / on service endpoint (bucket=nullptr)
 * Parse ListAllMyBucketsResult XML
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Callback context for parsing buckets */
typedef struct {
    s3_bucket_info *buckets;
    int             count;
    int             cap;
} list_buckets_ctx;

static int parse_bucket_cb(const char *element, size_t element_len, void *userdata)
{
    list_buckets_ctx *ctx = (list_buckets_ctx *)userdata;

    /* Grow array if needed */
    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 16;
        s3_bucket_info *p = (s3_bucket_info *)S3_REALLOC(
            ctx->buckets, (size_t)new_cap * sizeof(s3_bucket_info));
        if (!p) return -1;
        ctx->buckets = p;
        ctx->cap = new_cap;
    }

    s3_bucket_info *b = &ctx->buckets[ctx->count];
    memset(b, 0, sizeof(*b));

    const char *val;
    size_t vlen;

    if (s3__xml_find(element, element_len, "Name", &val, &vlen)) {
        s3__xml_decode_entities(val, vlen, b->name, sizeof(b->name));
    }
    if (s3__xml_find(element, element_len, "CreationDate", &val, &vlen)) {
        s3__xml_decode_entities(val, vlen, b->creation_date, sizeof(b->creation_date));
    }

    ctx->count++;
    return 0;
}

s3_status s3_list_buckets(s3_client *c, const char *prefix,
                          const char *continuation_token, int max_buckets,
                          s3_list_buckets_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qb;
    s3_buf_init(&qb);
    bool first = true;

    if (prefix && prefix[0]) {
        s3_buf_append_str(&qb, first ? "prefix=" : "&prefix=");
        s3_buf_append_str(&qb, prefix);
        first = false;
    }
    if (continuation_token && continuation_token[0]) {
        s3_buf_append_str(&qb, first ? "continuation-token=" : "&continuation-token=");
        s3_buf_append_str(&qb, continuation_token);
        first = false;
    }
    if (max_buckets > 0) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%smax-buckets=%d",
                 first ? "" : "&", max_buckets);
        s3_buf_append_str(&qb, tmp);
        first = false;
    }

    s3_request_params params = {
        .method            = "GET",
        .bucket            = nullptr,
        .key               = nullptr,
        .query_string      = qb.len ? qb.data : nullptr,
        .collect_response  = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK) {
        s3_buf_free(&qb);
        return status;
    }

    /* Parse ListAllMyBucketsResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0) {
        s3_buf_free(&qb);
        return S3_STATUS_OK;
    }

    /* Owner */
    const char *val;
    size_t vlen;

    if (s3__xml_find_in(xml, xml_len, "Owner", "ID", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->owner_id, sizeof(result->owner_id));
    if (s3__xml_find_in(xml, xml_len, "Owner", "DisplayName", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->owner_display_name,
                                sizeof(result->owner_display_name));

    /* IsTruncated */
    if (s3__xml_find(xml, xml_len, "IsTruncated", &val, &vlen))
        result->is_truncated = (vlen == 4 && memcmp(val, "true", 4) == 0);

    /* ContinuationToken */
    if (s3__xml_find(xml, xml_len, "ContinuationToken", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->continuation_token,
                                sizeof(result->continuation_token));

    /* Parse each Bucket element */
    list_buckets_ctx ctx = {0};
    s3__xml_each(xml, xml_len, "Bucket", parse_bucket_cb, &ctx);

    result->buckets = ctx.buckets;
    result->bucket_count = ctx.count;

    s3_buf_free(&qb);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_bucket_location — GET /?location
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_location(s3_client *c, const char *bucket,
                                 char *region_out, size_t region_out_size)
{
    if (!c || !bucket || !bucket[0] || !region_out || region_out_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;

    region_out[0] = '\0';

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .query_string     = "location",
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0) {
        /* Empty response means us-east-1 */
        snprintf(region_out, region_out_size, "us-east-1");
        return S3_STATUS_OK;
    }

    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, xml_len, "LocationConstraint", &val, &vlen)) {
        if (vlen == 0) {
            /* Empty LocationConstraint means us-east-1 */
            snprintf(region_out, region_out_size, "us-east-1");
        } else {
            s3__xml_decode_entities(val, vlen, region_out, region_out_size);
        }
    } else {
        /* No LocationConstraint tag = us-east-1 */
        snprintf(region_out, region_out_size, "us-east-1");
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_directory_buckets — GET /?bucket-type=directory
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_list_directory_buckets(s3_client *c,
                                   const char *continuation_token,
                                   int max_buckets,
                                   s3_list_buckets_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qb;
    s3_buf_init(&qb);
    s3_buf_append_str(&qb, "bucket-type=directory");

    if (continuation_token && continuation_token[0]) {
        s3_buf_append_str(&qb, "&continuation-token=");
        s3_buf_append_str(&qb, continuation_token);
    }
    if (max_buckets > 0) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "&max-directory-buckets=%d", max_buckets);
        s3_buf_append_str(&qb, tmp);
    }

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = nullptr,
        .query_string     = qb.data,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK) {
        s3_buf_free(&qb);
        return status;
    }

    /* Parse response -- same XML schema as ListBuckets */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0) {
        s3_buf_free(&qb);
        return S3_STATUS_OK;
    }

    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, xml_len, "IsTruncated", &val, &vlen))
        result->is_truncated = (vlen == 4 && memcmp(val, "true", 4) == 0);

    if (s3__xml_find(xml, xml_len, "ContinuationToken", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->continuation_token,
                                sizeof(result->continuation_token));

    list_buckets_ctx ctx = {0};
    s3__xml_each(xml, xml_len, "Bucket", parse_bucket_cb, &ctx);

    result->buckets = ctx.buckets;
    result->bucket_count = ctx.count;

    s3_buf_free(&qb);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_buckets_result_free — free buckets array
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_buckets_result_free(s3_list_buckets_result *r)
{
    if (!r) return;
    S3_FREE(r->buckets);
    r->buckets = nullptr;
    r->bucket_count = 0;
}
