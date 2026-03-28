/*
 * libs3 -- List operations
 *
 * ListObjectsV2, ListObjectsV1, ListObjectVersions,
 * and result free functions.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers — Parse common object fields from a Contents element
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_object_info(const char *xml, size_t len, s3_object_info *obj)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "Key", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->key, sizeof(obj->key));
    if (s3__xml_find(xml, len, "ETag", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->etag, sizeof(obj->etag));
    if (s3__xml_find(xml, len, "LastModified", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->last_modified, sizeof(obj->last_modified));
    if (s3__xml_find(xml, len, "StorageClass", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->storage_class, sizeof(obj->storage_class));
    if (s3__xml_find(xml, len, "Size", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        obj->size = strtoll(tmp, nullptr, 10);
    }
    if (s3__xml_find(xml, len, "ChecksumAlgorithm", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->checksum_algorithm,
                                sizeof(obj->checksum_algorithm));

    /* Owner (nested) */
    if (s3__xml_find_in(xml, len, "Owner", "ID", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->owner_id, sizeof(obj->owner_id));
    if (s3__xml_find_in(xml, len, "Owner", "DisplayName", &val, &vlen))
        s3__xml_decode_entities(val, vlen, obj->owner_display_name,
                                sizeof(obj->owner_display_name));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers — Dynamic object array
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    s3_object_info *items;
    int             count;
    int             cap;
} object_array;

static int object_array_cb(const char *element, size_t element_len, void *userdata)
{
    object_array *arr = (object_array *)userdata;

    if (arr->count >= arr->cap) {
        int new_cap = arr->cap ? arr->cap * 2 : 64;
        s3_object_info *p = (s3_object_info *)S3_REALLOC(
            arr->items, (size_t)new_cap * sizeof(s3_object_info));
        if (!p) return -1;
        arr->items = p;
        arr->cap = new_cap;
    }

    s3_object_info *obj = &arr->items[arr->count];
    memset(obj, 0, sizeof(*obj));
    parse_object_info(element, element_len, obj);
    arr->count++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers — CommonPrefixes array
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char **items;
    int    count;
    int    cap;
} prefix_array;

static int prefix_cb(const char *element, size_t element_len, void *userdata)
{
    prefix_array *arr = (prefix_array *)userdata;

    const char *val;
    size_t vlen;
    if (!s3__xml_find(element, element_len, "Prefix", &val, &vlen))
        return 0;

    if (arr->count >= arr->cap) {
        int new_cap = arr->cap ? arr->cap * 2 : 16;
        char **p = (char **)S3_REALLOC(arr->items, (size_t)new_cap * sizeof(char *));
        if (!p) return -1;
        arr->items = p;
        arr->cap = new_cap;
    }

    /* Decode entities into a temp buffer, then strdup */
    char buf[2048];
    s3__xml_decode_entities(val, vlen, buf, sizeof(buf));
    arr->items[arr->count] = s3__strdup(buf);
    arr->count++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers — Parse common list result fields
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_list_result_fields(const char *xml, size_t xml_len,
                                     s3_list_objects_result *result)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, xml_len, "Name", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->name, sizeof(result->name));
    if (s3__xml_find(xml, xml_len, "Prefix", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->prefix, sizeof(result->prefix));
    if (s3__xml_find(xml, xml_len, "Delimiter", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->delimiter, sizeof(result->delimiter));
    if (s3__xml_find(xml, xml_len, "EncodingType", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->encoding_type, sizeof(result->encoding_type));
    if (s3__xml_find(xml, xml_len, "IsTruncated", &val, &vlen))
        result->is_truncated = (vlen == 4 && memcmp(val, "true", 4) == 0);
    if (s3__xml_find(xml, xml_len, "MaxKeys", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        result->max_keys = (int)strtol(tmp, nullptr, 10);
    }
    if (s3__xml_find(xml, xml_len, "KeyCount", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        result->key_count = (int)strtol(tmp, nullptr, 10);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_objects_v2 — GET /?list-type=2
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_list_objects_v2(s3_client *c, const char *bucket,
                             const s3_list_objects_opts *opts,
                             s3_list_objects_result *result)
{
    if (!c || !bucket || !bucket[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qb;
    s3_buf_init(&qb);
    s3_buf_append_str(&qb, "list-type=2");

    if (opts) {
        if (opts->prefix && opts->prefix[0]) {
            s3_buf_append_str(&qb, "&prefix=");
            s3_buf_append_str(&qb, opts->prefix);
        }
        if (opts->delimiter && opts->delimiter[0]) {
            s3_buf_append_str(&qb, "&delimiter=");
            s3_buf_append_str(&qb, opts->delimiter);
        }
        if (opts->max_keys > 0) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "&max-keys=%d", opts->max_keys);
            s3_buf_append_str(&qb, tmp);
        }
        if (opts->continuation_token && opts->continuation_token[0]) {
            s3_buf_append_str(&qb, "&continuation-token=");
            s3_buf_append_str(&qb, opts->continuation_token);
        }
        if (opts->start_after && opts->start_after[0]) {
            s3_buf_append_str(&qb, "&start-after=");
            s3_buf_append_str(&qb, opts->start_after);
        }
        if (opts->fetch_owner) {
            s3_buf_append_str(&qb, "&fetch-owner=true");
        }
        if (opts->encoding_type && opts->encoding_type[0]) {
            s3_buf_append_str(&qb, "&encoding-type=");
            s3_buf_append_str(&qb, opts->encoding_type);
        }
    }

    /* Build extra headers */
    struct curl_slist *hdrs = nullptr;
    if (opts && opts->expected_bucket_owner && opts->expected_bucket_owner[0]) {
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "x-amz-expected-bucket-owner: %s",
                 opts->expected_bucket_owner);
        hdrs = curl_slist_append(hdrs, hdr);
    }
    if (opts && opts->request_payer) {
        hdrs = curl_slist_append(hdrs, "x-amz-request-payer: requester");
    }

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .query_string     = qb.data,
        .extra_headers    = hdrs,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(hdrs);

    if (status != S3_STATUS_OK) {
        s3_buf_free(&qb);
        return status;
    }

    /* Parse ListBucketResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0) {
        s3_buf_free(&qb);
        return S3_STATUS_OK;
    }

    parse_list_result_fields(xml, xml_len, result);

    const char *val;
    size_t vlen;

    /* V2-specific fields */
    if (s3__xml_find(xml, xml_len, "NextContinuationToken", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->next_continuation_token,
                                sizeof(result->next_continuation_token));
    if (s3__xml_find(xml, xml_len, "StartAfter", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->start_after,
                                sizeof(result->start_after));

    /* Parse Contents elements */
    object_array objs = {0};
    s3__xml_each(xml, xml_len, "Contents", object_array_cb, &objs);
    result->objects = objs.items;
    result->object_count = objs.count;

    /* Parse CommonPrefixes elements */
    prefix_array pfx = {0};
    s3__xml_each(xml, xml_len, "CommonPrefixes", prefix_cb, &pfx);
    result->common_prefixes = pfx.items;
    result->prefix_count = pfx.count;

    s3_buf_free(&qb);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_objects_v1 — GET / with prefix/delimiter/max-keys/marker
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_list_objects_v1(s3_client *c, const char *bucket,
                             const char *prefix, const char *delimiter,
                             const char *marker, int max_keys,
                             s3_list_objects_result *result)
{
    if (!c || !bucket || !bucket[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qb;
    s3_buf_init(&qb);
    bool first = true;

    if (prefix && prefix[0]) {
        s3_buf_append_str(&qb, "prefix=");
        s3_buf_append_str(&qb, prefix);
        first = false;
    }
    if (delimiter && delimiter[0]) {
        s3_buf_append_str(&qb, first ? "delimiter=" : "&delimiter=");
        s3_buf_append_str(&qb, delimiter);
        first = false;
    }
    if (marker && marker[0]) {
        s3_buf_append_str(&qb, first ? "marker=" : "&marker=");
        s3_buf_append_str(&qb, marker);
        first = false;
    }
    if (max_keys > 0) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%smax-keys=%d",
                 first ? "" : "&", max_keys);
        s3_buf_append_str(&qb, tmp);
        first = false;
    }

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .query_string     = qb.len ? qb.data : nullptr,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK) {
        s3_buf_free(&qb);
        return status;
    }

    /* Parse ListBucketResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0) {
        s3_buf_free(&qb);
        return S3_STATUS_OK;
    }

    parse_list_result_fields(xml, xml_len, result);

    const char *val;
    size_t vlen;

    /* V1-specific: NextMarker -> next_continuation_token */
    if (s3__xml_find(xml, xml_len, "NextMarker", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->next_continuation_token,
                                sizeof(result->next_continuation_token));

    /* Marker -> start_after (reuse the field) */
    if (s3__xml_find(xml, xml_len, "Marker", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->start_after,
                                sizeof(result->start_after));

    /* Parse Contents elements */
    object_array objs = {0};
    s3__xml_each(xml, xml_len, "Contents", object_array_cb, &objs);
    result->objects = objs.items;
    result->object_count = objs.count;

    /* Parse CommonPrefixes elements */
    prefix_array pfx = {0};
    s3__xml_each(xml, xml_len, "CommonPrefixes", prefix_cb, &pfx);
    result->common_prefixes = pfx.items;
    result->prefix_count = pfx.count;

    s3_buf_free(&qb);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_object_versions — GET /?versions
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Dynamic version array */
typedef struct {
    s3_version_info *items;
    int              count;
    int              cap;
} version_array;

static int grow_version_array(version_array *arr)
{
    if (arr->count < arr->cap)
        return 0;
    int new_cap = arr->cap ? arr->cap * 2 : 64;
    s3_version_info *p = (s3_version_info *)S3_REALLOC(
        arr->items, (size_t)new_cap * sizeof(s3_version_info));
    if (!p) return -1;
    arr->items = p;
    arr->cap = new_cap;
    return 0;
}

static void parse_version_common(const char *xml, size_t len, s3_version_info *v)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "Key", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->key, sizeof(v->key));
    if (s3__xml_find(xml, len, "VersionId", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->version_id, sizeof(v->version_id));
    if (s3__xml_find(xml, len, "IsLatest", &val, &vlen))
        v->is_latest = (vlen == 4 && memcmp(val, "true", 4) == 0);
    if (s3__xml_find(xml, len, "LastModified", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->last_modified, sizeof(v->last_modified));
    if (s3__xml_find(xml, len, "ETag", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->etag, sizeof(v->etag));
    if (s3__xml_find(xml, len, "Size", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        v->size = strtoll(tmp, nullptr, 10);
    }
    if (s3__xml_find(xml, len, "StorageClass", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->storage_class, sizeof(v->storage_class));

    /* Owner (nested) */
    if (s3__xml_find_in(xml, len, "Owner", "ID", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->owner_id, sizeof(v->owner_id));
    if (s3__xml_find_in(xml, len, "Owner", "DisplayName", &val, &vlen))
        s3__xml_decode_entities(val, vlen, v->owner_display_name,
                                sizeof(v->owner_display_name));
}

static int version_cb(const char *element, size_t element_len, void *userdata)
{
    version_array *arr = (version_array *)userdata;
    if (grow_version_array(arr) < 0) return -1;

    s3_version_info *v = &arr->items[arr->count];
    memset(v, 0, sizeof(*v));
    v->is_delete_marker = false;
    parse_version_common(element, element_len, v);
    arr->count++;
    return 0;
}

static int delete_marker_cb(const char *element, size_t element_len, void *userdata)
{
    version_array *arr = (version_array *)userdata;
    if (grow_version_array(arr) < 0) return -1;

    s3_version_info *v = &arr->items[arr->count];
    memset(v, 0, sizeof(*v));
    v->is_delete_marker = true;
    parse_version_common(element, element_len, v);
    arr->count++;
    return 0;
}

s3_status s3_list_object_versions(s3_client *c, const char *bucket,
                                  const s3_list_object_versions_opts *opts,
                                  s3_list_object_versions_result *result)
{
    if (!c || !bucket || !bucket[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qb;
    s3_buf_init(&qb);
    s3_buf_append_str(&qb, "versions");

    if (opts) {
        if (opts->prefix && opts->prefix[0]) {
            s3_buf_append_str(&qb, "&prefix=");
            s3_buf_append_str(&qb, opts->prefix);
        }
        if (opts->delimiter && opts->delimiter[0]) {
            s3_buf_append_str(&qb, "&delimiter=");
            s3_buf_append_str(&qb, opts->delimiter);
        }
        if (opts->key_marker && opts->key_marker[0]) {
            s3_buf_append_str(&qb, "&key-marker=");
            s3_buf_append_str(&qb, opts->key_marker);
        }
        if (opts->version_id_marker && opts->version_id_marker[0]) {
            s3_buf_append_str(&qb, "&version-id-marker=");
            s3_buf_append_str(&qb, opts->version_id_marker);
        }
        if (opts->max_keys > 0) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "&max-keys=%d", opts->max_keys);
            s3_buf_append_str(&qb, tmp);
        }
        if (opts->encoding_type && opts->encoding_type[0]) {
            s3_buf_append_str(&qb, "&encoding-type=");
            s3_buf_append_str(&qb, opts->encoding_type);
        }
    }

    /* Build extra headers */
    struct curl_slist *hdrs = nullptr;
    if (opts && opts->expected_bucket_owner && opts->expected_bucket_owner[0]) {
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "x-amz-expected-bucket-owner: %s",
                 opts->expected_bucket_owner);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .query_string     = qb.data,
        .extra_headers    = hdrs,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(hdrs);

    if (status != S3_STATUS_OK) {
        s3_buf_free(&qb);
        return status;
    }

    /* Parse ListVersionsResult XML */
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
    if (s3__xml_find(xml, xml_len, "NextKeyMarker", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->next_key_marker,
                                sizeof(result->next_key_marker));
    if (s3__xml_find(xml, xml_len, "NextVersionIdMarker", &val, &vlen))
        s3__xml_decode_entities(val, vlen, result->next_version_id_marker,
                                sizeof(result->next_version_id_marker));

    /* Parse Version elements and DeleteMarker elements into one array */
    version_array vers = {0};
    s3__xml_each(xml, xml_len, "Version", version_cb, &vers);
    s3__xml_each(xml, xml_len, "DeleteMarker", delete_marker_cb, &vers);
    result->versions = vers.items;
    result->version_count = vers.count;

    /* Parse CommonPrefixes elements */
    prefix_array pfx = {0};
    s3__xml_each(xml, xml_len, "CommonPrefixes", prefix_cb, &pfx);
    result->common_prefixes = pfx.items;
    result->prefix_count = pfx.count;

    s3_buf_free(&qb);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_objects_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_objects_result_free(s3_list_objects_result *r)
{
    if (!r) return;

    S3_FREE(r->objects);
    r->objects = nullptr;
    r->object_count = 0;

    if (r->common_prefixes) {
        for (int i = 0; i < r->prefix_count; i++)
            S3_FREE(r->common_prefixes[i]);
        S3_FREE(r->common_prefixes);
        r->common_prefixes = nullptr;
    }
    r->prefix_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_object_versions_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_object_versions_result_free(s3_list_object_versions_result *r)
{
    if (!r) return;

    S3_FREE(r->versions);
    r->versions = nullptr;
    r->version_count = 0;

    if (r->common_prefixes) {
        for (int i = 0; i < r->prefix_count; i++)
            S3_FREE(r->common_prefixes[i]);
        S3_FREE(r->common_prefixes);
        r->common_prefixes = nullptr;
    }
    r->prefix_count = 0;
}
