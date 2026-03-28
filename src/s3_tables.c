/*
 * libs3 -- S3 Tables API
 *
 * S3 Tables uses JSON (not XML) and a separate endpoint:
 *   https://s3tables.{region}.amazonaws.com
 *
 * We build JSON request bodies with snprintf and parse JSON responses
 * with simple string searching since we have no JSON library.
 *
 * All operations use use_control_endpoint=true with the path as the key,
 * and we override the endpoint to s3tables.{region}.amazonaws.com by
 * constructing the URL through the client's endpoint field temporarily
 * (or by building our own URL via the key path approach).
 *
 * NOTE: The control endpoint builds URLs as:
 *   {account_id}.s3-control.{region}.amazonaws.com/{key}
 * For S3 Tables we need s3tables.{region}.amazonaws.com/{path}, so we
 * temporarily swap the client endpoint and use bucket=nullptr, key=path,
 * use_control_endpoint=false.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * JSON Helpers — simple extractors (no JSON library)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Extract a JSON string value for a given key from a JSON blob.
 * Looks for "key": "value" and copies value into dst.
 * Returns true if found.
 */
static bool json_extract_string(const char *json, size_t json_len,
                                const char *key, char *dst, size_t dst_size)
{
    if (!json || !key || !dst || dst_size == 0) return false;

    /* Build the search pattern: "key": " */
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *end = json + json_len;
    const char *p = json;

    while (p < end) {
        const char *found = strstr(p, pattern);
        if (!found || found >= end) break;

        /* Skip past the key and look for the colon and opening quote */
        const char *after_key = found + strlen(pattern);
        while (after_key < end && (*after_key == ' ' || *after_key == '\t' ||
               *after_key == '\n' || *after_key == '\r')) after_key++;
        if (after_key >= end || *after_key != ':') { p = found + 1; continue; }
        after_key++;
        while (after_key < end && (*after_key == ' ' || *after_key == '\t' ||
               *after_key == '\n' || *after_key == '\r')) after_key++;
        if (after_key >= end || *after_key != '"') { p = found + 1; continue; }
        after_key++; /* skip opening quote */

        /* Extract until closing quote */
        const char *val_start = after_key;
        const char *val_end = val_start;
        while (val_end < end && *val_end != '"') {
            if (*val_end == '\\' && val_end + 1 < end) { val_end += 2; continue; }
            val_end++;
        }

        size_t vlen = (size_t)(val_end - val_start);
        if (vlen >= dst_size) vlen = dst_size - 1;
        memcpy(dst, val_start, vlen);
        dst[vlen] = '\0';
        return true;
    }

    dst[0] = '\0';
    return false;
}

/*
 * Count occurrences of a JSON object pattern within an array.
 * Counts opening braces '{' at the array level.
 */
static int json_count_objects(const char *array_start, size_t len)
{
    int count = 0;
    int depth = 0;
    for (size_t i = 0; i < len; i++) {
        if (array_start[i] == '{') {
            if (depth == 0) count++;
            depth++;
        } else if (array_start[i] == '}') {
            depth--;
        }
    }
    return count;
}

/*
 * Find the Nth JSON object (0-based) in a JSON array.
 * Returns pointer to the '{' and sets obj_len.
 */
static const char *json_nth_object(const char *array_start, size_t len,
                                   int n, size_t *obj_len)
{
    int count = 0;
    int depth = 0;
    const char *obj_start = nullptr;

    for (size_t i = 0; i < len; i++) {
        if (array_start[i] == '{') {
            if (depth == 0) {
                if (count == n) {
                    obj_start = array_start + i;
                }
                count++;
            }
            depth++;
        } else if (array_start[i] == '}') {
            depth--;
            if (depth == 0 && obj_start) {
                *obj_len = (size_t)(array_start + i + 1 - obj_start);
                return obj_start;
            }
        }
    }
    return nullptr;
}

/*
 * Find a JSON array value for a given key.
 * Returns pointer to '[' and sets array_len to include the ']'.
 */
static const char *json_find_array(const char *json, size_t json_len,
                                   const char *key, size_t *array_len)
{
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *end = json + json_len;
    const char *found = strstr(json, pattern);
    if (!found || found >= end) return nullptr;

    const char *after = found + strlen(pattern);
    while (after < end && (*after == ' ' || *after == '\t' ||
           *after == '\n' || *after == '\r')) after++;
    if (after >= end || *after != ':') return nullptr;
    after++;
    while (after < end && (*after == ' ' || *after == '\t' ||
           *after == '\n' || *after == '\r')) after++;
    if (after >= end || *after != '[') return nullptr;

    /* Find matching ']' */
    int depth = 0;
    const char *arr_start = after;
    for (const char *p = arr_start; p < end; p++) {
        if (*p == '[') depth++;
        else if (*p == ']') {
            depth--;
            if (depth == 0) {
                *array_len = (size_t)(p + 1 - arr_start);
                return arr_start;
            }
        }
    }
    return nullptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * S3 Tables endpoint helper
 *
 * S3 Tables uses s3tables.{region}.amazonaws.com, not the control endpoint.
 * We temporarily set the client endpoint, make the request, then restore it.
 * ═══════════════════════════════════════════════════════════════════════════ */

static s3_status s3_tables_request(s3_client *c, const s3_request_params *params)
{
    /* Save original endpoint */
    char *saved_endpoint = c->endpoint;
    bool saved_path_style = c->use_path_style;

    /* Build s3tables endpoint */
    char tables_endpoint[256];
    snprintf(tables_endpoint, sizeof(tables_endpoint),
             "s3tables.%s.amazonaws.com", c->region);
    c->endpoint = tables_endpoint;
    c->use_path_style = true;

    s3_status status = s3__request(c, params);

    /* Restore */
    c->endpoint = saved_endpoint;
    c->use_path_style = saved_path_style;

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Parse helpers for result types
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_table_bucket(const char *json, size_t len, s3_table_bucket *out)
{
    memset(out, 0, sizeof(*out));
    json_extract_string(json, len, "arn", out->arn, sizeof(out->arn));
    json_extract_string(json, len, "name", out->name, sizeof(out->name));
    json_extract_string(json, len, "ownerAccountId", out->owner_account_id, sizeof(out->owner_account_id));
    json_extract_string(json, len, "createdAt", out->created_at, sizeof(out->created_at));
}

static void parse_namespace(const char *json, size_t len, s3_namespace *out)
{
    memset(out, 0, sizeof(*out));
    json_extract_string(json, len, "namespace", out->name, sizeof(out->name));
    if (!out->name[0])
        json_extract_string(json, len, "name", out->name, sizeof(out->name));
    json_extract_string(json, len, "arn", out->arn, sizeof(out->arn));
    json_extract_string(json, len, "createdAt", out->created_at, sizeof(out->created_at));
}

static void parse_table(const char *json, size_t len, s3_table *out)
{
    memset(out, 0, sizeof(*out));
    json_extract_string(json, len, "name", out->name, sizeof(out->name));
    json_extract_string(json, len, "namespace", out->namespace_name, sizeof(out->namespace_name));
    json_extract_string(json, len, "arn", out->arn, sizeof(out->arn));
    json_extract_string(json, len, "type", out->type, sizeof(out->type));
    json_extract_string(json, len, "createdAt", out->created_at, sizeof(out->created_at));
    json_extract_string(json, len, "modifiedAt", out->modified_at, sizeof(out->modified_at));
    json_extract_string(json, len, "metadataLocation", out->metadata_location, sizeof(out->metadata_location));
    json_extract_string(json, len, "warehouseLocation", out->warehouse_location, sizeof(out->warehouse_location));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Table Bucket Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * s3_create_table_bucket — POST /buckets
 * Body: {"name": "<name>"}
 */
s3_status s3_create_table_bucket(s3_client *c, const char *name,
                                 s3_table_bucket *result)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build JSON body */
    char body[512];
    snprintf(body, sizeof(body), "{\"name\":\"%s\"}", name);

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = "buckets",
        .extra_headers    = hdrs,
        .upload_data      = body,
        .upload_len       = strlen(body),
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_table_bucket(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_delete_table_bucket — DELETE /buckets/{tableBucketARN}
 */
s3_status s3_delete_table_bucket(s3_client *c, const char *table_bucket_arn)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s", table_bucket_arn);

    s3_request_params params = {
        .method           = "DELETE",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    return s3_tables_request(c, &params);
}

/*
 * s3_get_table_bucket — GET /buckets/{tableBucketARN}
 */
s3_status s3_get_table_bucket(s3_client *c, const char *table_bucket_arn,
                              s3_table_bucket *result)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s", table_bucket_arn);

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_table_bucket(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_list_table_buckets — GET /buckets
 * Query: continuationToken=...&maxBuckets=...
 */
s3_status s3_list_table_buckets(s3_client *c, const char *continuation_token,
                                int max_buckets,
                                s3_table_bucket **buckets_out, int *count_out)
{
    if (!c || !buckets_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *buckets_out = nullptr;
    *count_out = 0;

    /* Build query string */
    char query[1024] = "";
    int offset = 0;
    if (max_buckets > 0) {
        offset += snprintf(query + offset, sizeof(query) - (size_t)offset,
                           "maxBuckets=%d", max_buckets);
    }
    if (continuation_token && continuation_token[0]) {
        offset += snprintf(query + offset, sizeof(query) - (size_t)offset,
                           "%scontinuationToken=%s",
                           offset > 0 ? "&" : "", continuation_token);
    }
    (void)offset;

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = "buckets",
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        /* Parse the array of table buckets from "tableBuckets": [...] */
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "tableBuckets", &arr_len);
        if (!arr) {
            /* Try alternate key */
            arr = json_find_array(c->response.data, c->response.len,
                                  "buckets", &arr_len);
        }

        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_table_bucket *results = (s3_table_bucket *)S3_CALLOC(
                    (size_t)n, sizeof(s3_table_bucket));
                if (!results) return S3_STATUS_OUT_OF_MEMORY;

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) {
                        parse_table_bucket(obj, obj_len, &results[i]);
                    }
                }
                *buckets_out = results;
                *count_out = n;
            }
        }
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Namespace Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * s3_create_namespace — POST /namespaces/{tableBucketARN}
 * Body: {"namespace": ["<name>"]}
 */
s3_status s3_create_namespace(s3_client *c, const char *table_bucket_arn,
                              const char *name, s3_namespace *result)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char body[512];
    snprintf(body, sizeof(body), "{\"namespace\":[\"%s\"]}", name);

    char path[512];
    snprintf(path, sizeof(path), "namespaces/%s", table_bucket_arn);

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body,
        .upload_len       = strlen(body),
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_namespace(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_delete_namespace — DELETE /namespaces/{tableBucketARN}/{namespace}
 */
s3_status s3_delete_namespace(s3_client *c, const char *table_bucket_arn,
                              const char *name)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "namespaces/%s/%s", table_bucket_arn, name);

    s3_request_params params = {
        .method           = "DELETE",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    return s3_tables_request(c, &params);
}

/*
 * s3_get_namespace — GET /namespaces/{tableBucketARN}/{namespace}
 */
s3_status s3_get_namespace(s3_client *c, const char *table_bucket_arn,
                           const char *name, s3_namespace *result)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "namespaces/%s/%s", table_bucket_arn, name);

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_namespace(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_list_namespaces — GET /namespaces/{tableBucketARN}
 * Query: continuationToken=...&maxNamespaces=...
 */
s3_status s3_list_namespaces(s3_client *c, const char *table_bucket_arn,
                             const char *continuation_token, int max_namespaces,
                             s3_namespace **namespaces_out, int *count_out)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] ||
        !namespaces_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *namespaces_out = nullptr;
    *count_out = 0;

    char path[512];
    snprintf(path, sizeof(path), "namespaces/%s", table_bucket_arn);

    char query[1024] = "";
    int offset = 0;
    if (max_namespaces > 0) {
        offset += snprintf(query + offset, sizeof(query) - (size_t)offset,
                           "maxNamespaces=%d", max_namespaces);
    }
    if (continuation_token && continuation_token[0]) {
        offset += snprintf(query + offset, sizeof(query) - (size_t)offset,
                           "%scontinuationToken=%s",
                           offset > 0 ? "&" : "", continuation_token);
    }
    (void)offset;

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "namespaces", &arr_len);
        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_namespace *results = (s3_namespace *)S3_CALLOC(
                    (size_t)n, sizeof(s3_namespace));
                if (!results) return S3_STATUS_OUT_OF_MEMORY;

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) {
                        parse_namespace(obj, obj_len, &results[i]);
                    }
                }
                *namespaces_out = results;
                *count_out = n;
            }
        }
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Table Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * s3_create_table — POST /tables/{tableBucketARN}/{namespace}
 * Body: {"name": "...", "format": "ICEBERG"}
 */
s3_status s3_create_table(s3_client *c, const char *table_bucket_arn,
                          const char *namespace_name, const char *name,
                          const char *format, s3_table *result)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] ||
        !namespace_name || !namespace_name[0] || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    const char *fmt = (format && format[0]) ? format : "ICEBERG";

    char body[1024];
    snprintf(body, sizeof(body), "{\"name\":\"%s\",\"format\":\"%s\"}",
             name, fmt);

    char path[512];
    snprintf(path, sizeof(path), "tables/%s/%s",
             table_bucket_arn, namespace_name);

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body,
        .upload_len       = strlen(body),
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_table(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_delete_table — DELETE /tables/{tableBucketARN}/{namespace}/{table}
 * Query: versionToken=...
 */
s3_status s3_delete_table(s3_client *c, const char *table_bucket_arn,
                          const char *namespace_name, const char *name,
                          const char *version_token)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] ||
        !namespace_name || !namespace_name[0] || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "tables/%s/%s/%s",
             table_bucket_arn, namespace_name, name);

    char query[512] = "";
    if (version_token && version_token[0]) {
        snprintf(query, sizeof(query), "versionToken=%s", version_token);
    }

    s3_request_params params = {
        .method           = "DELETE",
        .bucket           = nullptr,
        .key              = path,
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    return s3_tables_request(c, &params);
}

/*
 * s3_get_table — GET /tables/{tableBucketARN}/{namespace}/{table}
 */
s3_status s3_get_table(s3_client *c, const char *table_bucket_arn,
                       const char *namespace_name, const char *name,
                       s3_table *result)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] ||
        !namespace_name || !namespace_name[0] || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "tables/%s/%s/%s",
             table_bucket_arn, namespace_name, name);

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_table(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_list_tables — GET /tables/{tableBucketARN}/{namespace}
 * Query: continuationToken=...&maxTables=...
 */
s3_status s3_list_tables(s3_client *c, const char *table_bucket_arn,
                         const char *namespace_name,
                         const char *continuation_token, int max_tables,
                         s3_table **tables_out, int *count_out)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] ||
        !namespace_name || !namespace_name[0] ||
        !tables_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *tables_out = nullptr;
    *count_out = 0;

    char path[512];
    snprintf(path, sizeof(path), "tables/%s/%s",
             table_bucket_arn, namespace_name);

    char query[1024] = "";
    int offset = 0;
    if (max_tables > 0) {
        offset += snprintf(query + offset, sizeof(query) - (size_t)offset,
                           "maxTables=%d", max_tables);
    }
    if (continuation_token && continuation_token[0]) {
        offset += snprintf(query + offset, sizeof(query) - (size_t)offset,
                           "%scontinuationToken=%s",
                           offset > 0 ? "&" : "", continuation_token);
    }
    (void)offset;

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "tables", &arr_len);
        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_table *results = (s3_table *)S3_CALLOC(
                    (size_t)n, sizeof(s3_table));
                if (!results) return S3_STATUS_OUT_OF_MEMORY;

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) {
                        parse_table(obj, obj_len, &results[i]);
                    }
                }
                *tables_out = results;
                *count_out = n;
            }
        }
    }

    return status;
}

/*
 * s3_rename_table — PUT /tables/{tableBucketARN}/{namespace}/{table}/rename
 * Body: {"newNamespaceName": "...", "newName": "...", "versionToken": "..."}
 */
s3_status s3_rename_table(s3_client *c, const char *table_bucket_arn,
                          const char *namespace_name, const char *name,
                          const char *new_namespace_name, const char *new_name,
                          const char *version_token)
{
    if (!c || !table_bucket_arn || !table_bucket_arn[0] ||
        !namespace_name || !namespace_name[0] || !name || !name[0] ||
        !new_name || !new_name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "tables/%s/%s/%s/rename",
             table_bucket_arn, namespace_name, name);

    /* Build JSON body */
    s3_buf body;
    s3_buf_init(&body);
    s3_buf_append_str(&body, "{");

    if (new_namespace_name && new_namespace_name[0]) {
        char frag[512];
        snprintf(frag, sizeof(frag), "\"newNamespaceName\":\"%s\",",
                 new_namespace_name);
        s3_buf_append_str(&body, frag);
    }

    {
        char frag[512];
        snprintf(frag, sizeof(frag), "\"newName\":\"%s\"", new_name);
        s3_buf_append_str(&body, frag);
    }

    if (version_token && version_token[0]) {
        char frag[512];
        snprintf(frag, sizeof(frag), ",\"versionToken\":\"%s\"", version_token);
        s3_buf_append_str(&body, frag);
    }

    s3_buf_append_str(&body, "}");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "PUT",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3_tables_request(c, &params);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}
