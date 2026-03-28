#define _POSIX_C_SOURCE 200809L
#include <strings.h>
/*
 * libs3 -- S3 Vectors API
 *
 * S3 Vectors uses JSON and a separate endpoint:
 *   https://s3vectors.{region}.amazonaws.com
 *
 * We temporarily override the client endpoint for each request,
 * similar to the S3 Tables approach.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * JSON Helpers — simple extractors (no JSON library)
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool json_extract_string(const char *json, size_t json_len,
                                const char *key, char *dst, size_t dst_size)
{
    if (!json || !key || !dst || dst_size == 0) return false;

    char pattern[512];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *end = json + json_len;
    const char *p = json;

    while (p < end) {
        const char *found = strstr(p, pattern);
        if (!found || found >= end) break;

        const char *after_key = found + strlen(pattern);
        while (after_key < end && (*after_key == ' ' || *after_key == '\t' ||
               *after_key == '\n' || *after_key == '\r')) after_key++;
        if (after_key >= end || *after_key != ':') { p = found + 1; continue; }
        after_key++;
        while (after_key < end && (*after_key == ' ' || *after_key == '\t' ||
               *after_key == '\n' || *after_key == '\r')) after_key++;
        if (after_key >= end || *after_key != '"') { p = found + 1; continue; }
        after_key++;

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

static bool json_extract_int(const char *json, size_t json_len,
                             const char *key, int *out)
{
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *end = json + json_len;
    const char *found = strstr(json, pattern);
    if (!found || found >= end) return false;

    const char *after = found + strlen(pattern);
    while (after < end && (*after == ' ' || *after == '\t' ||
           *after == '\n' || *after == '\r')) after++;
    if (after >= end || *after != ':') return false;
    after++;
    while (after < end && (*after == ' ' || *after == '\t' ||
           *after == '\n' || *after == '\r')) after++;
    if (after >= end) return false;

    /* Might be quoted or not */
    if (*after == '"') {
        after++;
        *out = (int)strtol(after, nullptr, 10);
    } else {
        *out = (int)strtol(after, nullptr, 10);
    }
    return true;
}

static bool json_extract_float(const char *json, size_t json_len,
                               const char *key, float *out)
{
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *end = json + json_len;
    const char *found = strstr(json, pattern);
    if (!found || found >= end) return false;

    const char *after = found + strlen(pattern);
    while (after < end && (*after == ' ' || *after == '\t' ||
           *after == '\n' || *after == '\r')) after++;
    if (after >= end || *after != ':') return false;
    after++;
    while (after < end && (*after == ' ' || *after == '\t' ||
           *after == '\n' || *after == '\r')) after++;
    if (after >= end) return false;

    *out = strtof(after, nullptr);
    return true;
}

/* json_extract_float used below */

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

static const char *json_nth_object(const char *array_start, size_t len,
                                   int n, size_t *obj_len)
{
    int count = 0;
    int depth = 0;
    const char *obj_start = nullptr;

    for (size_t i = 0; i < len; i++) {
        if (array_start[i] == '{') {
            if (depth == 0) {
                if (count == n) obj_start = array_start + i;
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

/*
 * Parse a JSON float array like [1.0, 2.5, 3.0] into a float buffer.
 * Returns number of floats parsed.
 */
static int json_parse_float_array(const char *arr, size_t arr_len,
                                  float *out, int max_count)
{
    int count = 0;
    const char *p = arr;
    const char *end = arr + arr_len;

    /* Skip '[' */
    if (p < end && *p == '[') p++;

    while (p < end && count < max_count) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' ||
               *p == '\r' || *p == ',')) p++;
        if (p >= end || *p == ']') break;

        char *next = nullptr;
        out[count] = strtof(p, &next);
        if (next == p) break;
        count++;
        p = next;
    }
    return count;
}

/* json_parse_float_array used below */

/* ═══════════════════════════════════════════════════════════════════════════
 * S3 Vectors endpoint helper
 * ═══════════════════════════════════════════════════════════════════════════ */

static s3_status s3_vectors_request(s3_client *c, const s3_request_params *params)
{
    char *saved_endpoint = c->endpoint;
    bool saved_path_style = c->use_path_style;

    char vectors_endpoint[256];
    snprintf(vectors_endpoint, sizeof(vectors_endpoint),
             "s3vectors.%s.amazonaws.com", c->region);
    c->endpoint = vectors_endpoint;
    c->use_path_style = true;

    s3_status status = s3__request(c, params);

    c->endpoint = saved_endpoint;
    c->use_path_style = saved_path_style;

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Parse helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_vector_bucket(const char *json, size_t len, s3_vector_bucket *out)
{
    memset(out, 0, sizeof(*out));
    json_extract_string(json, len, "name", out->name, sizeof(out->name));
    json_extract_string(json, len, "arn", out->arn, sizeof(out->arn));
    json_extract_string(json, len, "createdAt", out->created_at, sizeof(out->created_at));
    json_extract_string(json, len, "encryptionType", out->encryption_type, sizeof(out->encryption_type));
}

static const char *distance_metric_string(s3_vector_distance_metric m)
{
    switch (m) {
    case S3_VECTOR_EUCLIDEAN:   return "euclidean";
    case S3_VECTOR_COSINE:      return "cosine";
    case S3_VECTOR_DOT_PRODUCT: return "dotProduct";
    }
    return "euclidean";
}

static s3_vector_distance_metric distance_metric_from_string(const char *s)
{
    if (!s) return S3_VECTOR_EUCLIDEAN;
    if (strcasecmp(s, "cosine") == 0)     return S3_VECTOR_COSINE;
    if (strcasecmp(s, "dotProduct") == 0 ||
        strcasecmp(s, "dot_product") == 0) return S3_VECTOR_DOT_PRODUCT;
    return S3_VECTOR_EUCLIDEAN;
}

static void parse_vector_index(const char *json, size_t len, s3_vector_index *out)
{
    memset(out, 0, sizeof(*out));
    json_extract_string(json, len, "name", out->name, sizeof(out->name));
    json_extract_string(json, len, "arn", out->arn, sizeof(out->arn));
    json_extract_int(json, len, "dimension", &out->dimension);
    json_extract_string(json, len, "createdAt", out->created_at, sizeof(out->created_at));

    char metric_str[64] = "";
    json_extract_string(json, len, "distanceMetric", metric_str, sizeof(metric_str));
    out->distance_metric = distance_metric_from_string(metric_str);
}

/*
 * Parse a single vector object from JSON.
 * The caller is responsible for freeing the returned s3_vector fields.
 */
static void parse_vector(const char *json, size_t len, s3_vector *out)
{
    memset(out, 0, sizeof(*out));

    char key_buf[1024] = "";
    json_extract_string(json, len, "key", key_buf, sizeof(key_buf));
    out->key = s3__strdup(key_buf);

    /* Parse vector data array */
    size_t arr_len = 0;
    const char *arr = json_find_array(json, len, "data", &arr_len);
    if (arr && arr_len > 2) {
        /* First pass: count floats */
        float tmp[4096];
        int n = json_parse_float_array(arr, arr_len, tmp,
                                       (int)S3_ARRAY_LEN(tmp));
        if (n > 0) {
            out->data = (float *)S3_MALLOC((size_t)n * sizeof(float));
            if (out->data) {
                memcpy(out->data, tmp, (size_t)n * sizeof(float));
                out->dimension = n;
            }
        }
    }

    /* Metadata not parsed for simplicity - left as nullptr/0 */
    out->metadata = nullptr;
    out->metadata_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Vector Bucket Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * s3_create_vector_bucket — POST /buckets
 * Body: {"name": "<name>"}
 */
s3_status s3_create_vector_bucket(s3_client *c, const char *name,
                                  s3_vector_bucket *result)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

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

    s3_status status = s3_vectors_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_vector_bucket(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_delete_vector_bucket — DELETE /buckets/{name}
 */
s3_status s3_delete_vector_bucket(s3_client *c, const char *name)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[256];
    snprintf(path, sizeof(path), "buckets/%s", name);

    s3_request_params params = {
        .method           = "DELETE",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    return s3_vectors_request(c, &params);
}

/*
 * s3_get_vector_bucket — GET /buckets/{name}
 */
s3_status s3_get_vector_bucket(s3_client *c, const char *name,
                               s3_vector_bucket *result)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[256];
    snprintf(path, sizeof(path), "buckets/%s", name);

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_vector_bucket(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_list_vector_buckets — GET /buckets
 * Query: continuationToken=...&maxBuckets=...
 */
s3_status s3_list_vector_buckets(s3_client *c, const char *continuation_token,
                                 int max_buckets,
                                 s3_vector_bucket **buckets_out, int *count_out)
{
    if (!c || !buckets_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *buckets_out = nullptr;
    *count_out = 0;

    char query[1024] = "";
    int off = 0;
    if (max_buckets > 0) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "maxBuckets=%d", max_buckets);
    }
    if (continuation_token && continuation_token[0]) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "%scontinuationToken=%s",
                        off > 0 ? "&" : "", continuation_token);
    }
    (void)off;

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = "buckets",
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "vectorBuckets", &arr_len);
        if (!arr) {
            arr = json_find_array(c->response.data, c->response.len,
                                  "buckets", &arr_len);
        }

        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_vector_bucket *results = (s3_vector_bucket *)S3_CALLOC(
                    (size_t)n, sizeof(s3_vector_bucket));
                if (!results) return S3_STATUS_OUT_OF_MEMORY;

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) parse_vector_bucket(obj, obj_len, &results[i]);
                }
                *buckets_out = results;
                *count_out = n;
            }
        }
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Index Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * s3_create_index — POST /buckets/{vectorBucket}/indexes
 * Body: {"name": "...", "dimension": N, "distanceMetric": "..."}
 */
s3_status s3_create_index(s3_client *c, const char *vector_bucket,
                          const char *index_name, int dimension,
                          s3_vector_distance_metric metric,
                          s3_vector_index *result)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0] || dimension <= 0)
        return S3_STATUS_INVALID_ARGUMENT;

    char body[1024];
    snprintf(body, sizeof(body),
             "{\"name\":\"%s\",\"dimension\":%d,\"distanceMetric\":\"%s\"}",
             index_name, dimension, distance_metric_string(metric));

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes", vector_bucket);

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

    s3_status status = s3_vectors_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_vector_index(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_delete_index — DELETE /buckets/{vectorBucket}/indexes/{indexName}
 */
s3_status s3_delete_index(s3_client *c, const char *vector_bucket,
                          const char *index_name)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s",
             vector_bucket, index_name);

    s3_request_params params = {
        .method           = "DELETE",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    return s3_vectors_request(c, &params);
}

/*
 * s3_get_index — GET /buckets/{vectorBucket}/indexes/{indexName}
 */
s3_status s3_get_index(s3_client *c, const char *vector_bucket,
                       const char *index_name, s3_vector_index *result)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s",
             vector_bucket, index_name);

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_vector_index(c->response.data, c->response.len, result);
    }

    return status;
}

/*
 * s3_list_indexes — GET /buckets/{vectorBucket}/indexes
 * Query: continuationToken=...&maxIndexes=...
 */
s3_status s3_list_indexes(s3_client *c, const char *vector_bucket,
                          const char *continuation_token, int max_indexes,
                          s3_vector_index **indexes_out, int *count_out)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !indexes_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *indexes_out = nullptr;
    *count_out = 0;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes", vector_bucket);

    char query[1024] = "";
    int off = 0;
    if (max_indexes > 0) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "maxIndexes=%d", max_indexes);
    }
    if (continuation_token && continuation_token[0]) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "%scontinuationToken=%s",
                        off > 0 ? "&" : "", continuation_token);
    }
    (void)off;

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "indexes", &arr_len);
        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_vector_index *results = (s3_vector_index *)S3_CALLOC(
                    (size_t)n, sizeof(s3_vector_index));
                if (!results) return S3_STATUS_OUT_OF_MEMORY;

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) parse_vector_index(obj, obj_len, &results[i]);
                }
                *indexes_out = results;
                *count_out = n;
            }
        }
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Vector CRUD Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Build a JSON float array string from a float pointer.
 * Writes "[1.0,2.0,3.0]" into buf.
 */
static int build_float_array(const float *data, int dim, char *buf, size_t buf_size)
{
    int written = 0;
    written += snprintf(buf + written, buf_size - (size_t)written, "[");
    for (int i = 0; i < dim; i++) {
        if (i > 0)
            written += snprintf(buf + written, buf_size - (size_t)written, ",");
        written += snprintf(buf + written, buf_size - (size_t)written, "%g",
                            (double)data[i]);
        if ((size_t)written >= buf_size - 1) break;
    }
    written += snprintf(buf + written, buf_size - (size_t)written, "]");
    return written;
}

/*
 * s3_put_vectors — POST /buckets/{vectorBucket}/indexes/{indexName}/vectors
 * Body: {"vectors": [{"key":"k1","data":[1.0,2.0]}, ...]}
 */
s3_status s3_put_vectors(s3_client *c, const char *vector_bucket,
                         const char *index_name,
                         const s3_vector *vectors, int vector_count)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0] || !vectors || vector_count <= 0)
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s/vectors",
             vector_bucket, index_name);

    /* Build JSON body using growable buffer */
    s3_buf body;
    s3_buf_init(&body);
    s3_buf_append_str(&body, "{\"vectors\":[");

    for (int i = 0; i < vector_count; i++) {
        if (i > 0) s3_buf_append_str(&body, ",");

        s3_buf_append_str(&body, "{\"key\":\"");
        if (vectors[i].key)
            s3_buf_append_str(&body, vectors[i].key);
        s3_buf_append_str(&body, "\",\"data\":");

        /* Float array */
        char float_buf[16384];
        build_float_array(vectors[i].data, vectors[i].dimension,
                          float_buf, sizeof(float_buf));
        s3_buf_append_str(&body, float_buf);

        /* Metadata if present */
        if (vectors[i].metadata && vectors[i].metadata_count > 0) {
            s3_buf_append_str(&body, ",\"metadata\":{");
            for (int m = 0; m < vectors[i].metadata_count; m++) {
                if (m > 0) s3_buf_append_str(&body, ",");
                char meta_frag[1024];
                snprintf(meta_frag, sizeof(meta_frag), "\"%s\":\"%s\"",
                         vectors[i].metadata[m].key,
                         vectors[i].metadata[m].value);
                s3_buf_append_str(&body, meta_frag);
            }
            s3_buf_append_str(&body, "}");
        }

        s3_buf_append_str(&body, "}");
    }

    s3_buf_append_str(&body, "]}");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/*
 * s3_get_vectors — POST /buckets/{vectorBucket}/indexes/{indexName}/vectors/get
 * Body: {"keys": ["k1","k2",...]}
 */
s3_status s3_get_vectors(s3_client *c, const char *vector_bucket,
                         const char *index_name,
                         const char *const *keys, int key_count,
                         s3_vector **vectors_out, int *count_out)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0] ||
        !keys || key_count <= 0 || !vectors_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *vectors_out = nullptr;
    *count_out = 0;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s/vectors/get",
             vector_bucket, index_name);

    /* Build JSON body */
    s3_buf body;
    s3_buf_init(&body);
    s3_buf_append_str(&body, "{\"keys\":[");
    for (int i = 0; i < key_count; i++) {
        if (i > 0) s3_buf_append_str(&body, ",");
        s3_buf_append_str(&body, "\"");
        if (keys[i]) s3_buf_append_str(&body, keys[i]);
        s3_buf_append_str(&body, "\"");
    }
    s3_buf_append_str(&body, "]}");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && c->response.data) {
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "vectors", &arr_len);
        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_vector *results = (s3_vector *)S3_CALLOC(
                    (size_t)n, sizeof(s3_vector));
                if (!results) { s3_buf_free(&body); return S3_STATUS_OUT_OF_MEMORY; }

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) parse_vector(obj, obj_len, &results[i]);
                }
                *vectors_out = results;
                *count_out = n;
            }
        }
    }

    s3_buf_free(&body);
    return status;
}

/*
 * s3_delete_vectors — POST /buckets/{vectorBucket}/indexes/{indexName}/vectors/delete
 * Body: {"keys": ["k1","k2",...]}
 */
s3_status s3_delete_vectors(s3_client *c, const char *vector_bucket,
                            const char *index_name,
                            const char *const *keys, int key_count)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0] || !keys || key_count <= 0)
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s/vectors/delete",
             vector_bucket, index_name);

    s3_buf body;
    s3_buf_init(&body);
    s3_buf_append_str(&body, "{\"keys\":[");
    for (int i = 0; i < key_count; i++) {
        if (i > 0) s3_buf_append_str(&body, ",");
        s3_buf_append_str(&body, "\"");
        if (keys[i]) s3_buf_append_str(&body, keys[i]);
        s3_buf_append_str(&body, "\"");
    }
    s3_buf_append_str(&body, "]}");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/*
 * s3_list_vectors — GET /buckets/{vectorBucket}/indexes/{indexName}/vectors
 * Query: continuationToken=...&maxVectors=...
 */
s3_status s3_list_vectors(s3_client *c, const char *vector_bucket,
                          const char *index_name,
                          const char *continuation_token, int max_vectors,
                          s3_vector **vectors_out, int *count_out)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0] ||
        !vectors_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *vectors_out = nullptr;
    *count_out = 0;

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s/vectors",
             vector_bucket, index_name);

    char query[1024] = "";
    int off = 0;
    if (max_vectors > 0) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "maxVectors=%d", max_vectors);
    }
    if (continuation_token && continuation_token[0]) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "%scontinuationToken=%s",
                        off > 0 ? "&" : "", continuation_token);
    }
    (void)off;

    s3_request_params params = {
        .method           = "GET",
        .bucket           = nullptr,
        .key              = path,
        .query_string     = query[0] ? query : nullptr,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "vectors", &arr_len);
        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                s3_vector *results = (s3_vector *)S3_CALLOC(
                    (size_t)n, sizeof(s3_vector));
                if (!results) return S3_STATUS_OUT_OF_MEMORY;

                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) parse_vector(obj, obj_len, &results[i]);
                }
                *vectors_out = results;
                *count_out = n;
            }
        }
    }

    return status;
}

/*
 * s3_query_vectors — POST /buckets/{vectorBucket}/indexes/{indexName}/vectors/query
 * Body: {"queryVector": [...], "topK": N, "filter": "..."}
 */
s3_status s3_query_vectors(s3_client *c, const char *vector_bucket,
                           const char *index_name,
                           const float *query_vector, int dimension,
                           int top_k, const char *filter_expression,
                           s3_vector_query_result *result)
{
    if (!c || !vector_bucket || !vector_bucket[0] ||
        !index_name || !index_name[0] ||
        !query_vector || dimension <= 0 || top_k <= 0 || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char path[512];
    snprintf(path, sizeof(path), "buckets/%s/indexes/%s/vectors/query",
             vector_bucket, index_name);

    /* Build JSON body */
    s3_buf body;
    s3_buf_init(&body);
    s3_buf_append_str(&body, "{\"queryVector\":");

    /* Float array */
    char float_buf[16384];
    build_float_array(query_vector, dimension, float_buf, sizeof(float_buf));
    s3_buf_append_str(&body, float_buf);

    {
        char frag[128];
        snprintf(frag, sizeof(frag), ",\"topK\":%d", top_k);
        s3_buf_append_str(&body, frag);
    }

    if (filter_expression && filter_expression[0]) {
        s3_buf_append_str(&body, ",\"filter\":\"");
        s3_buf_append_str(&body, filter_expression);
        s3_buf_append_str(&body, "\"");
    }

    s3_buf_append_str(&body, "}");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = nullptr,
        .key              = path,
        .extra_headers    = hdrs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3_vectors_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && c->response.data) {
        /* Parse results array of {key, data, distance} objects */
        size_t arr_len = 0;
        const char *arr = json_find_array(c->response.data, c->response.len,
                                          "results", &arr_len);
        if (!arr) {
            arr = json_find_array(c->response.data, c->response.len,
                                  "vectors", &arr_len);
        }

        if (arr) {
            int n = json_count_objects(arr, arr_len);
            if (n > 0) {
                result->vectors = (s3_vector *)S3_CALLOC(
                    (size_t)n, sizeof(s3_vector));
                result->distances = (float *)S3_CALLOC(
                    (size_t)n, sizeof(float));
                if (!result->vectors || !result->distances) {
                    S3_FREE(result->vectors);
                    S3_FREE(result->distances);
                    result->vectors = nullptr;
                    result->distances = nullptr;
                    s3_buf_free(&body);
                    return S3_STATUS_OUT_OF_MEMORY;
                }

                result->count = n;
                for (int i = 0; i < n; i++) {
                    size_t obj_len = 0;
                    const char *obj = json_nth_object(arr, arr_len, i, &obj_len);
                    if (obj) {
                        parse_vector(obj, obj_len, &result->vectors[i]);

                        /* Extract distance */
                        float dist = 0.0f;
                        json_extract_float(obj, obj_len, "distance", &dist);
                        result->distances[i] = dist;
                    }
                }
            }
        }
    }

    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Free function
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_vector_query_result_free(s3_vector_query_result *r)
{
    if (!r) return;

    if (r->vectors) {
        for (int i = 0; i < r->count; i++) {
            S3_FREE(r->vectors[i].key);
            S3_FREE(r->vectors[i].data);
            if (r->vectors[i].metadata) {
                for (int m = 0; m < r->vectors[i].metadata_count; m++) {
                    S3_FREE((void *)r->vectors[i].metadata[m].key);
                    S3_FREE((void *)r->vectors[i].metadata[m].value);
                }
                S3_FREE(r->vectors[i].metadata);
            }
        }
        S3_FREE(r->vectors);
    }
    S3_FREE(r->distances);

    r->vectors = nullptr;
    r->distances = nullptr;
    r->count = 0;
}
