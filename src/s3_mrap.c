/*
 * libs3 -- S3 Control API: Multi-Region Access Points
 *
 * CreateMultiRegionAccessPoint, DeleteMultiRegionAccessPoint,
 * GetMultiRegionAccessPoint, ListMultiRegionAccessPoints,
 * DescribeMultiRegionAccessPointOperation, result free.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Build the x-amz-account-id header list
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *account_id_header(const s3_client *c)
{
    char hdr[256];
    snprintf(hdr, sizeof(hdr), "x-amz-account-id: %s",
             c->account_id ? c->account_id : "");
    return curl_slist_append(nullptr, hdr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Parse MRAP from XML
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_mrap(const char *xml, size_t len, s3_mrap *r)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "Name", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->name, sizeof(r->name));
    if (s3__xml_find(xml, len, "Alias", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->alias, sizeof(r->alias));
    if (s3__xml_find(xml, len, "AccessPointArn", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->arn, sizeof(r->arn));
    if (s3__xml_find(xml, len, "Status", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->status, sizeof(r->status));
    if (s3__xml_find(xml, len, "CreatedAt", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->created_at, sizeof(r->created_at));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_multi_region_access_point
 * POST /v20180820/async-requests/mrap/create
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_multi_region_access_point(
    s3_client *c, const char *name,
    const char *const *regions, const char *const *buckets, int count,
    char *request_token_out, size_t token_buf_size)
{
    if (!c || !name || !regions || !buckets || count <= 0 ||
        !request_token_out || token_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;

    request_token_out[0] = '\0';

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateMultiRegionAccessPointRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_open(&body, "Details");
    s3__xml_buf_element(&body, "Name", name);
    s3__xml_buf_open(&body, "Regions");
    for (int i = 0; i < count; i++) {
        s3__xml_buf_open(&body, "Region");
        s3__xml_buf_element(&body, "Bucket", buckets[i]);
        s3__xml_buf_element(&body, "BucketAccountId", c->account_id ? c->account_id : "");
        s3__xml_buf_element(&body, "Region", regions[i]);
        s3__xml_buf_close(&body, "Region");
    }
    s3__xml_buf_close(&body, "Regions");
    s3__xml_buf_close(&body, "Details");
    s3_buf_append_str(&body, "</CreateMultiRegionAccessPointRequest>");

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "v20180820/async-requests/mrap/create",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *val;
        size_t vlen;
        if (s3__xml_find(c->response.data, c->response.len,
                         "RequestTokenARN", &val, &vlen)) {
            size_t n = vlen < token_buf_size - 1 ? vlen : token_buf_size - 1;
            memcpy(request_token_out, val, n);
            request_token_out[n] = '\0';
        }
    }

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_multi_region_access_point
 * POST /v20180820/async-requests/mrap/delete
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_multi_region_access_point(
    s3_client *c, const char *name,
    char *request_token_out, size_t token_buf_size)
{
    if (!c || !name || !request_token_out || token_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;

    request_token_out[0] = '\0';

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<DeleteMultiRegionAccessPointRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_open(&body, "Details");
    s3__xml_buf_element(&body, "Name", name);
    s3__xml_buf_close(&body, "Details");
    s3_buf_append_str(&body, "</DeleteMultiRegionAccessPointRequest>");

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "v20180820/async-requests/mrap/delete",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *val;
        size_t vlen;
        if (s3__xml_find(c->response.data, c->response.len,
                         "RequestTokenARN", &val, &vlen)) {
            size_t n = vlen < token_buf_size - 1 ? vlen : token_buf_size - 1;
            memcpy(request_token_out, val, n);
            request_token_out[n] = '\0';
        }
    }

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_multi_region_access_point
 * GET /v20180820/mrap/instances/{name}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_multi_region_access_point(
    s3_client *c, const char *name, s3_mrap *result)
{
    if (!c || !name || !name[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char path[512];
    snprintf(path, sizeof(path), "v20180820/mrap/instances/%s", name);

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = path,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data)
        parse_mrap(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_multi_region_access_points
 * GET /v20180820/mrap/instances
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    s3_mrap *items;
    int      count;
    int      cap;
} mrap_array;

static int mrap_array_cb(const char *element, size_t element_len, void *userdata)
{
    mrap_array *arr = (mrap_array *)userdata;

    if (arr->count >= arr->cap) {
        int new_cap = arr->cap ? arr->cap * 2 : 16;
        s3_mrap *p = (s3_mrap *)S3_REALLOC(
            arr->items, (size_t)new_cap * sizeof(s3_mrap));
        if (!p) return -1;
        arr->items = p;
        arr->cap = new_cap;
    }

    s3_mrap *m = &arr->items[arr->count];
    memset(m, 0, sizeof(*m));
    parse_mrap(element, element_len, m);
    arr->count++;
    return 0;
}

s3_status s3_list_multi_region_access_points(
    s3_client *c, const char *next_token, int max_results,
    s3_list_mrap_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qbuf;
    s3_buf_init(&qbuf);

    if (next_token && next_token[0]) {
        s3_buf_append_str(&qbuf, "nextToken=");
        s3_buf_append_str(&qbuf, next_token);
    }
    if (max_results > 0) {
        if (qbuf.len > 0) s3_buf_append_str(&qbuf, "&");
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "maxResults=%d", max_results);
        s3_buf_append_str(&qbuf, tmp);
    }

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = "v20180820/mrap/instances",
        .query_string        = qbuf.len > 0 ? qbuf.data : nullptr,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *xml = c->response.data;
        size_t len = c->response.len;

        /* Parse access points list */
        mrap_array arr = {0};
        s3__xml_each(xml, len, "AccessPoint", mrap_array_cb, &arr);

        result->mraps = arr.items;
        result->count = arr.count;

        /* Parse NextToken */
        const char *val;
        size_t vlen;
        if (s3__xml_find(xml, len, "NextToken", &val, &vlen))
            s3__xml_decode_entities(val, vlen, result->next_token,
                                    sizeof(result->next_token));
    }

    curl_slist_free_all(hdrs);
    s3_buf_free(&qbuf);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_describe_multi_region_access_point_operation
 * GET /v20180820/async-requests/mrap/{token}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_describe_multi_region_access_point_operation(
    s3_client *c, const char *request_token,
    char *status_out, size_t status_buf_size)
{
    if (!c || !request_token || !request_token[0] ||
        !status_out || status_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;

    status_out[0] = '\0';

    char path[1024];
    snprintf(path, sizeof(path),
             "v20180820/async-requests/mrap/%s", request_token);

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = path,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *val;
        size_t vlen;
        if (s3__xml_find(c->response.data, c->response.len,
                         "RequestStatus", &val, &vlen)) {
            size_t n = vlen < status_buf_size - 1 ? vlen : status_buf_size - 1;
            memcpy(status_out, val, n);
            status_out[n] = '\0';
        }
    }

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_mrap_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_mrap_result_free(s3_list_mrap_result *r)
{
    if (!r) return;
    S3_FREE(r->mraps);
    r->mraps = nullptr;
    r->count = 0;
    r->next_token[0] = '\0';
}
