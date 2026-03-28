/*
 * libs3 -- S3 Control: Access Point operations
 *
 * All operations use the S3 Control endpoint:
 *   https://{account_id}.s3-control.{region}.amazonaws.com
 *
 * The API path prefix is /v20180820/accesspoint/{name}.
 * The x-amz-account-id header is required on every request.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: build x-amz-account-id header
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *add_account_id_header(struct curl_slist *hdrs,
                                                const s3_client *c)
{
    char hdr[512];
    snprintf(hdr, sizeof(hdr), "x-amz-account-id: %s",
             c->account_id ? c->account_id : "");
    return curl_slist_append(hdrs, hdr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_access_point — PUT /v20180820/accesspoint/{name}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_access_point(s3_client *c, const char *name,
                                 const char *bucket,
                                 const s3_public_access_block *block_config)
{
    if (!c || !name || !name[0] || !bucket || !bucket[0])
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build the API path */
    char path[512];
    snprintf(path, sizeof(path), "v20180820/accesspoint/%s", name);

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateAccessPointRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_element(&body, "Bucket", bucket);

    if (block_config) {
        s3__xml_buf_open(&body, "PublicAccessBlockConfiguration");
        s3__xml_buf_element_bool(&body, "BlockPublicAcls",
                                 block_config->block_public_acls);
        s3__xml_buf_element_bool(&body, "IgnorePublicAcls",
                                 block_config->ignore_public_acls);
        s3__xml_buf_element_bool(&body, "BlockPublicPolicy",
                                 block_config->block_public_policy);
        s3__xml_buf_element_bool(&body, "RestrictPublicBuckets",
                                 block_config->restrict_public_buckets);
        s3__xml_buf_close(&body, "PublicAccessBlockConfiguration");
    }

    s3_buf_append_str(&body, "</CreateAccessPointRequest>");

    /* Headers */
    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    s3_request_params params = {
        .method               = "PUT",
        .bucket               = nullptr,
        .key                  = path,
        .extra_headers        = hdrs,
        .upload_data          = body.data,
        .upload_len           = body.len,
        .collect_response     = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_access_point — DELETE /v20180820/accesspoint/{name}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_point(s3_client *c, const char *name)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/accesspoint/%s", name);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params params = {
        .method               = "DELETE",
        .bucket               = nullptr,
        .key                  = path,
        .extra_headers        = hdrs,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_access_point — GET /v20180820/accesspoint/{name}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_point(s3_client *c, const char *name,
                              s3_access_point *result)
{
    if (!c || !name || !name[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char path[512];
    snprintf(path, sizeof(path), "v20180820/accesspoint/%s", name);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params params = {
        .method               = "GET",
        .bucket               = nullptr,
        .key                  = path,
        .extra_headers        = hdrs,
        .collect_response     = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK) {
        curl_slist_free_all(hdrs);
        return status;
    }

    /* Parse the GetAccessPointResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, xml_len, "Name", &val, &vlen)) {
        size_t n = vlen < sizeof(result->name) - 1 ? vlen : sizeof(result->name) - 1;
        memcpy(result->name, val, n);
        result->name[n] = '\0';
    }
    if (s3__xml_find(xml, xml_len, "Bucket", &val, &vlen)) {
        size_t n = vlen < sizeof(result->bucket) - 1 ? vlen : sizeof(result->bucket) - 1;
        memcpy(result->bucket, val, n);
        result->bucket[n] = '\0';
    }
    if (s3__xml_find(xml, xml_len, "NetworkOrigin", &val, &vlen)) {
        size_t n = vlen < sizeof(result->network_origin) - 1
                       ? vlen : sizeof(result->network_origin) - 1;
        memcpy(result->network_origin, val, n);
        result->network_origin[n] = '\0';
    }
    if (s3__xml_find(xml, xml_len, "AccessPointArn", &val, &vlen)) {
        size_t n = vlen < sizeof(result->access_point_arn) - 1
                       ? vlen : sizeof(result->access_point_arn) - 1;
        memcpy(result->access_point_arn, val, n);
        result->access_point_arn[n] = '\0';
    }
    if (s3__xml_find(xml, xml_len, "Alias", &val, &vlen)) {
        size_t n = vlen < sizeof(result->alias) - 1 ? vlen : sizeof(result->alias) - 1;
        memcpy(result->alias, val, n);
        result->alias[n] = '\0';
    }
    if (s3__xml_find(xml, xml_len, "CreationDate", &val, &vlen)) {
        size_t n = vlen < sizeof(result->creation_date) - 1
                       ? vlen : sizeof(result->creation_date) - 1;
        memcpy(result->creation_date, val, n);
        result->creation_date[n] = '\0';
    }

    curl_slist_free_all(hdrs);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_access_points — GET /v20180820/accesspoint
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Callback context for parsing each <AccessPoint> element */
typedef struct {
    s3_access_point *items;
    int              count;
    int              cap;
} ap_list_ctx;

static int parse_access_point_element(const char *element, size_t element_len,
                                      void *userdata)
{
    ap_list_ctx *ctx = (ap_list_ctx *)userdata;

    /* Grow array if needed */
    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_access_point *p = (s3_access_point *)S3_REALLOC(
            ctx->items, (size_t)new_cap * sizeof(s3_access_point));
        if (!p) return -1;
        ctx->items = p;
        ctx->cap = new_cap;
    }

    s3_access_point *ap = &ctx->items[ctx->count];
    memset(ap, 0, sizeof(*ap));

    const char *val;
    size_t vlen;

    if (s3__xml_find(element, element_len, "Name", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->name) - 1);
        memcpy(ap->name, val, n);
        ap->name[n] = '\0';
    }
    if (s3__xml_find(element, element_len, "Bucket", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->bucket) - 1);
        memcpy(ap->bucket, val, n);
        ap->bucket[n] = '\0';
    }
    if (s3__xml_find(element, element_len, "NetworkOrigin", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->network_origin) - 1);
        memcpy(ap->network_origin, val, n);
        ap->network_origin[n] = '\0';
    }
    if (s3__xml_find(element, element_len, "AccessPointArn", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->access_point_arn) - 1);
        memcpy(ap->access_point_arn, val, n);
        ap->access_point_arn[n] = '\0';
    }
    if (s3__xml_find(element, element_len, "Alias", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->alias) - 1);
        memcpy(ap->alias, val, n);
        ap->alias[n] = '\0';
    }
    if (s3__xml_find(element, element_len, "CreationDate", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->creation_date) - 1);
        memcpy(ap->creation_date, val, n);
        ap->creation_date[n] = '\0';
    }

    ctx->count++;
    return 0;
}

s3_status s3_list_access_points(s3_client *c, const char *bucket,
                                const char *next_token, int max_results,
                                s3_list_access_points_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qs;
    s3_buf_init(&qs);

    if (bucket && bucket[0]) {
        s3_buf_append_str(&qs, "bucket=");
        s3_buf_append_str(&qs, bucket);
    }
    if (next_token && next_token[0]) {
        if (qs.len > 0) s3_buf_append_str(&qs, "&");
        s3_buf_append_str(&qs, "nextToken=");
        s3_buf_append_str(&qs, next_token);
    }
    if (max_results > 0) {
        char mr[32];
        snprintf(mr, sizeof(mr), "%d", max_results);
        if (qs.len > 0) s3_buf_append_str(&qs, "&");
        s3_buf_append_str(&qs, "maxResults=");
        s3_buf_append_str(&qs, mr);
    }

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params params = {
        .method               = "GET",
        .bucket               = nullptr,
        .key                  = "v20180820/accesspoint",
        .query_string         = qs.len > 0 ? qs.data : nullptr,
        .extra_headers        = hdrs,
        .collect_response     = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK) {
        curl_slist_free_all(hdrs);
        s3_buf_free(&qs);
        return status;
    }

    /* Parse ListAccessPointsResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    ap_list_ctx ctx = { .items = nullptr, .count = 0, .cap = 0 };
    s3__xml_each(xml, xml_len, "AccessPoint", parse_access_point_element, &ctx);

    result->access_points = ctx.items;
    result->count = ctx.count;

    /* NextToken for pagination */
    const char *val;
    size_t vlen;
    if (s3__xml_find(xml, xml_len, "NextToken", &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(result->next_token) - 1);
        memcpy(result->next_token, val, n);
        result->next_token[n] = '\0';
    }

    curl_slist_free_all(hdrs);
    s3_buf_free(&qs);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_access_point_policy — GET /v20180820/accesspoint/{name}/policy
 * Returns JSON policy document.
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_point_policy(s3_client *c, const char *name,
                                     char **policy_json_out)
{
    if (!c || !name || !name[0] || !policy_json_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *policy_json_out = nullptr;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/accesspoint/%s/policy", name);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params params = {
        .method               = "GET",
        .bucket               = nullptr,
        .key                  = path,
        .extra_headers        = hdrs,
        .collect_response     = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK) {
        curl_slist_free_all(hdrs);
        return status;
    }

    /* The response body contains the JSON policy.
     * The actual JSON is inside the <Policy> XML element. */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, xml_len, "Policy", &val, &vlen)) {
        *policy_json_out = s3__strndup(val, vlen);
    } else {
        /* Fallback: treat entire response as the policy */
        *policy_json_out = s3__strndup(c->response.data, c->response.len);
    }

    curl_slist_free_all(hdrs);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_put_access_point_policy — PUT /v20180820/accesspoint/{name}/policy
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_put_access_point_policy(s3_client *c, const char *name,
                                     const char *policy_json)
{
    if (!c || !name || !name[0] || !policy_json)
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/accesspoint/%s/policy", name);

    /* Wrap the policy JSON in the XML envelope */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<PutAccessPointPolicyRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_element(&body, "Policy", policy_json);
    s3_buf_append_str(&body, "</PutAccessPointPolicyRequest>");

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    s3_request_params params = {
        .method               = "PUT",
        .bucket               = nullptr,
        .key                  = path,
        .extra_headers        = hdrs,
        .upload_data          = body.data,
        .upload_len           = body.len,
        .collect_response     = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_access_point_policy — DELETE /v20180820/accesspoint/{name}/policy
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_point_policy(s3_client *c, const char *name)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/accesspoint/%s/policy", name);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params params = {
        .method               = "DELETE",
        .bucket               = nullptr,
        .key                  = path,
        .extra_headers        = hdrs,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_access_points_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_access_points_result_free(s3_list_access_points_result *r)
{
    if (!r) return;
    S3_FREE(r->access_points);
    r->access_points = nullptr;
    r->count = 0;
    r->next_token[0] = '\0';
}
