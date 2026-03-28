/*
 * libs3 -- S3 Control: Object Lambda Access Point operations
 *
 * All operations use the S3 Control endpoint:
 *   https://{account_id}.s3-control.{region}.amazonaws.com
 *
 * The API path prefix is /v20180820/accesspointforobjectlambda/{name}.
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
 * s3_create_access_point_for_object_lambda
 *   PUT /v20180820/accesspointforobjectlambda/{name}
 *
 * The caller provides the full Object Lambda configuration as XML.
 * A minimal configuration includes the SupportingAccessPoint and
 * TransformationConfigurations.
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_access_point_for_object_lambda(
    s3_client *c, const char *name, const char *supporting_access_point,
    const char *configuration_xml)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accesspointforobjectlambda/%s", name);

    /* Build XML body.  If the caller provides raw configuration_xml we wrap
     * it; if only supporting_access_point is given we build a minimal body. */
    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateAccessPointForObjectLambdaRequest "
        "xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_open(&body, "Configuration");

    if (supporting_access_point && supporting_access_point[0]) {
        s3__xml_buf_element(&body, "SupportingAccessPoint",
                            supporting_access_point);
    }

    /* Append caller-provided transformation configuration XML verbatim */
    if (configuration_xml && configuration_xml[0]) {
        s3_buf_append_str(&body, configuration_xml);
    }

    s3__xml_buf_close(&body, "Configuration");
    s3_buf_append_str(&body,
        "</CreateAccessPointForObjectLambdaRequest>");

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
 * s3_delete_access_point_for_object_lambda
 *   DELETE /v20180820/accesspointforobjectlambda/{name}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_point_for_object_lambda(s3_client *c,
                                                    const char *name)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accesspointforobjectlambda/%s", name);

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
 * s3_get_access_point_for_object_lambda
 *   GET /v20180820/accesspointforobjectlambda/{name}
 *
 * Returns the full Object Lambda configuration as XML in *config_xml_out.
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_point_for_object_lambda(s3_client *c,
                                                 const char *name,
                                                 char **config_xml_out)
{
    if (!c || !name || !name[0] || !config_xml_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *config_xml_out = nullptr;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accesspointforobjectlambda/%s", name);

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

    /* Return entire response XML -- the caller can parse configuration
     * details (SupportingAccessPoint, TransformationConfigurations, etc.) */
    *config_xml_out = s3__strndup(c->response.data, c->response.len);

    curl_slist_free_all(hdrs);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_access_points_for_object_lambda
 *   GET /v20180820/accesspointforobjectlambda
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Callback context for parsing each <ObjectLambdaAccessPoint> element */
typedef struct {
    s3_access_point *items;
    int              count;
    int              cap;
} ol_list_ctx;

static int parse_ol_access_point_element(const char *element,
                                         size_t element_len,
                                         void *userdata)
{
    ol_list_ctx *ctx = (ol_list_ctx *)userdata;

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
    if (s3__xml_find(element, element_len, "ObjectLambdaAccessPointArn",
                     &val, &vlen)) {
        size_t n = S3_MIN(vlen, sizeof(ap->access_point_arn) - 1);
        memcpy(ap->access_point_arn, val, n);
        ap->access_point_arn[n] = '\0';
    }

    ctx->count++;
    return 0;
}

s3_status s3_list_access_points_for_object_lambda(
    s3_client *c, const char *next_token, int max_results,
    s3_list_access_points_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qs;
    s3_buf_init(&qs);

    if (next_token && next_token[0]) {
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
        .key                  = "v20180820/accesspointforobjectlambda",
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

    /* Parse ListAccessPointsForObjectLambdaResult XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    ol_list_ctx ctx = { .items = nullptr, .count = 0, .cap = 0 };
    s3__xml_each(xml, xml_len, "ObjectLambdaAccessPoint",
                 parse_ol_access_point_element, &ctx);

    result->access_points = ctx.items;
    result->count = ctx.count;

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
 * s3_get_access_point_policy_for_object_lambda
 *   GET /v20180820/accesspointforobjectlambda/{name}/policy
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_point_policy_for_object_lambda(s3_client *c,
                                                        const char *name,
                                                        char **policy_json_out)
{
    if (!c || !name || !name[0] || !policy_json_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *policy_json_out = nullptr;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accesspointforobjectlambda/%s/policy", name);

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

    /* Extract JSON policy from response (may be wrapped in XML <Policy> tag) */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, xml_len, "Policy", &val, &vlen)) {
        *policy_json_out = s3__strndup(val, vlen);
    } else {
        *policy_json_out = s3__strndup(c->response.data, c->response.len);
    }

    curl_slist_free_all(hdrs);
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_put_access_point_policy_for_object_lambda
 *   PUT /v20180820/accesspointforobjectlambda/{name}/policy
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_put_access_point_policy_for_object_lambda(s3_client *c,
                                                        const char *name,
                                                        const char *policy_json)
{
    if (!c || !name || !name[0] || !policy_json)
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accesspointforobjectlambda/%s/policy", name);

    /* Wrap policy in XML envelope */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<PutAccessPointPolicyForObjectLambdaRequest "
        "xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_element(&body, "Policy", policy_json);
    s3_buf_append_str(&body,
        "</PutAccessPointPolicyForObjectLambdaRequest>");

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
 * s3_delete_access_point_policy_for_object_lambda
 *   DELETE /v20180820/accesspointforobjectlambda/{name}/policy
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_point_policy_for_object_lambda(s3_client *c,
                                                           const char *name)
{
    if (!c || !name || !name[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accesspointforobjectlambda/%s/policy", name);

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
