/*
 * libs3 -- S3 on Outposts API
 *
 * S3 on Outposts uses the endpoint:
 *   https://s3-outposts.{region}.amazonaws.com
 *
 * Responses are XML. We use the control endpoint flag approach by
 * temporarily overriding the client endpoint.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * S3 Outposts endpoint helper
 * ═══════════════════════════════════════════════════════════════════════════ */

static s3_status s3_outposts_request(s3_client *c, const s3_request_params *params)
{
    char *saved_endpoint = c->endpoint;
    bool saved_path_style = c->use_path_style;

    char outposts_endpoint[256];
    snprintf(outposts_endpoint, sizeof(outposts_endpoint),
             "s3-outposts.%s.amazonaws.com", c->region);
    c->endpoint = outposts_endpoint;
    c->use_path_style = true;

    s3_status status = s3__request(c, params);

    c->endpoint = saved_endpoint;
    c->use_path_style = saved_path_style;

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML Parse helpers for outpost endpoints
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_outpost_endpoint(const char *xml, size_t len,
                                   s3_outpost_endpoint *out)
{
    memset(out, 0, sizeof(*out));

    const char *val = nullptr;
    size_t vlen = 0;

    if (s3__xml_find(xml, len, "EndpointArn", &val, &vlen)) {
        size_t n = vlen < sizeof(out->endpoint_arn) - 1 ? vlen : sizeof(out->endpoint_arn) - 1;
        memcpy(out->endpoint_arn, val, n);
        out->endpoint_arn[n] = '\0';
    }

    if (s3__xml_find(xml, len, "OutpostId", &val, &vlen)) {
        size_t n = vlen < sizeof(out->outpost_id) - 1 ? vlen : sizeof(out->outpost_id) - 1;
        memcpy(out->outpost_id, val, n);
        out->outpost_id[n] = '\0';
    }

    if (s3__xml_find(xml, len, "CidrBlock", &val, &vlen)) {
        size_t n = vlen < sizeof(out->cidr_block) - 1 ? vlen : sizeof(out->cidr_block) - 1;
        memcpy(out->cidr_block, val, n);
        out->cidr_block[n] = '\0';
    }

    if (s3__xml_find(xml, len, "Status", &val, &vlen)) {
        size_t n = vlen < sizeof(out->status) - 1 ? vlen : sizeof(out->status) - 1;
        memcpy(out->status, val, n);
        out->status[n] = '\0';
    }

    if (s3__xml_find(xml, len, "CreationTime", &val, &vlen)) {
        size_t n = vlen < sizeof(out->creation_time) - 1 ? vlen : sizeof(out->creation_time) - 1;
        memcpy(out->creation_time, val, n);
        out->creation_time[n] = '\0';
    }

    if (s3__xml_find(xml, len, "AccessType", &val, &vlen)) {
        size_t n = vlen < sizeof(out->access_type) - 1 ? vlen : sizeof(out->access_type) - 1;
        memcpy(out->access_type, val, n);
        out->access_type[n] = '\0';
    }

    if (s3__xml_find(xml, len, "SubnetId", &val, &vlen)) {
        size_t n = vlen < sizeof(out->subnet_id) - 1 ? vlen : sizeof(out->subnet_id) - 1;
        memcpy(out->subnet_id, val, n);
        out->subnet_id[n] = '\0';
    }

    if (s3__xml_find(xml, len, "SecurityGroupId", &val, &vlen)) {
        size_t n = vlen < sizeof(out->security_group_id) - 1 ? vlen : sizeof(out->security_group_id) - 1;
        memcpy(out->security_group_id, val, n);
        out->security_group_id[n] = '\0';
    }

    /* NetworkInterfaces is complex XML; store raw content for now */
    if (s3__xml_find(xml, len, "NetworkInterfaces", &val, &vlen)) {
        size_t n = vlen < sizeof(out->network_interfaces) - 1 ? vlen : sizeof(out->network_interfaces) - 1;
        memcpy(out->network_interfaces, val, n);
        out->network_interfaces[n] = '\0';
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_outpost_endpoint
 *
 * POST /S3Outposts/CreateEndpoint
 * Body XML: <CreateEndpointRequest>
 *             <OutpostId>...</OutpostId>
 *             <SubnetId>...</SubnetId>
 *             <SecurityGroupId>...</SecurityGroupId>
 *             <AccessType>...</AccessType>
 *           </CreateEndpointRequest>
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_outpost_endpoint(s3_client *c, const char *outpost_id,
                                     const char *subnet_id,
                                     const char *security_group_id,
                                     const char *access_type,
                                     s3_outpost_endpoint *result)
{
    if (!c || !outpost_id || !outpost_id[0])
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateEndpointRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_element(&body, "OutpostId", outpost_id);

    if (subnet_id && subnet_id[0])
        s3__xml_buf_element(&body, "SubnetId", subnet_id);

    if (security_group_id && security_group_id[0])
        s3__xml_buf_element(&body, "SecurityGroupId", security_group_id);

    if (access_type && access_type[0])
        s3__xml_buf_element(&body, "AccessType", access_type);

    s3_buf_append_str(&body, "</CreateEndpointRequest>");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "S3Outposts/CreateEndpoint",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3_outposts_request(c, &params);
    curl_slist_free_all(hdrs);

    if (status == S3_STATUS_OK && result && c->response.data) {
        parse_outpost_endpoint(c->response.data, c->response.len, result);
    }

    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_outpost_endpoint
 *
 * DELETE /S3Outposts/DeleteEndpoint?endpointId=...&outpostId=...
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_outpost_endpoint(s3_client *c, const char *endpoint_id,
                                     const char *outpost_id)
{
    if (!c || !endpoint_id || !endpoint_id[0] ||
        !outpost_id || !outpost_id[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char query[512];
    snprintf(query, sizeof(query), "endpointId=%s&outpostId=%s",
             endpoint_id, outpost_id);

    s3_request_params params = {
        .method              = "DELETE",
        .bucket              = nullptr,
        .key                 = "S3Outposts/DeleteEndpoint",
        .query_string        = query,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    return s3_outposts_request(c, &params);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_outpost_endpoints
 *
 * GET /S3Outposts/ListEndpoints?outpostId=...&nextToken=...&maxResults=...
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct list_endpoints_ctx {
    s3_outpost_endpoint *endpoints;
    int                  count;
    int                  cap;
} list_endpoints_ctx;

static int list_endpoints_each(const char *element, size_t element_len,
                               void *userdata)
{
    list_endpoints_ctx *ctx = (list_endpoints_ctx *)userdata;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_outpost_endpoint *p = (s3_outpost_endpoint *)S3_REALLOC(
            ctx->endpoints, (size_t)new_cap * sizeof(s3_outpost_endpoint));
        if (!p) return -1;
        ctx->endpoints = p;
        ctx->cap = new_cap;
    }

    parse_outpost_endpoint(element, element_len, &ctx->endpoints[ctx->count]);
    ctx->count++;
    return 0;
}

s3_status s3_list_outpost_endpoints(s3_client *c, const char *outpost_id,
                                    const char *next_token, int max_results,
                                    s3_outpost_endpoint **endpoints_out,
                                    int *count_out)
{
    if (!c || !outpost_id || !outpost_id[0] ||
        !endpoints_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *endpoints_out = nullptr;
    *count_out = 0;

    /* Build query string */
    char query[1024] = "";
    int off = 0;
    off += snprintf(query + off, sizeof(query) - (size_t)off,
                    "outpostId=%s", outpost_id);
    if (max_results > 0) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "&maxResults=%d", max_results);
    }
    if (next_token && next_token[0]) {
        off += snprintf(query + off, sizeof(query) - (size_t)off,
                        "&nextToken=%s", next_token);
    }
    (void)off;

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = "S3Outposts/ListEndpoints",
        .query_string        = query,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3_outposts_request(c, &params);

    if (status == S3_STATUS_OK && c->response.data && c->response.len > 0) {
        list_endpoints_ctx ctx = { .endpoints = nullptr, .count = 0, .cap = 0 };

        s3__xml_each(c->response.data, c->response.len,
                     "Endpoint", list_endpoints_each, &ctx);

        if (ctx.count > 0) {
            *endpoints_out = ctx.endpoints;
            *count_out = ctx.count;
        } else {
            S3_FREE(ctx.endpoints);
        }
    }

    return status;
}
