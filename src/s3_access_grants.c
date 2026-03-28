/*
 * libs3 -- S3 Control API: Access Grants
 *
 * CreateAccessGrantsInstance, DeleteAccessGrantsInstance,
 * GetAccessGrantsInstance, CreateAccessGrantsLocation,
 * DeleteAccessGrantsLocation, GetAccessGrantsLocation,
 * CreateAccessGrant, DeleteAccessGrant, GetAccessGrant,
 * GetDataAccess.
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
 * Helper — Parse access grants instance from XML
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_instance(const char *xml, size_t len,
                           s3_access_grants_instance *r)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "AccessGrantsInstanceArn", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->instance_arn, sizeof(r->instance_arn));
    if (s3__xml_find(xml, len, "AccessGrantsInstanceId", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->instance_id, sizeof(r->instance_id));
    if (s3__xml_find(xml, len, "IdentityCenterArn", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->identity_center_arn, sizeof(r->identity_center_arn));
    if (s3__xml_find(xml, len, "CreatedAt", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->created_at, sizeof(r->created_at));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Parse access grants location from XML
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_location(const char *xml, size_t len,
                           s3_access_grants_location *r)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "AccessGrantsLocationId", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->location_id, sizeof(r->location_id));
    if (s3__xml_find(xml, len, "LocationScope", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->location_scope, sizeof(r->location_scope));
    if (s3__xml_find(xml, len, "IAMRoleArn", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->iam_role_arn, sizeof(r->iam_role_arn));
    if (s3__xml_find(xml, len, "CreatedAt", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->created_at, sizeof(r->created_at));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Parse access grant from XML
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_grant(const char *xml, size_t len, s3_access_grant *r)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "AccessGrantId", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->grant_id, sizeof(r->grant_id));
    if (s3__xml_find(xml, len, "AccessGrantArn", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->grant_arn, sizeof(r->grant_arn));
    if (s3__xml_find(xml, len, "GranteeType", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->grantee_type, sizeof(r->grantee_type));
    if (s3__xml_find(xml, len, "GranteeIdentifier", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->grantee_id, sizeof(r->grantee_id));
    if (s3__xml_find(xml, len, "Permission", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->permission, sizeof(r->permission));
    if (s3__xml_find(xml, len, "AccessGrantsLocationId", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->location_id, sizeof(r->location_id));
    if (s3__xml_find(xml, len, "LocationScope", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->location_scope, sizeof(r->location_scope));
    if (s3__xml_find(xml, len, "CreatedAt", &val, &vlen))
        s3__xml_decode_entities(val, vlen, r->created_at, sizeof(r->created_at));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_access_grants_instance
 * POST /v20180820/accessgrantsinstance
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_access_grants_instance(
    s3_client *c, const char *identity_center_arn,
    s3_access_grants_instance *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateAccessGrantsInstanceRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    if (identity_center_arn && identity_center_arn[0])
        s3__xml_buf_element(&body, "IdentityCenterArn", identity_center_arn);
    s3_buf_append_str(&body, "</CreateAccessGrantsInstanceRequest>");

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "v20180820/accessgrantsinstance",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data)
        parse_instance(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_access_grants_instance
 * DELETE /v20180820/accessgrantsinstance
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_grants_instance(s3_client *c)
{
    if (!c)
        return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "DELETE",
        .bucket              = nullptr,
        .key                 = "v20180820/accessgrantsinstance",
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_access_grants_instance
 * GET /v20180820/accessgrantsinstance
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_grants_instance(
    s3_client *c, s3_access_grants_instance *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = "v20180820/accessgrantsinstance",
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data)
        parse_instance(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_access_grants_location
 * POST /v20180820/accessgrantsinstance/location
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_access_grants_location(
    s3_client *c, const char *location_scope, const char *iam_role_arn,
    s3_access_grants_location *result)
{
    if (!c || !location_scope || !iam_role_arn || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateAccessGrantsLocationRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_element(&body, "LocationScope", location_scope);
    s3__xml_buf_element(&body, "IAMRoleArn", iam_role_arn);
    s3_buf_append_str(&body, "</CreateAccessGrantsLocationRequest>");

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "v20180820/accessgrantsinstance/location",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data)
        parse_location(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_access_grants_location
 * DELETE /v20180820/accessgrantsinstance/location/{id}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_grants_location(
    s3_client *c, const char *location_id)
{
    if (!c || !location_id || !location_id[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accessgrantsinstance/location/%s", location_id);

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "DELETE",
        .bucket              = nullptr,
        .key                 = path,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_access_grants_location
 * GET /v20180820/accessgrantsinstance/location/{id}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_grants_location(
    s3_client *c, const char *location_id, s3_access_grants_location *result)
{
    if (!c || !location_id || !location_id[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accessgrantsinstance/location/%s", location_id);

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
        parse_location(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_access_grant
 * POST /v20180820/accessgrantsinstance/grant
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_access_grant(
    s3_client *c, const char *location_id,
    const char *grantee_type, const char *grantee_id,
    const char *permission, s3_access_grant *result)
{
    if (!c || !location_id || !grantee_type || !grantee_id ||
        !permission || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateAccessGrantRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_element(&body, "AccessGrantsLocationId", location_id);
    s3__xml_buf_open(&body, "Grantee");
    s3__xml_buf_element(&body, "GranteeType", grantee_type);
    s3__xml_buf_element(&body, "GranteeIdentifier", grantee_id);
    s3__xml_buf_close(&body, "Grantee");
    s3__xml_buf_element(&body, "Permission", permission);
    s3_buf_append_str(&body, "</CreateAccessGrantRequest>");

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "v20180820/accessgrantsinstance/grant",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data)
        parse_grant(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_access_grant
 * DELETE /v20180820/accessgrantsinstance/grant/{id}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_access_grant(s3_client *c, const char *grant_id)
{
    if (!c || !grant_id || !grant_id[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accessgrantsinstance/grant/%s", grant_id);

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "DELETE",
        .bucket              = nullptr,
        .key                 = path,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_access_grant
 * GET /v20180820/accessgrantsinstance/grant/{id}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_access_grant(
    s3_client *c, const char *grant_id, s3_access_grant *result)
{
    if (!c || !grant_id || !grant_id[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char path[512];
    snprintf(path, sizeof(path),
             "v20180820/accessgrantsinstance/grant/%s", grant_id);

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
        parse_grant(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_get_data_access
 * GET /v20180820/accessgrantsinstance/dataaccess?...
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_data_access(
    s3_client *c, const char *target, const char *permission,
    int duration_seconds, s3_session_credentials *result)
{
    if (!c || !target || !permission || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    char query[2048];
    if (duration_seconds > 0) {
        snprintf(query, sizeof(query),
                 "target=%s&permission=%s&durationSeconds=%d",
                 target, permission, duration_seconds);
    } else {
        snprintf(query, sizeof(query),
                 "target=%s&permission=%s",
                 target, permission);
    }

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = "v20180820/accessgrantsinstance/dataaccess",
        .query_string        = query,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *xml = c->response.data;
        size_t len = c->response.len;
        const char *val;
        size_t vlen;

        /* Parse Credentials block */
        if (s3__xml_find_in(xml, len, "Credentials", "AccessKeyId", &val, &vlen))
            s3__xml_decode_entities(val, vlen, result->access_key_id,
                                    sizeof(result->access_key_id));
        if (s3__xml_find_in(xml, len, "Credentials", "SecretAccessKey", &val, &vlen))
            s3__xml_decode_entities(val, vlen, result->secret_access_key,
                                    sizeof(result->secret_access_key));
        if (s3__xml_find_in(xml, len, "Credentials", "SessionToken", &val, &vlen))
            s3__xml_decode_entities(val, vlen, result->session_token,
                                    sizeof(result->session_token));
        if (s3__xml_find_in(xml, len, "Credentials", "Expiration", &val, &vlen))
            s3__xml_decode_entities(val, vlen, result->expiration,
                                    sizeof(result->expiration));
    }

    curl_slist_free_all(hdrs);
    return status;
}
