/*
 * libs3 -- Object configuration operations
 *
 * Tagging, ACL, legal hold, retention, and restore for individual objects.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Tagging
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Parse a single <Tag> element: extract <Key> and <Value>.
 */
static int parse_tag_cb(const char *element, size_t element_len, void *userdata)
{
    s3_tag_set *ts = (s3_tag_set *)userdata;

    const char *key_val   = nullptr;
    size_t      key_len   = 0;
    const char *value_val = nullptr;
    size_t      value_len = 0;

    if (!s3__xml_find(element, element_len, "Key", &key_val, &key_len))
        return 0;  /* skip malformed tag */
    s3__xml_find(element, element_len, "Value", &value_val, &value_len);

    /* Grow array */
    int new_count = ts->count + 1;
    s3_tag *p = (s3_tag *)S3_REALLOC(ts->tags, (size_t)new_count * sizeof(s3_tag));
    if (!p) return -1;
    ts->tags = p;

    s3_tag *t = &ts->tags[ts->count];
    memset(t, 0, sizeof(*t));
    s3__xml_decode_entities(key_val, key_len, t->key, sizeof(t->key));
    if (value_val)
        s3__xml_decode_entities(value_val, value_len, t->value, sizeof(t->value));

    ts->count = new_count;
    return 0;
}

s3_status s3_get_object_tagging(s3_client *c, const char *bucket, const char *key,
                                const char *version_id, s3_tag_set *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "tagging&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "tagging");

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    /* Parse <Tagging><TagSet><Tag>...</Tag></TagSet></Tagging> */
    const char *xml = c->response.data;
    size_t xml_len  = c->response.len;

    /* Find the <TagSet> block */
    const char *tagset_val = nullptr;
    size_t      tagset_len = 0;
    if (s3__xml_find(xml, xml_len, "TagSet", &tagset_val, &tagset_len)) {
        s3__xml_each(tagset_val, tagset_len, "Tag", parse_tag_cb, result);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_object_tagging(s3_client *c, const char *bucket, const char *key,
                                const char *version_id, const s3_tag *tags, int tag_count)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;
    if (tag_count > 0 && !tags)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<Tagging><TagSet>");

    for (int i = 0; i < tag_count; i++) {
        s3__xml_buf_open(&body, "Tag");
        s3__xml_buf_element(&body, "Key", tags[i].key);
        s3__xml_buf_element(&body, "Value", tags[i].value);
        s3__xml_buf_close(&body, "Tag");
    }

    s3_buf_append_str(&body, "</TagSet></Tagging>");

    /* Build query string */
    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "tagging&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "tagging");

    s3_request_params params = {
        .method           = "PUT",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    s3_buf_free(&body);
    return status;
}

s3_status s3_delete_object_tagging(s3_client *c, const char *bucket, const char *key,
                                   const char *version_id)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "tagging&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "tagging");

    s3_request_params params = {
        .method       = "DELETE",
        .bucket       = bucket,
        .key          = key,
        .query_string = qs,
    };

    return s3__request(c, &params);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACL
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Parse a single <Grant> element.
 */
static int parse_grant_cb(const char *element, size_t element_len, void *userdata)
{
    s3_acl *acl = (s3_acl *)userdata;

    /* Grow array */
    int new_count = acl->grant_count + 1;
    s3_grant *p = (s3_grant *)S3_REALLOC(acl->grants, (size_t)new_count * sizeof(s3_grant));
    if (!p) return -1;
    acl->grants = p;

    s3_grant *g = &acl->grants[acl->grant_count];
    memset(g, 0, sizeof(*g));

    /* Permission */
    const char *perm_val = nullptr;
    size_t perm_len = 0;
    if (s3__xml_find(element, element_len, "Permission", &perm_val, &perm_len)) {
        s3__xml_decode_entities(perm_val, perm_len, g->permission, sizeof(g->permission));
    }

    /* Grantee sub-element */
    const char *grantee_val = nullptr;
    size_t grantee_len = 0;
    if (s3__xml_find(element, element_len, "Grantee", &grantee_val, &grantee_len)) {
        const char *v = nullptr;
        size_t vl = 0;

        /* Try to determine type from xsi:type attribute or from content */
        if (s3__xml_find(grantee_val, grantee_len, "ID", &v, &vl)) {
            snprintf(g->grantee.type, sizeof(g->grantee.type), "CanonicalUser");
            s3__xml_decode_entities(v, vl, g->grantee.id, sizeof(g->grantee.id));
        }
        if (s3__xml_find(grantee_val, grantee_len, "DisplayName", &v, &vl)) {
            s3__xml_decode_entities(v, vl, g->grantee.display_name, sizeof(g->grantee.display_name));
        }
        if (s3__xml_find(grantee_val, grantee_len, "EmailAddress", &v, &vl)) {
            snprintf(g->grantee.type, sizeof(g->grantee.type), "AmazonCustomerByEmail");
            s3__xml_decode_entities(v, vl, g->grantee.email, sizeof(g->grantee.email));
        }
        if (s3__xml_find(grantee_val, grantee_len, "URI", &v, &vl)) {
            snprintf(g->grantee.type, sizeof(g->grantee.type), "Group");
            s3__xml_decode_entities(v, vl, g->grantee.uri, sizeof(g->grantee.uri));
        }
    }

    acl->grant_count = new_count;
    return 0;
}

s3_status s3_get_object_acl(s3_client *c, const char *bucket, const char *key,
                            const char *version_id, s3_acl *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "acl&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "acl");

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    /* Parse <AccessControlPolicy> */
    const char *xml = c->response.data;
    size_t xml_len  = c->response.len;

    /* Owner */
    const char *owner_val = nullptr;
    size_t owner_len = 0;
    if (s3__xml_find(xml, xml_len, "Owner", &owner_val, &owner_len)) {
        const char *v = nullptr;
        size_t vl = 0;
        if (s3__xml_find(owner_val, owner_len, "ID", &v, &vl))
            s3__xml_decode_entities(v, vl, result->owner_id, sizeof(result->owner_id));
        if (s3__xml_find(owner_val, owner_len, "DisplayName", &v, &vl))
            s3__xml_decode_entities(v, vl, result->owner_display_name, sizeof(result->owner_display_name));
    }

    /* Grants */
    const char *acl_list_val = nullptr;
    size_t acl_list_len = 0;
    if (s3__xml_find(xml, xml_len, "AccessControlList", &acl_list_val, &acl_list_len)) {
        s3__xml_each(acl_list_val, acl_list_len, "Grant", parse_grant_cb, result);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_object_acl(s3_client *c, const char *bucket, const char *key,
                            const char *version_id, const s3_acl *acl)
{
    if (!c || !bucket || !key || !acl)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3__xml_buf_open(&body, "AccessControlPolicy");

    /* Owner */
    s3__xml_buf_open(&body, "Owner");
    s3__xml_buf_element(&body, "ID", acl->owner_id);
    if (acl->owner_display_name[0])
        s3__xml_buf_element(&body, "DisplayName", acl->owner_display_name);
    s3__xml_buf_close(&body, "Owner");

    /* AccessControlList */
    s3__xml_buf_open(&body, "AccessControlList");
    for (int i = 0; i < acl->grant_count; i++) {
        const s3_grant *g = &acl->grants[i];
        s3__xml_buf_open(&body, "Grant");

        /* Grantee with xsi:type */
        char grantee_open[256];
        snprintf(grantee_open, sizeof(grantee_open),
                 "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                 "xsi:type=\"%s\">", g->grantee.type);
        s3_buf_append_str(&body, grantee_open);

        if (strcmp(g->grantee.type, "CanonicalUser") == 0) {
            s3__xml_buf_element(&body, "ID", g->grantee.id);
            if (g->grantee.display_name[0])
                s3__xml_buf_element(&body, "DisplayName", g->grantee.display_name);
        } else if (strcmp(g->grantee.type, "AmazonCustomerByEmail") == 0) {
            s3__xml_buf_element(&body, "EmailAddress", g->grantee.email);
        } else if (strcmp(g->grantee.type, "Group") == 0) {
            s3__xml_buf_element(&body, "URI", g->grantee.uri);
        }

        s3_buf_append_str(&body, "</Grantee>");
        s3__xml_buf_element(&body, "Permission", g->permission);
        s3__xml_buf_close(&body, "Grant");
    }
    s3__xml_buf_close(&body, "AccessControlList");

    s3__xml_buf_close(&body, "AccessControlPolicy");

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "acl&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "acl");

    s3_request_params params = {
        .method           = "PUT",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    s3_buf_free(&body);
    return status;
}

s3_status s3_put_object_acl_canned(s3_client *c, const char *bucket, const char *key,
                                   const char *version_id, s3_canned_acl acl)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;

    const char *acl_str = s3__canned_acl_string(acl);
    if (!acl_str)
        return S3_STATUS_INVALID_ARGUMENT;

    char acl_hdr[256];
    snprintf(acl_hdr, sizeof(acl_hdr), "x-amz-acl: %s", acl_str);

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, acl_hdr);

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "acl&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "acl");

    s3_request_params params = {
        .method        = "PUT",
        .bucket        = bucket,
        .key           = key,
        .query_string  = qs,
        .extra_headers = headers,
        .upload_data   = "",
        .upload_len    = 0,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Legal Hold
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_object_legal_hold(s3_client *c, const char *bucket, const char *key,
                                   const char *version_id, s3_object_lock_legal_hold *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    *result = S3_LEGAL_HOLD_OFF;

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "legal-hold&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "legal-hold");

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    const char *val = nullptr;
    size_t val_len = 0;
    if (s3__xml_find(c->response.data, c->response.len, "Status", &val, &val_len)) {
        if (val_len == 2 && strncmp(val, "ON", 2) == 0)
            *result = S3_LEGAL_HOLD_ON;
    }

    return S3_STATUS_OK;
}

s3_status s3_put_object_legal_hold(s3_client *c, const char *bucket, const char *key,
                                   const char *version_id, s3_object_lock_legal_hold hold)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3__xml_buf_open(&body, "LegalHold");
    s3__xml_buf_element(&body, "Status", hold == S3_LEGAL_HOLD_ON ? "ON" : "OFF");
    s3__xml_buf_close(&body, "LegalHold");

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "legal-hold&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "legal-hold");

    s3_request_params params = {
        .method           = "PUT",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Retention
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_object_retention(s3_client *c, const char *bucket, const char *key,
                                  const char *version_id, s3_object_retention *result)
{
    if (!c || !bucket || !key || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "retention&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "retention");

    s3_request_params params = {
        .method           = "GET",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    if (status != S3_STATUS_OK)
        return status;

    const char *xml = c->response.data;
    size_t xml_len  = c->response.len;

    const char *val = nullptr;
    size_t val_len = 0;

    if (s3__xml_find(xml, xml_len, "Mode", &val, &val_len)) {
        if (val_len >= 10 && strncmp(val, "GOVERNANCE", 10) == 0)
            result->mode = S3_LOCK_GOVERNANCE;
        else if (val_len >= 10 && strncmp(val, "COMPLIANCE", 10) == 0)
            result->mode = S3_LOCK_COMPLIANCE;
        else
            result->mode = S3_LOCK_NONE;
    }

    if (s3__xml_find(xml, xml_len, "RetainUntilDate", &val, &val_len)) {
        size_t copy_len = val_len < sizeof(result->retain_until) - 1
                        ? val_len : sizeof(result->retain_until) - 1;
        memcpy(result->retain_until, val, copy_len);
        result->retain_until[copy_len] = '\0';
    }

    return S3_STATUS_OK;
}

s3_status s3_put_object_retention(s3_client *c, const char *bucket, const char *key,
                                  const char *version_id, const s3_object_retention *retention,
                                  bool bypass_governance)
{
    if (!c || !bucket || !key || !retention)
        return S3_STATUS_INVALID_ARGUMENT;

    const char *mode_str = nullptr;
    switch (retention->mode) {
    case S3_LOCK_GOVERNANCE: mode_str = "GOVERNANCE"; break;
    case S3_LOCK_COMPLIANCE: mode_str = "COMPLIANCE"; break;
    default: return S3_STATUS_INVALID_ARGUMENT;
    }

    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3__xml_buf_open(&body, "Retention");
    s3__xml_buf_element(&body, "Mode", mode_str);
    s3__xml_buf_element(&body, "RetainUntilDate", retention->retain_until);
    s3__xml_buf_close(&body, "Retention");

    char qs[512];
    if (version_id && version_id[0])
        snprintf(qs, sizeof(qs), "retention&versionId=%s", version_id);
    else
        snprintf(qs, sizeof(qs), "retention");

    struct curl_slist *headers = nullptr;
    if (bypass_governance)
        headers = curl_slist_append(headers, "x-amz-bypass-governance-retention: true");

    s3_request_params params = {
        .method           = "PUT",
        .bucket           = bucket,
        .key              = key,
        .query_string     = qs,
        .extra_headers    = headers,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(headers);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Restore Object
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_restore_object(s3_client *c, const char *bucket, const char *key,
                            const s3_restore_object_opts *opts)
{
    if (!c || !bucket || !key)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3__xml_buf_open(&body, "RestoreRequest");

    int days = (opts && opts->days > 0) ? opts->days : 1;
    s3__xml_buf_element_int(&body, "Days", days);

    /* GlacierJobParameters */
    if (opts) {
        const char *tier_str = "Standard";
        switch (opts->tier) {
        case S3_TIER_EXPEDITED: tier_str = "Expedited"; break;
        case S3_TIER_BULK:      tier_str = "Bulk";      break;
        case S3_TIER_STANDARD:  tier_str = "Standard";  break;
        }
        s3__xml_buf_open(&body, "GlacierJobParameters");
        s3__xml_buf_element(&body, "Tier", tier_str);
        s3__xml_buf_close(&body, "GlacierJobParameters");
    }

    if (opts && opts->description) {
        s3__xml_buf_element(&body, "Description", opts->description);
    }

    s3__xml_buf_close(&body, "RestoreRequest");

    struct curl_slist *extra = nullptr;
    if (opts && opts->request_payer)
        extra = curl_slist_append(extra, "x-amz-request-payer: requester");

    s3_request_params params = {
        .method           = "POST",
        .bucket           = bucket,
        .key              = key,
        .query_string     = "restore",
        .extra_headers    = extra,
        .upload_data      = body.data,
        .upload_len       = body.len,
        .collect_response = true,
    };

    s3_status status = s3__request(c, &params);
    curl_slist_free_all(extra);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Free helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_tag_set_free(s3_tag_set *r)
{
    if (!r) return;
    S3_FREE(r->tags);
    r->tags  = nullptr;
    r->count = 0;
}

void s3_acl_free(s3_acl *r)
{
    if (!r) return;
    S3_FREE(r->grants);
    r->grants      = nullptr;
    r->grant_count = 0;
}
