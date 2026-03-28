/*
 * libs3 -- S3 Control: Storage Lens & Resource Tagging
 *
 * Implements Storage Lens configuration CRUD and resource tagging
 * operations via the S3 Control endpoint.
 *
 * All operations use:
 *   use_control_endpoint = true
 *   bucket = nullptr
 */

#define _POSIX_C_SOURCE 200809L
#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void xml_extract(const char *xml, size_t len,
                        const char *tag, char *dst, size_t dst_size)
{
    const char *v;
    size_t vlen;
    if (s3__xml_find(xml, len, tag, &v, &vlen)) {
        s3__xml_decode_entities(v, vlen, dst, dst_size);
    } else {
        dst[0] = '\0';
    }
}

static bool xml_extract_bool(const char *xml, size_t len, const char *tag)
{
    char buf[16];
    xml_extract(xml, len, tag, buf, sizeof(buf));
    return (strcmp(buf, "true") == 0 || strcmp(buf, "True") == 0);
}

static struct curl_slist *add_account_id_header(struct curl_slist *h,
                                                 const s3_client *c)
{
    if (c->account_id && c->account_id[0]) {
        char buf[512];
        snprintf(buf, sizeof(buf), "x-amz-account-id: %s", c->account_id);
        h = curl_slist_append(h, buf);
    }
    return h;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Lens — GET configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_storage_lens_configuration(s3_client *c, const char *id,
                                            char **config_xml_out)
{
    if (!c || !id || !config_xml_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *config_xml_out = nullptr;

    /* Build path: v20180820/storagelens/{id} */
    char path[512];
    snprintf(path, sizeof(path), "v20180820/storagelens/%s", id);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params p = {
        .method            = "GET",
        .bucket            = nullptr,
        .key               = path,
        .extra_headers     = hdrs,
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);

    if (st != S3_STATUS_OK)
        return st;

    /* Return a copy of the raw XML response */
    if (c->response.data && c->response.len > 0) {
        *config_xml_out = s3__strndup(c->response.data, c->response.len);
        if (!*config_xml_out)
            return S3_STATUS_OUT_OF_MEMORY;
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Lens — PUT configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_put_storage_lens_configuration(s3_client *c, const char *id,
                                            const char *config_xml)
{
    if (!c || !id || !config_xml)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build path: v20180820/storagelens/{id} */
    char path[512];
    snprintf(path, sizeof(path), "v20180820/storagelens/%s", id);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    s3_request_params p = {
        .method            = "PUT",
        .bucket            = nullptr,
        .key               = path,
        .extra_headers     = hdrs,
        .upload_data       = config_xml,
        .upload_len        = strlen(config_xml),
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Lens — DELETE configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_storage_lens_configuration(s3_client *c, const char *id)
{
    if (!c || !id)
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/storagelens/%s", id);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params p = {
        .method            = "DELETE",
        .bucket            = nullptr,
        .key               = path,
        .extra_headers     = hdrs,
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage Lens — LIST configurations
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Callback for parsing each <StorageLensConfiguration> element */
static int parse_lens_entry(const char *element, size_t element_len, void *userdata)
{
    s3_list_storage_lens_result *result = (s3_list_storage_lens_result *)userdata;

    /* Grow array if needed */
    int idx = result->count;
    s3_storage_lens_config_entry *new_configs = (s3_storage_lens_config_entry *)S3_REALLOC(
        result->configs,
        (size_t)(idx + 1) * sizeof(s3_storage_lens_config_entry));
    if (!new_configs)
        return -1;
    result->configs = new_configs;

    s3_storage_lens_config_entry *entry = &result->configs[idx];
    memset(entry, 0, sizeof(*entry));

    xml_extract(element, element_len, "Id", entry->id, sizeof(entry->id));
    xml_extract(element, element_len, "StorageLensArn", entry->arn, sizeof(entry->arn));
    xml_extract(element, element_len, "HomeRegion", entry->home_region, sizeof(entry->home_region));
    entry->is_enabled = xml_extract_bool(element, element_len, "IsEnabled");

    result->count++;
    return 0;
}

s3_status s3_list_storage_lens_configurations(s3_client *c, const char *next_token,
                                              s3_list_storage_lens_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string with optional continuation token */
    char query[2048] = "";
    if (next_token && next_token[0]) {
        snprintf(query, sizeof(query), "nextToken=%s", next_token);
    }

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params p = {
        .method            = "GET",
        .bucket            = nullptr,
        .key               = "v20180820/storagelens",
        .query_string      = query[0] ? query : nullptr,
        .extra_headers     = hdrs,
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);

    if (st != S3_STATUS_OK)
        return st;

    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    if (!xml || xml_len == 0)
        return S3_STATUS_OK;

    /* Parse each StorageLensConfiguration element */
    s3__xml_each(xml, xml_len, "StorageLensConfiguration", parse_lens_entry, result);

    /* Parse continuation token */
    xml_extract(xml, xml_len, "NextToken", result->next_token, sizeof(result->next_token));

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Resource Tagging — TagResource (POST)
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_tag_resource(s3_client *c, const char *resource_arn,
                          const s3_tag *tags, int tag_count)
{
    if (!c || !resource_arn || !tags || tag_count <= 0)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build path: v20180820/tags/{arn} */
    char path[1024];
    snprintf(path, sizeof(path), "v20180820/tags/%s", resource_arn);

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<Tagging xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");
    s3__xml_buf_open(&body, "TagSet");

    for (int i = 0; i < tag_count; i++) {
        s3__xml_buf_open(&body, "Tag");
        s3__xml_buf_element(&body, "Key", tags[i].key);
        s3__xml_buf_element(&body, "Value", tags[i].value);
        s3__xml_buf_close(&body, "Tag");
    }

    s3__xml_buf_close(&body, "TagSet");
    s3_buf_append_str(&body, "</Tagging>");

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    s3_request_params p = {
        .method            = "POST",
        .bucket            = nullptr,
        .key               = path,
        .extra_headers     = hdrs,
        .upload_data       = body.data,
        .upload_len        = body.len,
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Resource Tagging — UntagResource (DELETE)
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_untag_resource(s3_client *c, const char *resource_arn,
                            const char *const *tag_keys, int key_count)
{
    if (!c || !resource_arn || !tag_keys || key_count <= 0)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build path: v20180820/tags/{arn} */
    char path[1024];
    snprintf(path, sizeof(path), "v20180820/tags/%s", resource_arn);

    /* Build query string with tag keys: tagKeys=key1&tagKeys=key2&... */
    s3_buf query;
    s3_buf_init(&query);

    for (int i = 0; i < key_count; i++) {
        if (i > 0)
            s3_buf_append_str(&query, "&");
        s3_buf_append_str(&query, "tagKeys=");

        /* URI-encode the tag key value */
        char encoded[512];
        s3__uri_encode(tag_keys[i], strlen(tag_keys[i]),
                       encoded, sizeof(encoded), false);
        s3_buf_append_str(&query, encoded);
    }

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params p = {
        .method            = "DELETE",
        .bucket            = nullptr,
        .key               = path,
        .query_string      = query.data,
        .extra_headers     = hdrs,
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    s3_buf_free(&query);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Resource Tagging — ListTagsForResource (GET)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Callback for parsing each <Tag> element */
static int parse_tag_entry(const char *element, size_t element_len, void *userdata)
{
    s3_tag_set *result = (s3_tag_set *)userdata;

    int idx = result->count;
    s3_tag *new_tags = (s3_tag *)S3_REALLOC(
        result->tags, (size_t)(idx + 1) * sizeof(s3_tag));
    if (!new_tags)
        return -1;
    result->tags = new_tags;

    s3_tag *tag = &result->tags[idx];
    memset(tag, 0, sizeof(*tag));

    xml_extract(element, element_len, "Key", tag->key, sizeof(tag->key));
    xml_extract(element, element_len, "Value", tag->value, sizeof(tag->value));

    result->count++;
    return 0;
}

s3_status s3_list_tags_for_resource(s3_client *c, const char *resource_arn,
                                    s3_tag_set *result)
{
    if (!c || !resource_arn || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build path: v20180820/tags/{arn} */
    char path[1024];
    snprintf(path, sizeof(path), "v20180820/tags/%s", resource_arn);

    struct curl_slist *hdrs = nullptr;
    hdrs = add_account_id_header(hdrs, c);

    s3_request_params p = {
        .method            = "GET",
        .bucket            = nullptr,
        .key               = path,
        .extra_headers     = hdrs,
        .collect_response  = true,
        .use_control_endpoint = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);

    if (st != S3_STATUS_OK)
        return st;

    const char *xml = c->response.data;
    size_t xml_len = c->response.len;
    if (!xml || xml_len == 0)
        return S3_STATUS_OK;

    /* Parse each <Tag> element */
    s3__xml_each(xml, xml_len, "Tag", parse_tag_entry, result);

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Free — s3_list_storage_lens_result
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_storage_lens_result_free(s3_list_storage_lens_result *r)
{
    if (!r)
        return;
    S3_FREE(r->configs);
    r->configs = nullptr;
    r->count = 0;
    r->next_token[0] = '\0';
}
