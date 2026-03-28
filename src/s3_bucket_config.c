/*
 * libs3 -- Bucket configuration operations
 *
 * Implements all GET/PUT/DELETE /?{subresource} bucket configuration APIs.
 */

#define _POSIX_C_SOURCE 200809L
#include "s3_internal.h"
#include <inttypes.h>
#include <strings.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Simple helper: extract text content of a tag into a fixed-size char buffer.
 * Returns true if found.
 */
static bool xml_get_str(const char *xml, size_t len,
                        const char *tag, char *out, size_t out_size)
{
    const char *val;
    size_t vlen;
    if (!s3__xml_find(xml, len, tag, &val, &vlen))
        return false;
    if (vlen >= out_size) vlen = out_size - 1;
    memcpy(out, val, vlen);
    out[vlen] = '\0';
    return true;
}

/*
 * Same but search within a parent element.
 */
static bool xml_get_str_in(const char *xml, size_t len,
                           const char *parent, const char *child,
                           char *out, size_t out_size)
{
    const char *val;
    size_t vlen;
    if (!s3__xml_find_in(xml, len, parent, child, &val, &vlen))
        return false;
    if (vlen >= out_size) vlen = out_size - 1;
    memcpy(out, val, vlen);
    out[vlen] = '\0';
    return true;
}

static int xml_get_int(const char *xml, size_t len, const char *tag, int def)
{
    const char *val;
    size_t vlen;
    if (!s3__xml_find(xml, len, tag, &val, &vlen))
        return def;
    return (int)strtol(val, nullptr, 10);
}

static int64_t xml_get_int64(const char *xml, size_t len, const char *tag, int64_t def)
{
    const char *val;
    size_t vlen;
    if (!s3__xml_find(xml, len, tag, &val, &vlen))
        return def;
    return strtoll(val, nullptr, 10);
}

static bool xml_get_bool(const char *xml, size_t len, const char *tag)
{
    const char *val;
    size_t vlen;
    if (!s3__xml_find(xml, len, tag, &val, &vlen))
        return false;
    return (vlen >= 4 && strncasecmp(val, "true", 4) == 0);
}

/*
 * Parse string list from XML: repeated <tag> elements inside xml.
 * Caller must free the returned array and each string.
 */
typedef struct str_acc {
    char **arr;
    int    count;
    int    capacity;
} str_acc;

static int collect_string_cb(const char *elem, size_t elen, void *ud)
{
    str_acc *a = (str_acc *)ud;
    if (a->count >= a->capacity) {
        int nc = a->capacity ? a->capacity * 2 : 8;
        char **p = (char **)S3_REALLOC(a->arr, (size_t)nc * sizeof(char *));
        if (!p) return -1;
        a->arr = p;
        a->capacity = nc;
    }
    a->arr[a->count] = s3__strndup(elem, elen);
    a->count++;
    return 0;
}

static char **xml_get_string_list(const char *xml, size_t len,
                                  const char *tag, int *count_out)
{
    str_acc acc = {0};
    s3__xml_each(xml, len, tag, collect_string_cb, &acc);
    *count_out = acc.count;
    return acc.arr;
}

static void free_string_list(char **list, int count)
{
    if (!list) return;
    for (int i = 0; i < count; i++)
        S3_FREE(list[i]);
    S3_FREE(list);
}

/*
 * Simple GET /?subresource and collect response.
 */
static s3_status bucket_get(s3_client *c, const char *bucket,
                            const char *subresource)
{
    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = subresource,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/*
 * Simple PUT /?subresource with XML body.
 */
static s3_status bucket_put(s3_client *c, const char *bucket,
                            const char *subresource,
                            const char *body, size_t body_len,
                            struct curl_slist *extra_headers)
{
    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = subresource,
        .extra_headers = extra_headers,
        .upload_data = body,
        .upload_len = body_len,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/*
 * Simple DELETE /?subresource.
 */
static s3_status bucket_delete(s3_client *c, const char *bucket,
                               const char *subresource)
{
    s3_request_params p = {
        .method = "DELETE",
        .bucket = bucket,
        .query_string = subresource,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* Tag parsing callback used by several sections */
typedef struct tag_acc {
    s3_tag *tags;
    int     count;
    int     cap;
} tag_acc;

static int parse_tag_cb(const char *te, size_t tel, void *tud)
{
    tag_acc *ta = (tag_acc *)tud;
    if (ta->count >= ta->cap) {
        int nc = ta->cap ? ta->cap * 2 : 4;
        s3_tag *p = (s3_tag *)S3_REALLOC(ta->tags, (size_t)nc * sizeof(s3_tag));
        if (!p) return -1;
        ta->tags = p;
        ta->cap = nc;
    }
    s3_tag *t = &ta->tags[ta->count++];
    memset(t, 0, sizeof(*t));
    xml_get_str(te, tel, "Key", t->key, sizeof(t->key));
    xml_get_str(te, tel, "Value", t->value, sizeof(t->value));
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. Versioning
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_versioning(s3_client *c, const char *bucket,
                                   s3_versioning_status *status, bool *mfa_delete)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "versioning");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    if (status) {
        char val[32] = "";
        xml_get_str(xml, len, "Status", val, sizeof(val));
        if (strcmp(val, "Enabled") == 0)
            *status = S3_VERSIONING_ENABLED;
        else if (strcmp(val, "Suspended") == 0)
            *status = S3_VERSIONING_SUSPENDED;
        else
            *status = S3_VERSIONING_UNSET;
    }

    if (mfa_delete) {
        char val[32] = "";
        xml_get_str(xml, len, "MfaDelete", val, sizeof(val));
        *mfa_delete = (strcmp(val, "Enabled") == 0);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_versioning(s3_client *c, const char *bucket,
                                   s3_versioning_status status,
                                   bool mfa_delete, const char *mfa)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b, "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    if (status == S3_VERSIONING_ENABLED)
        s3__xml_buf_element(&b, "Status", "Enabled");
    else if (status == S3_VERSIONING_SUSPENDED)
        s3__xml_buf_element(&b, "Status", "Suspended");
    s3__xml_buf_element(&b, "MfaDelete", mfa_delete ? "Enabled" : "Disabled");
    s3_buf_append_str(&b, "</VersioningConfiguration>");

    struct curl_slist *hdrs = nullptr;
    if (mfa && mfa[0]) {
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "x-amz-mfa: %s", mfa);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    s3_status st = bucket_put(c, bucket, "versioning", b.data, b.len, hdrs);
    s3_buf_free(&b);
    if (hdrs) curl_slist_free_all(hdrs);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Transition callback */
typedef struct trans_acc {
    s3_lifecycle_transition *arr;
    int count;
    int cap;
} trans_acc;

static int parse_transition_cb(const char *te, size_t tel, void *tud)
{
    trans_acc *ta = (trans_acc *)tud;
    if (ta->count >= ta->cap) {
        int nc = ta->cap ? ta->cap * 2 : 4;
        s3_lifecycle_transition *p = (s3_lifecycle_transition *)S3_REALLOC(
            ta->arr, (size_t)nc * sizeof(s3_lifecycle_transition));
        if (!p) return -1;
        ta->arr = p;
        ta->cap = nc;
    }
    s3_lifecycle_transition *t = &ta->arr[ta->count++];
    memset(t, 0, sizeof(*t));
    t->days = xml_get_int(te, tel, "Days", 0);
    xml_get_str(te, tel, "Date", t->date, sizeof(t->date));
    xml_get_str(te, tel, "StorageClass", t->storage_class, sizeof(t->storage_class));
    return 0;
}

/* NoncurrentVersionTransition callback */
typedef struct nc_trans_acc {
    s3_lifecycle_noncurrent_transition *arr;
    int count;
    int cap;
} nc_trans_acc;

static int parse_nc_transition_cb(const char *te, size_t tel, void *tud)
{
    nc_trans_acc *a = (nc_trans_acc *)tud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_lifecycle_noncurrent_transition *p =
            (s3_lifecycle_noncurrent_transition *)S3_REALLOC(
                a->arr, (size_t)nc * sizeof(*p));
        if (!p) return -1;
        a->arr = p;
        a->cap = nc;
    }
    s3_lifecycle_noncurrent_transition *t = &a->arr[a->count++];
    memset(t, 0, sizeof(*t));
    t->noncurrent_days = xml_get_int(te, tel, "NoncurrentDays", 0);
    t->newer_noncurrent_versions = xml_get_int(te, tel, "NewerNoncurrentVersions", 0);
    xml_get_str(te, tel, "StorageClass", t->storage_class, sizeof(t->storage_class));
    return 0;
}

static int parse_lifecycle_rule(const char *elem, size_t elen, void *ud)
{
    s3_lifecycle_configuration *cfg = (s3_lifecycle_configuration *)ud;

    /* Grow rules array */
    int idx = cfg->rule_count;
    s3_lifecycle_rule *tmp = (s3_lifecycle_rule *)S3_REALLOC(
        cfg->rules, (size_t)(idx + 1) * sizeof(s3_lifecycle_rule));
    if (!tmp) return -1;
    cfg->rules = tmp;
    cfg->rule_count = idx + 1;

    s3_lifecycle_rule *r = &cfg->rules[idx];
    memset(r, 0, sizeof(*r));

    xml_get_str(elem, elen, "ID", r->id, sizeof(r->id));
    xml_get_str(elem, elen, "Prefix", r->prefix, sizeof(r->prefix));

    /* Status */
    char status_str[32] = "";
    xml_get_str(elem, elen, "Status", status_str, sizeof(status_str));
    r->enabled = (strcmp(status_str, "Enabled") == 0);

    /* Filter */
    const char *filter_start;
    size_t flen;
    if (s3__xml_find(elem, elen, "Filter", &filter_start, &flen)) {
        xml_get_str(filter_start, flen, "Prefix", r->filter.prefix, sizeof(r->filter.prefix));
        r->filter.object_size_greater_than = xml_get_int64(filter_start, flen,
            "ObjectSizeGreaterThan", 0);
        r->filter.object_size_less_than = xml_get_int64(filter_start, flen,
            "ObjectSizeLessThan", 0);

        /* Check for And */
        const char *and_val;
        size_t and_len;
        if (s3__xml_find(filter_start, flen, "And", &and_val, &and_len)) {
            r->filter.has_and = true;
            xml_get_str(and_val, and_len, "Prefix",
                        r->filter.prefix, sizeof(r->filter.prefix));
            r->filter.object_size_greater_than = xml_get_int64(and_val, and_len,
                "ObjectSizeGreaterThan", r->filter.object_size_greater_than);
            r->filter.object_size_less_than = xml_get_int64(and_val, and_len,
                "ObjectSizeLessThan", r->filter.object_size_less_than);

            /* Tags in filter/And */
            tag_acc tacc = {0};
            s3__xml_each(and_val, and_len, "Tag", parse_tag_cb, &tacc);
            r->filter.tags = tacc.tags;
            r->filter.tag_count = tacc.count;
        }
    }

    /* Expiration */
    const char *exp_val;
    size_t exp_len;
    if (s3__xml_find(elem, elen, "Expiration", &exp_val, &exp_len)) {
        r->expiration.days = xml_get_int(exp_val, exp_len, "Days", 0);
        xml_get_str(exp_val, exp_len, "Date", r->expiration.date,
                    sizeof(r->expiration.date));
        r->expiration.expired_object_delete_marker =
            xml_get_bool(exp_val, exp_len, "ExpiredObjectDeleteMarker");
    }

    /* Transitions */
    trans_acc tracc = {0};
    s3__xml_each(elem, elen, "Transition", parse_transition_cb, &tracc);
    r->transitions = tracc.arr;
    r->transition_count = tracc.count;

    /* NoncurrentVersionTransitions */
    nc_trans_acc nctracc = {0};
    s3__xml_each(elem, elen, "NoncurrentVersionTransition",
                 parse_nc_transition_cb, &nctracc);
    r->noncurrent_transitions = nctracc.arr;
    r->noncurrent_transition_count = nctracc.count;

    /* NoncurrentVersionExpiration */
    const char *nce_val;
    size_t nce_len;
    if (s3__xml_find(elem, elen, "NoncurrentVersionExpiration", &nce_val, &nce_len)) {
        r->noncurrent_expiration.noncurrent_days =
            xml_get_int(nce_val, nce_len, "NoncurrentDays", 0);
        r->noncurrent_expiration.newer_noncurrent_versions =
            xml_get_int(nce_val, nce_len, "NewerNoncurrentVersions", 0);
    }

    /* AbortIncompleteMultipartUpload */
    const char *aim_val;
    size_t aim_len;
    if (s3__xml_find(elem, elen, "AbortIncompleteMultipartUpload", &aim_val, &aim_len)) {
        r->abort_incomplete_mpu.days_after_initiation =
            xml_get_int(aim_val, aim_len, "DaysAfterInitiation", 0);
    }

    return 0;
}

s3_status s3_get_bucket_lifecycle(s3_client *c, const char *bucket,
                                  s3_lifecycle_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "lifecycle");
    if (st != S3_STATUS_OK) return st;

    s3__xml_each(c->response.data, c->response.len, "Rule",
                 parse_lifecycle_rule, config);

    return S3_STATUS_OK;
}

static void build_lifecycle_filter(s3_buf *b, const s3_lifecycle_filter *f)
{
    s3__xml_buf_open(b, "Filter");
    bool need_and = f->has_and || f->tag_count > 0 ||
        (f->prefix[0] && (f->object_size_greater_than > 0 || f->object_size_less_than > 0));

    if (need_and) s3__xml_buf_open(b, "And");

    if (f->prefix[0])
        s3__xml_buf_element(b, "Prefix", f->prefix);
    else if (!need_and)
        s3__xml_buf_element(b, "Prefix", "");

    for (int i = 0; i < f->tag_count; i++) {
        s3__xml_buf_open(b, "Tag");
        s3__xml_buf_element(b, "Key", f->tags[i].key);
        s3__xml_buf_element(b, "Value", f->tags[i].value);
        s3__xml_buf_close(b, "Tag");
    }

    if (f->object_size_greater_than > 0)
        s3__xml_buf_element_int(b, "ObjectSizeGreaterThan", f->object_size_greater_than);
    if (f->object_size_less_than > 0)
        s3__xml_buf_element_int(b, "ObjectSizeLessThan", f->object_size_less_than);

    if (need_and) s3__xml_buf_close(b, "And");
    s3__xml_buf_close(b, "Filter");
}

s3_status s3_put_bucket_lifecycle(s3_client *c, const char *bucket,
                                  const s3_lifecycle_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b, "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    for (int i = 0; i < config->rule_count; i++) {
        const s3_lifecycle_rule *r = &config->rules[i];
        s3__xml_buf_open(&b, "Rule");

        if (r->id[0])
            s3__xml_buf_element(&b, "ID", r->id);

        build_lifecycle_filter(&b, &r->filter);
        s3__xml_buf_element(&b, "Status", r->enabled ? "Enabled" : "Disabled");

        /* Expiration */
        if (r->expiration.days > 0 || r->expiration.date[0] ||
            r->expiration.expired_object_delete_marker) {
            s3__xml_buf_open(&b, "Expiration");
            if (r->expiration.days > 0)
                s3__xml_buf_element_int(&b, "Days", r->expiration.days);
            if (r->expiration.date[0])
                s3__xml_buf_element(&b, "Date", r->expiration.date);
            if (r->expiration.expired_object_delete_marker)
                s3__xml_buf_element_bool(&b, "ExpiredObjectDeleteMarker", true);
            s3__xml_buf_close(&b, "Expiration");
        }

        /* Transitions */
        for (int j = 0; j < r->transition_count; j++) {
            const s3_lifecycle_transition *t = &r->transitions[j];
            s3__xml_buf_open(&b, "Transition");
            if (t->days > 0)
                s3__xml_buf_element_int(&b, "Days", t->days);
            if (t->date[0])
                s3__xml_buf_element(&b, "Date", t->date);
            s3__xml_buf_element(&b, "StorageClass", t->storage_class);
            s3__xml_buf_close(&b, "Transition");
        }

        /* NoncurrentVersionTransition */
        for (int j = 0; j < r->noncurrent_transition_count; j++) {
            const s3_lifecycle_noncurrent_transition *t = &r->noncurrent_transitions[j];
            s3__xml_buf_open(&b, "NoncurrentVersionTransition");
            s3__xml_buf_element_int(&b, "NoncurrentDays", t->noncurrent_days);
            if (t->newer_noncurrent_versions > 0)
                s3__xml_buf_element_int(&b, "NewerNoncurrentVersions",
                                        t->newer_noncurrent_versions);
            s3__xml_buf_element(&b, "StorageClass", t->storage_class);
            s3__xml_buf_close(&b, "NoncurrentVersionTransition");
        }

        /* NoncurrentVersionExpiration */
        if (r->noncurrent_expiration.noncurrent_days > 0) {
            s3__xml_buf_open(&b, "NoncurrentVersionExpiration");
            s3__xml_buf_element_int(&b, "NoncurrentDays",
                                    r->noncurrent_expiration.noncurrent_days);
            if (r->noncurrent_expiration.newer_noncurrent_versions > 0)
                s3__xml_buf_element_int(&b, "NewerNoncurrentVersions",
                                        r->noncurrent_expiration.newer_noncurrent_versions);
            s3__xml_buf_close(&b, "NoncurrentVersionExpiration");
        }

        /* AbortIncompleteMultipartUpload */
        if (r->abort_incomplete_mpu.days_after_initiation > 0) {
            s3__xml_buf_open(&b, "AbortIncompleteMultipartUpload");
            s3__xml_buf_element_int(&b, "DaysAfterInitiation",
                                    r->abort_incomplete_mpu.days_after_initiation);
            s3__xml_buf_close(&b, "AbortIncompleteMultipartUpload");
        }

        s3__xml_buf_close(&b, "Rule");
    }

    s3_buf_append_str(&b, "</LifecycleConfiguration>");

    s3_status st = bucket_put(c, bucket, "lifecycle", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_lifecycle(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "lifecycle");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. Policy (JSON, not XML)
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_policy(s3_client *c, const char *bucket,
                               char **policy_json_out)
{
    if (!c || !bucket || !policy_json_out)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "policy");
    if (st != S3_STATUS_OK) return st;

    *policy_json_out = s3__strndup(c->response.data, c->response.len);
    return *policy_json_out ? S3_STATUS_OK : S3_STATUS_OUT_OF_MEMORY;
}

s3_status s3_put_bucket_policy(s3_client *c, const char *bucket,
                               const char *policy_json)
{
    if (!c || !bucket || !policy_json)
        return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *hdrs = curl_slist_append(nullptr,
        "Content-Type: application/json");

    s3_status st = bucket_put(c, bucket, "policy",
                              policy_json, strlen(policy_json), hdrs);
    curl_slist_free_all(hdrs);
    return st;
}

s3_status s3_delete_bucket_policy(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "policy");
}

s3_status s3_get_bucket_policy_status(s3_client *c, const char *bucket,
                                      bool *is_public)
{
    if (!c || !bucket || !is_public)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "policyStatus");
    if (st != S3_STATUS_OK) return st;

    *is_public = xml_get_bool(c->response.data, c->response.len, "IsPublic");
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. CORS
 * ═══════════════════════════════════════════════════════════════════════════ */

static int parse_cors_rule(const char *elem, size_t elen, void *ud)
{
    s3_cors_configuration *cfg = (s3_cors_configuration *)ud;

    int idx = cfg->rule_count;
    s3_cors_rule *tmp = (s3_cors_rule *)S3_REALLOC(
        cfg->rules, (size_t)(idx + 1) * sizeof(s3_cors_rule));
    if (!tmp) return -1;
    cfg->rules = tmp;
    cfg->rule_count = idx + 1;

    s3_cors_rule *r = &cfg->rules[idx];
    memset(r, 0, sizeof(*r));

    xml_get_str(elem, elen, "ID", r->id, sizeof(r->id));
    r->max_age_seconds = xml_get_int(elem, elen, "MaxAgeSeconds", 0);

    r->allowed_origins = xml_get_string_list(elem, elen, "AllowedOrigin",
                                             &r->allowed_origin_count);
    r->allowed_methods = xml_get_string_list(elem, elen, "AllowedMethod",
                                             &r->allowed_method_count);
    r->allowed_headers = xml_get_string_list(elem, elen, "AllowedHeader",
                                             &r->allowed_header_count);
    r->expose_headers = xml_get_string_list(elem, elen, "ExposeHeader",
                                            &r->expose_header_count);
    return 0;
}

s3_status s3_get_bucket_cors(s3_client *c, const char *bucket,
                             s3_cors_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "cors");
    if (st != S3_STATUS_OK) return st;

    s3__xml_each(c->response.data, c->response.len, "CORSRule",
                 parse_cors_rule, config);

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_cors(s3_client *c, const char *bucket,
                             const s3_cors_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b, "<CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    for (int i = 0; i < config->rule_count; i++) {
        const s3_cors_rule *r = &config->rules[i];
        s3__xml_buf_open(&b, "CORSRule");

        if (r->id[0])
            s3__xml_buf_element(&b, "ID", r->id);

        for (int j = 0; j < r->allowed_origin_count; j++)
            s3__xml_buf_element(&b, "AllowedOrigin", r->allowed_origins[j]);
        for (int j = 0; j < r->allowed_method_count; j++)
            s3__xml_buf_element(&b, "AllowedMethod", r->allowed_methods[j]);
        for (int j = 0; j < r->allowed_header_count; j++)
            s3__xml_buf_element(&b, "AllowedHeader", r->allowed_headers[j]);
        for (int j = 0; j < r->expose_header_count; j++)
            s3__xml_buf_element(&b, "ExposeHeader", r->expose_headers[j]);

        if (r->max_age_seconds > 0)
            s3__xml_buf_element_int(&b, "MaxAgeSeconds", r->max_age_seconds);

        s3__xml_buf_close(&b, "CORSRule");
    }

    s3_buf_append_str(&b, "</CORSConfiguration>");

    s3_status st = bucket_put(c, bucket, "cors", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_cors(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "cors");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. Encryption
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_encryption(s3_client *c, const char *bucket,
                                   s3_bucket_encryption *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "encryption");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    char algo[64] = "";
    xml_get_str(xml, len, "SSEAlgorithm", algo, sizeof(algo));
    if (strcmp(algo, "aws:kms") == 0 || strcmp(algo, "aws:kms:dsse") == 0)
        config->default_sse = S3_SSE_KMS;
    else if (strcmp(algo, "AES256") == 0)
        config->default_sse = S3_SSE_S3;
    else
        config->default_sse = S3_SSE_NONE;

    xml_get_str(xml, len, "KMSMasterKeyID", config->kms_key_id,
                sizeof(config->kms_key_id));
    config->bucket_key_enabled = xml_get_bool(xml, len, "BucketKeyEnabled");

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_encryption(s3_client *c, const char *bucket,
                                   const s3_bucket_encryption *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_open(&b, "Rule");
    s3__xml_buf_open(&b, "ApplyServerSideEncryptionByDefault");

    const char *algo = "AES256";
    if (config->default_sse == S3_SSE_KMS)
        algo = "aws:kms";
    s3__xml_buf_element(&b, "SSEAlgorithm", algo);

    if (config->kms_key_id[0])
        s3__xml_buf_element(&b, "KMSMasterKeyID", config->kms_key_id);

    s3__xml_buf_close(&b, "ApplyServerSideEncryptionByDefault");

    if (config->bucket_key_enabled)
        s3__xml_buf_element_bool(&b, "BucketKeyEnabled", true);

    s3__xml_buf_close(&b, "Rule");
    s3_buf_append_str(&b, "</ServerSideEncryptionConfiguration>");

    s3_status st = bucket_put(c, bucket, "encryption", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_encryption(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "encryption");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. Logging
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_logging(s3_client *c, const char *bucket,
                                s3_bucket_logging *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "logging");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    const char *le_val;
    size_t le_len;
    if (s3__xml_find(xml, len, "LoggingEnabled", &le_val, &le_len)) {
        config->enabled = true;
        xml_get_str(le_val, le_len, "TargetBucket",
                    config->target_bucket, sizeof(config->target_bucket));
        xml_get_str(le_val, le_len, "TargetPrefix",
                    config->target_prefix, sizeof(config->target_prefix));
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_logging(s3_client *c, const char *bucket,
                                const s3_bucket_logging *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if (config->enabled) {
        s3__xml_buf_open(&b, "LoggingEnabled");
        s3__xml_buf_element(&b, "TargetBucket", config->target_bucket);
        s3__xml_buf_element(&b, "TargetPrefix", config->target_prefix);
        s3__xml_buf_close(&b, "LoggingEnabled");
    }

    s3_buf_append_str(&b, "</BucketLoggingStatus>");

    s3_status st = bucket_put(c, bucket, "logging", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 7. Tagging
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_tagging(s3_client *c, const char *bucket,
                                s3_tag_set *tags)
{
    if (!c || !bucket || !tags)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(tags, 0, sizeof(*tags));

    s3_status st = bucket_get(c, bucket, "tagging");
    if (st != S3_STATUS_OK) return st;

    tag_acc acc = {0};
    s3__xml_each(c->response.data, c->response.len, "Tag", parse_tag_cb, &acc);

    tags->tags = acc.tags;
    tags->count = acc.count;
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_tagging(s3_client *c, const char *bucket,
                                const s3_tag *tags, int tag_count)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_open(&b, "TagSet");

    for (int i = 0; i < tag_count; i++) {
        s3__xml_buf_open(&b, "Tag");
        s3__xml_buf_element(&b, "Key", tags[i].key);
        s3__xml_buf_element(&b, "Value", tags[i].value);
        s3__xml_buf_close(&b, "Tag");
    }

    s3__xml_buf_close(&b, "TagSet");
    s3_buf_append_str(&b, "</Tagging>");

    s3_status st = bucket_put(c, bucket, "tagging", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_tagging(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "tagging");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 8. Website
 * ═══════════════════════════════════════════════════════════════════════════ */

static int parse_routing_rule(const char *elem, size_t elen, void *ud)
{
    s3_website_configuration *cfg = (s3_website_configuration *)ud;

    int idx = cfg->routing_rule_count;
    s3_website_redirect_rule *tmp = (s3_website_redirect_rule *)S3_REALLOC(
        cfg->routing_rules, (size_t)(idx + 1) * sizeof(s3_website_redirect_rule));
    if (!tmp) return -1;
    cfg->routing_rules = tmp;
    cfg->routing_rule_count = idx + 1;

    s3_website_redirect_rule *r = &cfg->routing_rules[idx];
    memset(r, 0, sizeof(*r));

    /* Condition */
    const char *cond_val;
    size_t cond_len;
    if (s3__xml_find(elem, elen, "Condition", &cond_val, &cond_len)) {
        xml_get_str(cond_val, cond_len, "KeyPrefixEquals",
                    r->condition_key_prefix, sizeof(r->condition_key_prefix));
        r->condition_http_error_code =
            xml_get_int(cond_val, cond_len, "HttpErrorCodeReturnedEquals", 0);
    }

    /* Redirect */
    const char *redir_val;
    size_t redir_len;
    if (s3__xml_find(elem, elen, "Redirect", &redir_val, &redir_len)) {
        xml_get_str(redir_val, redir_len, "HostName",
                    r->redirect_hostname, sizeof(r->redirect_hostname));
        xml_get_str(redir_val, redir_len, "Protocol",
                    r->redirect_protocol, sizeof(r->redirect_protocol));
        xml_get_str(redir_val, redir_len, "ReplaceKeyPrefixWith",
                    r->redirect_replace_key_prefix,
                    sizeof(r->redirect_replace_key_prefix));
        xml_get_str(redir_val, redir_len, "ReplaceKeyWith",
                    r->redirect_replace_key, sizeof(r->redirect_replace_key));
        r->redirect_http_code =
            xml_get_int(redir_val, redir_len, "HttpRedirectCode", 0);
    }

    return 0;
}

s3_status s3_get_bucket_website(s3_client *c, const char *bucket,
                                s3_website_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "website");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    xml_get_str_in(xml, len, "IndexDocument", "Suffix",
                   config->index_document, sizeof(config->index_document));
    xml_get_str_in(xml, len, "ErrorDocument", "Key",
                   config->error_document, sizeof(config->error_document));

    /* RedirectAllRequestsTo */
    const char *redir_val;
    size_t redir_len;
    if (s3__xml_find(xml, len, "RedirectAllRequestsTo", &redir_val, &redir_len)) {
        xml_get_str(redir_val, redir_len, "HostName",
                    config->redirect_hostname, sizeof(config->redirect_hostname));
        xml_get_str(redir_val, redir_len, "Protocol",
                    config->redirect_protocol, sizeof(config->redirect_protocol));
    }

    /* RoutingRules */
    const char *rr_val;
    size_t rr_len;
    if (s3__xml_find(xml, len, "RoutingRules", &rr_val, &rr_len)) {
        s3__xml_each(rr_val, rr_len, "RoutingRule",
                     parse_routing_rule, config);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_website(s3_client *c, const char *bucket,
                                const s3_website_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<WebsiteConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if (config->redirect_hostname[0]) {
        s3__xml_buf_open(&b, "RedirectAllRequestsTo");
        s3__xml_buf_element(&b, "HostName", config->redirect_hostname);
        if (config->redirect_protocol[0])
            s3__xml_buf_element(&b, "Protocol", config->redirect_protocol);
        s3__xml_buf_close(&b, "RedirectAllRequestsTo");
    } else {
        if (config->index_document[0]) {
            s3__xml_buf_open(&b, "IndexDocument");
            s3__xml_buf_element(&b, "Suffix", config->index_document);
            s3__xml_buf_close(&b, "IndexDocument");
        }
        if (config->error_document[0]) {
            s3__xml_buf_open(&b, "ErrorDocument");
            s3__xml_buf_element(&b, "Key", config->error_document);
            s3__xml_buf_close(&b, "ErrorDocument");
        }

        if (config->routing_rule_count > 0) {
            s3__xml_buf_open(&b, "RoutingRules");
            for (int i = 0; i < config->routing_rule_count; i++) {
                const s3_website_redirect_rule *r = &config->routing_rules[i];
                s3__xml_buf_open(&b, "RoutingRule");

                if (r->condition_key_prefix[0] || r->condition_http_error_code > 0) {
                    s3__xml_buf_open(&b, "Condition");
                    if (r->condition_key_prefix[0])
                        s3__xml_buf_element(&b, "KeyPrefixEquals",
                                            r->condition_key_prefix);
                    if (r->condition_http_error_code > 0)
                        s3__xml_buf_element_int(&b, "HttpErrorCodeReturnedEquals",
                                                r->condition_http_error_code);
                    s3__xml_buf_close(&b, "Condition");
                }

                s3__xml_buf_open(&b, "Redirect");
                if (r->redirect_hostname[0])
                    s3__xml_buf_element(&b, "HostName", r->redirect_hostname);
                if (r->redirect_protocol[0])
                    s3__xml_buf_element(&b, "Protocol", r->redirect_protocol);
                if (r->redirect_replace_key_prefix[0])
                    s3__xml_buf_element(&b, "ReplaceKeyPrefixWith",
                                        r->redirect_replace_key_prefix);
                if (r->redirect_replace_key[0])
                    s3__xml_buf_element(&b, "ReplaceKeyWith",
                                        r->redirect_replace_key);
                if (r->redirect_http_code > 0)
                    s3__xml_buf_element_int(&b, "HttpRedirectCode",
                                            r->redirect_http_code);
                s3__xml_buf_close(&b, "Redirect");

                s3__xml_buf_close(&b, "RoutingRule");
            }
            s3__xml_buf_close(&b, "RoutingRules");
        }
    }

    s3_buf_append_str(&b, "</WebsiteConfiguration>");

    s3_status st = bucket_put(c, bucket, "website", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_website(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "website");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 9. Notification
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct nc_acc {
    s3_notification_config **arr;
    int *count;
    int *cap;
} nc_acc;

/* Filter rule callback */
typedef struct fr_acc {
    s3_filter_rule *arr;
    int count;
    int cap;
} fr_acc;

static int parse_filter_rule_cb(const char *fe, size_t fel, void *fud)
{
    fr_acc *a = (fr_acc *)fud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_filter_rule *p = (s3_filter_rule *)S3_REALLOC(
            a->arr, (size_t)nc * sizeof(s3_filter_rule));
        if (!p) return -1;
        a->arr = p;
        a->cap = nc;
    }
    s3_filter_rule *fr = &a->arr[a->count++];
    memset(fr, 0, sizeof(*fr));
    xml_get_str(fe, fel, "Name", fr->name, sizeof(fr->name));
    xml_get_str(fe, fel, "Value", fr->value, sizeof(fr->value));
    return 0;
}

static int parse_notification_config(const char *elem, size_t elen, void *ud)
{
    nc_acc *acc = (nc_acc *)ud;

    if (*acc->count >= *acc->cap) {
        int nc = *acc->cap ? *acc->cap * 2 : 4;
        s3_notification_config *p = (s3_notification_config *)S3_REALLOC(
            *acc->arr, (size_t)nc * sizeof(s3_notification_config));
        if (!p) return -1;
        *acc->arr = p;
        *acc->cap = nc;
    }

    s3_notification_config *cfg = &(*acc->arr)[(*acc->count)++];
    memset(cfg, 0, sizeof(*cfg));

    xml_get_str(elem, elen, "Id", cfg->id, sizeof(cfg->id));

    /* ARN - could be Topic, Queue, or CloudFunction */
    if (!xml_get_str(elem, elen, "Topic", cfg->arn, sizeof(cfg->arn)))
        if (!xml_get_str(elem, elen, "Queue", cfg->arn, sizeof(cfg->arn)))
            xml_get_str(elem, elen, "CloudFunction", cfg->arn, sizeof(cfg->arn));

    /* Events */
    cfg->events = xml_get_string_list(elem, elen, "Event", &cfg->event_count);

    /* Filter rules */
    const char *filt_val;
    size_t filt_len;
    if (s3__xml_find(elem, elen, "Filter", &filt_val, &filt_len)) {
        const char *s3key_val;
        size_t s3key_len;
        if (s3__xml_find(filt_val, filt_len, "S3Key", &s3key_val, &s3key_len)) {
            fr_acc fracc = {0};
            s3__xml_each(s3key_val, s3key_len, "FilterRule",
                         parse_filter_rule_cb, &fracc);
            cfg->filter_rules = fracc.arr;
            cfg->filter_rule_count = fracc.count;
        }
    }

    return 0;
}

s3_status s3_get_bucket_notification(s3_client *c, const char *bucket,
                                     s3_notification_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "notification");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    int topic_cap = 0, queue_cap = 0, lambda_cap = 0;

    nc_acc topic_acc = {
        &config->topic_configs, &config->topic_count, &topic_cap
    };
    nc_acc queue_acc = {
        &config->queue_configs, &config->queue_count, &queue_cap
    };
    nc_acc lambda_acc = {
        &config->lambda_configs, &config->lambda_count, &lambda_cap
    };

    s3__xml_each(xml, len, "TopicConfiguration",
                 parse_notification_config, &topic_acc);
    s3__xml_each(xml, len, "QueueConfiguration",
                 parse_notification_config, &queue_acc);
    s3__xml_each(xml, len, "CloudFunctionConfiguration",
                 parse_notification_config, &lambda_acc);

    return S3_STATUS_OK;
}

static void build_notification_configs(s3_buf *b,
                                       const char *wrapper_tag,
                                       const char *arn_tag,
                                       const s3_notification_config *configs,
                                       int count)
{
    for (int i = 0; i < count; i++) {
        const s3_notification_config *cfg = &configs[i];
        s3__xml_buf_open(b, wrapper_tag);

        if (cfg->id[0])
            s3__xml_buf_element(b, "Id", cfg->id);
        s3__xml_buf_element(b, arn_tag, cfg->arn);

        for (int j = 0; j < cfg->event_count; j++)
            s3__xml_buf_element(b, "Event", cfg->events[j]);

        if (cfg->filter_rule_count > 0) {
            s3__xml_buf_open(b, "Filter");
            s3__xml_buf_open(b, "S3Key");
            for (int j = 0; j < cfg->filter_rule_count; j++) {
                s3__xml_buf_open(b, "FilterRule");
                s3__xml_buf_element(b, "Name", cfg->filter_rules[j].name);
                s3__xml_buf_element(b, "Value", cfg->filter_rules[j].value);
                s3__xml_buf_close(b, "FilterRule");
            }
            s3__xml_buf_close(b, "S3Key");
            s3__xml_buf_close(b, "Filter");
        }

        s3__xml_buf_close(b, wrapper_tag);
    }
}

s3_status s3_put_bucket_notification(s3_client *c, const char *bucket,
                                     const s3_notification_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    build_notification_configs(&b, "TopicConfiguration", "Topic",
                               config->topic_configs, config->topic_count);
    build_notification_configs(&b, "QueueConfiguration", "Queue",
                               config->queue_configs, config->queue_count);
    build_notification_configs(&b, "CloudFunctionConfiguration", "CloudFunction",
                               config->lambda_configs, config->lambda_count);

    s3_buf_append_str(&b, "</NotificationConfiguration>");

    s3_status st = bucket_put(c, bucket, "notification", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 10. Replication
 * ═══════════════════════════════════════════════════════════════════════════ */

static int parse_replication_rule(const char *elem, size_t elen, void *ud)
{
    s3_replication_configuration *cfg = (s3_replication_configuration *)ud;

    int idx = cfg->rule_count;
    s3_replication_rule *tmp = (s3_replication_rule *)S3_REALLOC(
        cfg->rules, (size_t)(idx + 1) * sizeof(s3_replication_rule));
    if (!tmp) return -1;
    cfg->rules = tmp;
    cfg->rule_count = idx + 1;

    s3_replication_rule *r = &cfg->rules[idx];
    memset(r, 0, sizeof(*r));

    xml_get_str(elem, elen, "ID", r->id, sizeof(r->id));
    r->priority = xml_get_int(elem, elen, "Priority", 0);

    char status_str[32] = "";
    xml_get_str(elem, elen, "Status", status_str, sizeof(status_str));
    r->enabled = (strcmp(status_str, "Enabled") == 0);

    /* Prefix (deprecated filter) or Filter/Prefix */
    if (!xml_get_str(elem, elen, "Prefix", r->prefix, sizeof(r->prefix))) {
        const char *fv;
        size_t fl;
        if (s3__xml_find(elem, elen, "Filter", &fv, &fl)) {
            xml_get_str(fv, fl, "Prefix", r->prefix, sizeof(r->prefix));
        }
    }

    /* Destination */
    const char *dest_val;
    size_t dest_len;
    if (s3__xml_find(elem, elen, "Destination", &dest_val, &dest_len)) {
        xml_get_str(dest_val, dest_len, "Bucket",
                    r->destination.bucket, sizeof(r->destination.bucket));
        xml_get_str(dest_val, dest_len, "Account",
                    r->destination.account, sizeof(r->destination.account));
        xml_get_str(dest_val, dest_len, "StorageClass",
                    r->destination.storage_class,
                    sizeof(r->destination.storage_class));

        const char *enc_val;
        size_t enc_len;
        if (s3__xml_find(dest_val, dest_len, "EncryptionConfiguration",
                         &enc_val, &enc_len)) {
            r->destination.replicate_kms = true;
            xml_get_str(enc_val, enc_len, "ReplicaKmsKeyID",
                        r->destination.kms_key_id,
                        sizeof(r->destination.kms_key_id));
        }
    }

    /* DeleteMarkerReplication */
    const char *dm_val;
    size_t dm_len;
    if (s3__xml_find(elem, elen, "DeleteMarkerReplication", &dm_val, &dm_len)) {
        char dm_status[32] = "";
        xml_get_str(dm_val, dm_len, "Status", dm_status, sizeof(dm_status));
        r->delete_marker_replication = (strcmp(dm_status, "Enabled") == 0);
    }

    /* ExistingObjectReplication */
    const char *eor_val;
    size_t eor_len;
    if (s3__xml_find(elem, elen, "ExistingObjectReplication", &eor_val, &eor_len)) {
        char eor_status[32] = "";
        xml_get_str(eor_val, eor_len, "Status", eor_status, sizeof(eor_status));
        r->existing_object_replication = (strcmp(eor_status, "Enabled") == 0);
    }

    return 0;
}

s3_status s3_get_bucket_replication(s3_client *c, const char *bucket,
                                    s3_replication_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "replication");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    xml_get_str(xml, len, "Role", config->role, sizeof(config->role));
    s3__xml_each(xml, len, "Rule", parse_replication_rule, config);

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_replication(s3_client *c, const char *bucket,
                                    const s3_replication_configuration *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&b, "Role", config->role);

    for (int i = 0; i < config->rule_count; i++) {
        const s3_replication_rule *r = &config->rules[i];
        s3__xml_buf_open(&b, "Rule");

        if (r->id[0])
            s3__xml_buf_element(&b, "ID", r->id);
        if (r->priority > 0)
            s3__xml_buf_element_int(&b, "Priority", r->priority);

        s3__xml_buf_element(&b, "Status", r->enabled ? "Enabled" : "Disabled");

        /* Filter */
        s3__xml_buf_open(&b, "Filter");
        s3__xml_buf_element(&b, "Prefix", r->prefix);
        s3__xml_buf_close(&b, "Filter");

        /* Destination */
        s3__xml_buf_open(&b, "Destination");
        s3__xml_buf_element(&b, "Bucket", r->destination.bucket);
        if (r->destination.account[0])
            s3__xml_buf_element(&b, "Account", r->destination.account);
        if (r->destination.storage_class[0])
            s3__xml_buf_element(&b, "StorageClass", r->destination.storage_class);
        if (r->destination.replicate_kms) {
            s3__xml_buf_open(&b, "EncryptionConfiguration");
            s3__xml_buf_element(&b, "ReplicaKmsKeyID",
                                r->destination.kms_key_id);
            s3__xml_buf_close(&b, "EncryptionConfiguration");
        }
        s3__xml_buf_close(&b, "Destination");

        /* DeleteMarkerReplication */
        s3__xml_buf_open(&b, "DeleteMarkerReplication");
        s3__xml_buf_element(&b, "Status",
                            r->delete_marker_replication ? "Enabled" : "Disabled");
        s3__xml_buf_close(&b, "DeleteMarkerReplication");

        if (r->existing_object_replication) {
            s3__xml_buf_open(&b, "ExistingObjectReplication");
            s3__xml_buf_element(&b, "Status", "Enabled");
            s3__xml_buf_close(&b, "ExistingObjectReplication");
        }

        s3__xml_buf_close(&b, "Rule");
    }

    s3_buf_append_str(&b, "</ReplicationConfiguration>");

    s3_status st = bucket_put(c, bucket, "replication", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_replication(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "replication");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 11. Accelerate
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_accelerate(s3_client *c, const char *bucket,
                                   bool *enabled)
{
    if (!c || !bucket || !enabled)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "accelerate");
    if (st != S3_STATUS_OK) return st;

    char val[32] = "";
    xml_get_str(c->response.data, c->response.len, "Status", val, sizeof(val));
    *enabled = (strcmp(val, "Enabled") == 0);

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_accelerate(s3_client *c, const char *bucket,
                                   bool enabled)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<AccelerateConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&b, "Status", enabled ? "Enabled" : "Suspended");
    s3_buf_append_str(&b, "</AccelerateConfiguration>");

    s3_status st = bucket_put(c, bucket, "accelerate", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 12. Request Payment
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_request_payment(s3_client *c, const char *bucket,
                                        s3_payer *payer)
{
    if (!c || !bucket || !payer)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "requestPayment");
    if (st != S3_STATUS_OK) return st;

    char val[32] = "";
    xml_get_str(c->response.data, c->response.len, "Payer", val, sizeof(val));
    *payer = (strcmp(val, "Requester") == 0) ?
             S3_PAYER_REQUESTER : S3_PAYER_BUCKET_OWNER;

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_request_payment(s3_client *c, const char *bucket,
                                        s3_payer payer)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<RequestPaymentConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&b, "Payer",
                        payer == S3_PAYER_REQUESTER ? "Requester" : "BucketOwner");
    s3_buf_append_str(&b, "</RequestPaymentConfiguration>");

    s3_status st = bucket_put(c, bucket, "requestPayment", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 13. Object Lock Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_object_lock_configuration(s3_client *c, const char *bucket,
                                           s3_object_lock_config *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "object-lock");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    char ols[32] = "";
    xml_get_str(xml, len, "ObjectLockEnabled", ols, sizeof(ols));
    config->enabled = (strcmp(ols, "Enabled") == 0);

    const char *dr_val;
    size_t dr_len;
    if (s3__xml_find(xml, len, "DefaultRetention", &dr_val, &dr_len)) {
        char mode[32] = "";
        xml_get_str(dr_val, dr_len, "Mode", mode, sizeof(mode));
        if (strcmp(mode, "GOVERNANCE") == 0)
            config->default_mode = S3_LOCK_GOVERNANCE;
        else if (strcmp(mode, "COMPLIANCE") == 0)
            config->default_mode = S3_LOCK_COMPLIANCE;
        config->default_days = xml_get_int(dr_val, dr_len, "Days", 0);
        config->default_years = xml_get_int(dr_val, dr_len, "Years", 0);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_object_lock_configuration(s3_client *c, const char *bucket,
                                           const s3_object_lock_config *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&b, "ObjectLockEnabled",
                        config->enabled ? "Enabled" : "Disabled");

    if (config->default_mode != S3_LOCK_NONE) {
        s3__xml_buf_open(&b, "Rule");
        s3__xml_buf_open(&b, "DefaultRetention");

        const char *mode = config->default_mode == S3_LOCK_GOVERNANCE ?
                           "GOVERNANCE" : "COMPLIANCE";
        s3__xml_buf_element(&b, "Mode", mode);

        if (config->default_days > 0)
            s3__xml_buf_element_int(&b, "Days", config->default_days);
        if (config->default_years > 0)
            s3__xml_buf_element_int(&b, "Years", config->default_years);

        s3__xml_buf_close(&b, "DefaultRetention");
        s3__xml_buf_close(&b, "Rule");
    }

    s3_buf_append_str(&b, "</ObjectLockConfiguration>");

    s3_status st = bucket_put(c, bucket, "object-lock", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 14. ACL
 * ═══════════════════════════════════════════════════════════════════════════ */

static int parse_grant(const char *elem, size_t elen, void *ud)
{
    s3_acl *acl = (s3_acl *)ud;

    int idx = acl->grant_count;
    s3_grant *tmp = (s3_grant *)S3_REALLOC(
        acl->grants, (size_t)(idx + 1) * sizeof(s3_grant));
    if (!tmp) return -1;
    acl->grants = tmp;
    acl->grant_count = idx + 1;

    s3_grant *g = &acl->grants[idx];
    memset(g, 0, sizeof(*g));

    xml_get_str(elem, elen, "Permission", g->permission, sizeof(g->permission));

    const char *grantee_val;
    size_t grantee_len;
    if (s3__xml_find(elem, elen, "Grantee", &grantee_val, &grantee_len)) {
        xml_get_str(grantee_val, grantee_len, "ID",
                    g->grantee.id, sizeof(g->grantee.id));
        xml_get_str(grantee_val, grantee_len, "DisplayName",
                    g->grantee.display_name, sizeof(g->grantee.display_name));
        xml_get_str(grantee_val, grantee_len, "URI",
                    g->grantee.uri, sizeof(g->grantee.uri));
        xml_get_str(grantee_val, grantee_len, "EmailAddress",
                    g->grantee.email, sizeof(g->grantee.email));

        /* Determine type */
        if (g->grantee.id[0])
            snprintf(g->grantee.type, sizeof(g->grantee.type), "CanonicalUser");
        else if (g->grantee.uri[0])
            snprintf(g->grantee.type, sizeof(g->grantee.type), "Group");
        else if (g->grantee.email[0])
            snprintf(g->grantee.type, sizeof(g->grantee.type),
                     "AmazonCustomerByEmail");
    }

    return 0;
}

s3_status s3_get_bucket_acl(s3_client *c, const char *bucket, s3_acl *acl)
{
    if (!c || !bucket || !acl)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(acl, 0, sizeof(*acl));

    s3_status st = bucket_get(c, bucket, "acl");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    xml_get_str_in(xml, len, "Owner", "ID",
                   acl->owner_id, sizeof(acl->owner_id));
    xml_get_str_in(xml, len, "Owner", "DisplayName",
                   acl->owner_display_name, sizeof(acl->owner_display_name));

    s3__xml_each(xml, len, "Grant", parse_grant, acl);

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_acl(s3_client *c, const char *bucket,
                            const s3_acl *acl)
{
    if (!c || !bucket || !acl)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_open(&b, "Owner");
    s3__xml_buf_element(&b, "ID", acl->owner_id);
    if (acl->owner_display_name[0])
        s3__xml_buf_element(&b, "DisplayName", acl->owner_display_name);
    s3__xml_buf_close(&b, "Owner");

    s3__xml_buf_open(&b, "AccessControlList");

    for (int i = 0; i < acl->grant_count; i++) {
        const s3_grant *g = &acl->grants[i];
        s3__xml_buf_open(&b, "Grant");

        /* Grantee with xsi:type attribute */
        if (strcmp(g->grantee.type, "Group") == 0) {
            s3_buf_append_str(&b,
                "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                " xsi:type=\"Group\">");
            s3__xml_buf_element(&b, "URI", g->grantee.uri);
            s3_buf_append_str(&b, "</Grantee>");
        } else if (strcmp(g->grantee.type, "AmazonCustomerByEmail") == 0) {
            s3_buf_append_str(&b,
                "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                " xsi:type=\"AmazonCustomerByEmail\">");
            s3__xml_buf_element(&b, "EmailAddress", g->grantee.email);
            s3_buf_append_str(&b, "</Grantee>");
        } else {
            s3_buf_append_str(&b,
                "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                " xsi:type=\"CanonicalUser\">");
            s3__xml_buf_element(&b, "ID", g->grantee.id);
            if (g->grantee.display_name[0])
                s3__xml_buf_element(&b, "DisplayName", g->grantee.display_name);
            s3_buf_append_str(&b, "</Grantee>");
        }

        s3__xml_buf_element(&b, "Permission", g->permission);
        s3__xml_buf_close(&b, "Grant");
    }

    s3__xml_buf_close(&b, "AccessControlList");
    s3_buf_append_str(&b, "</AccessControlPolicy>");

    s3_status st = bucket_put(c, bucket, "acl", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_put_bucket_acl_canned(s3_client *c, const char *bucket,
                                   s3_canned_acl acl)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    const char *acl_str = s3__canned_acl_string(acl);
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "x-amz-acl: %s", acl_str);

    struct curl_slist *hdrs = curl_slist_append(nullptr, hdr);

    s3_status st = bucket_put(c, bucket, "acl", "", 0, hdrs);
    curl_slist_free_all(hdrs);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 15. Intelligent Tiering
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Tiering callback */
typedef struct tiering_acc {
    s3_tiering *arr;
    int count;
    int cap;
} tiering_acc;

static int parse_tiering_cb(const char *te, size_t tel, void *tud)
{
    tiering_acc *a = (tiering_acc *)tud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_tiering *p = (s3_tiering *)S3_REALLOC(a->arr,
            (size_t)nc * sizeof(s3_tiering));
        if (!p) return -1;
        a->arr = p;
        a->cap = nc;
    }
    s3_tiering *t = &a->arr[a->count++];
    memset(t, 0, sizeof(*t));
    xml_get_str(te, tel, "AccessTier", t->access_tier, sizeof(t->access_tier));
    t->days = xml_get_int(te, tel, "Days", 0);
    return 0;
}

static void parse_intelligent_tiering_config(const char *xml, size_t len,
                                             s3_intelligent_tiering_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    xml_get_str(xml, len, "Id", cfg->id, sizeof(cfg->id));

    char status_str[32] = "";
    xml_get_str(xml, len, "Status", status_str, sizeof(status_str));
    cfg->enabled = (strcmp(status_str, "Enabled") == 0);

    /* Filter */
    const char *fv;
    size_t fl;
    if (s3__xml_find(xml, len, "Filter", &fv, &fl)) {
        xml_get_str(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));

        tag_acc tacc = {0};
        s3__xml_each(fv, fl, "Tag", parse_tag_cb, &tacc);
        cfg->tags = tacc.tags;
        cfg->tag_count = tacc.count;
    }

    /* Tierings */
    tiering_acc tiacc = {0};
    s3__xml_each(xml, len, "Tiering", parse_tiering_cb, &tiacc);
    cfg->tierings = tiacc.arr;
    cfg->tiering_count = tiacc.count;
}

s3_status s3_get_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                            const char *id,
                                            s3_intelligent_tiering_config *config)
{
    if (!c || !bucket || !id || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "intelligent-tiering&id=%s", id);

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    parse_intelligent_tiering_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

static void build_filter_with_tags(s3_buf *b, const char *prefix,
                                   const s3_tag *tags, int tag_count)
{
    bool has_filter = (prefix && prefix[0]) || tag_count > 0;
    if (!has_filter) return;

    s3__xml_buf_open(b, "Filter");
    bool need_and = ((prefix && prefix[0]) && tag_count > 0) || tag_count > 1;
    if (need_and) s3__xml_buf_open(b, "And");

    if (prefix && prefix[0])
        s3__xml_buf_element(b, "Prefix", prefix);
    for (int i = 0; i < tag_count; i++) {
        s3__xml_buf_open(b, "Tag");
        s3__xml_buf_element(b, "Key", tags[i].key);
        s3__xml_buf_element(b, "Value", tags[i].value);
        s3__xml_buf_close(b, "Tag");
    }

    if (need_and) s3__xml_buf_close(b, "And");
    s3__xml_buf_close(b, "Filter");
}

s3_status s3_put_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                            const s3_intelligent_tiering_config *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "intelligent-tiering&id=%s", config->id);

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<IntelligentTieringConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&b, "Id", config->id);
    s3__xml_buf_element(&b, "Status", config->enabled ? "Enabled" : "Disabled");

    build_filter_with_tags(&b, config->prefix, config->tags, config->tag_count);

    for (int i = 0; i < config->tiering_count; i++) {
        s3__xml_buf_open(&b, "Tiering");
        s3__xml_buf_element(&b, "AccessTier", config->tierings[i].access_tier);
        s3__xml_buf_element_int(&b, "Days", config->tierings[i].days);
        s3__xml_buf_close(&b, "Tiering");
    }

    s3_buf_append_str(&b, "</IntelligentTieringConfiguration>");

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = qs,
        .upload_data = b.data,
        .upload_len = b.len,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                               const char *id)
{
    if (!c || !bucket || !id)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "intelligent-tiering&id=%s", id);

    s3_request_params p = {
        .method = "DELETE",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* List intelligent tiering callback */
typedef struct it_list_acc {
    s3_intelligent_tiering_config *arr;
    int count;
    int cap;
} it_list_acc;

static int parse_it_list_cb(const char *elem, size_t elen, void *ud)
{
    it_list_acc *a = (it_list_acc *)ud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_intelligent_tiering_config *p =
            (s3_intelligent_tiering_config *)S3_REALLOC(
                a->arr, (size_t)nc * sizeof(*p));
        if (!p) return -1;
        a->arr = p;
        a->cap = nc;
    }
    parse_intelligent_tiering_config(elem, elen, &a->arr[a->count++]);
    return 0;
}

s3_status s3_list_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                             s3_intelligent_tiering_config **configs,
                                             int *count)
{
    if (!c || !bucket || !configs || !count)
        return S3_STATUS_INVALID_ARGUMENT;

    *configs = nullptr;
    *count = 0;

    s3_status st = bucket_get(c, bucket, "intelligent-tiering");
    if (st != S3_STATUS_OK) return st;

    it_list_acc acc = {0};
    s3__xml_each(c->response.data, c->response.len,
                 "IntelligentTieringConfiguration", parse_it_list_cb, &acc);

    *configs = acc.arr;
    *count = acc.count;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 16. Metrics
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_metrics_config(const char *xml, size_t len,
                                 s3_metrics_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    xml_get_str(xml, len, "Id", cfg->id, sizeof(cfg->id));

    const char *fv;
    size_t fl;
    if (s3__xml_find(xml, len, "Filter", &fv, &fl)) {
        xml_get_str(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));

        tag_acc tacc = {0};
        s3__xml_each(fv, fl, "Tag", parse_tag_cb, &tacc);
        cfg->tags = tacc.tags;
        cfg->tag_count = tacc.count;
    }
}

s3_status s3_get_bucket_metrics(s3_client *c, const char *bucket,
                                const char *id, s3_metrics_config *config)
{
    if (!c || !bucket || !id || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "metrics&id=%s", id);

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    parse_metrics_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_metrics(s3_client *c, const char *bucket,
                                const s3_metrics_config *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "metrics&id=%s", config->id);

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<MetricsConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&b, "Id", config->id);
    build_filter_with_tags(&b, config->prefix, config->tags, config->tag_count);
    s3_buf_append_str(&b, "</MetricsConfiguration>");

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = qs,
        .upload_data = b.data,
        .upload_len = b.len,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_metrics(s3_client *c, const char *bucket,
                                   const char *id)
{
    if (!c || !bucket || !id)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "metrics&id=%s", id);

    s3_request_params p = {
        .method = "DELETE",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* Metrics list callback */
typedef struct mc_list_acc {
    s3_metrics_config *arr;
    int count;
    int cap;
} mc_list_acc;

static int parse_mc_list_cb(const char *elem, size_t elen, void *ud)
{
    mc_list_acc *a = (mc_list_acc *)ud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_metrics_config *pp = (s3_metrics_config *)S3_REALLOC(
            a->arr, (size_t)nc * sizeof(*pp));
        if (!pp) return -1;
        a->arr = pp;
        a->cap = nc;
    }
    parse_metrics_config(elem, elen, &a->arr[a->count++]);
    return 0;
}

s3_status s3_list_bucket_metrics(s3_client *c, const char *bucket,
                                 const char *continuation_token,
                                 s3_list_metrics_result *result)
{
    if (!c || !bucket || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char qs[1280];
    if (continuation_token && continuation_token[0])
        snprintf(qs, sizeof(qs), "metrics&continuation-token=%s",
                 continuation_token);
    else
        snprintf(qs, sizeof(qs), "metrics");

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    result->is_truncated = xml_get_bool(xml, len, "IsTruncated");
    xml_get_str(xml, len, "ContinuationToken",
                result->continuation_token, sizeof(result->continuation_token));

    mc_list_acc acc = {0};
    s3__xml_each(xml, len, "MetricsConfiguration", parse_mc_list_cb, &acc);
    result->configs = acc.arr;
    result->count = acc.count;

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 17. Inventory
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_inventory_config(const char *xml, size_t len,
                                   s3_inventory_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    xml_get_str(xml, len, "Id", cfg->id, sizeof(cfg->id));

    char en[32] = "";
    xml_get_str(xml, len, "IsEnabled", en, sizeof(en));
    cfg->enabled = (strncasecmp(en, "true", 4) == 0);

    xml_get_str(xml, len, "IncludedObjectVersions",
                cfg->included_versions, sizeof(cfg->included_versions));

    /* Schedule */
    const char *sv;
    size_t sl;
    if (s3__xml_find(xml, len, "Schedule", &sv, &sl)) {
        xml_get_str(sv, sl, "Frequency", cfg->schedule, sizeof(cfg->schedule));
    }

    /* Destination */
    const char *dv;
    size_t dl;
    if (s3__xml_find(xml, len, "Destination", &dv, &dl)) {
        const char *s3bv;
        size_t s3bl;
        if (s3__xml_find(dv, dl, "S3BucketDestination", &s3bv, &s3bl)) {
            xml_get_str(s3bv, s3bl, "Bucket",
                        cfg->destination_bucket, sizeof(cfg->destination_bucket));
            xml_get_str(s3bv, s3bl, "Prefix",
                        cfg->destination_prefix, sizeof(cfg->destination_prefix));
            xml_get_str(s3bv, s3bl, "Format",
                        cfg->destination_format, sizeof(cfg->destination_format));
            xml_get_str(s3bv, s3bl, "AccountId",
                        cfg->destination_account, sizeof(cfg->destination_account));
        }
    }

    /* Filter */
    const char *fv;
    size_t fl;
    if (s3__xml_find(xml, len, "Filter", &fv, &fl)) {
        xml_get_str(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));
    }

    /* OptionalFields */
    const char *ofv;
    size_t ofl;
    if (s3__xml_find(xml, len, "OptionalFields", &ofv, &ofl)) {
        cfg->optional_fields = xml_get_string_list(ofv, ofl, "Field",
                                                   &cfg->field_count);
    }
}

s3_status s3_get_bucket_inventory(s3_client *c, const char *bucket,
                                  const char *id, s3_inventory_config *config)
{
    if (!c || !bucket || !id || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "inventory&id=%s", id);

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    parse_inventory_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_inventory(s3_client *c, const char *bucket,
                                  const s3_inventory_config *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "inventory&id=%s", config->id);

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&b, "Id", config->id);
    s3__xml_buf_element_bool(&b, "IsEnabled", config->enabled);
    s3__xml_buf_element(&b, "IncludedObjectVersions", config->included_versions);

    s3__xml_buf_open(&b, "Schedule");
    s3__xml_buf_element(&b, "Frequency", config->schedule);
    s3__xml_buf_close(&b, "Schedule");

    s3__xml_buf_open(&b, "Destination");
    s3__xml_buf_open(&b, "S3BucketDestination");
    s3__xml_buf_element(&b, "Bucket", config->destination_bucket);
    if (config->destination_prefix[0])
        s3__xml_buf_element(&b, "Prefix", config->destination_prefix);
    s3__xml_buf_element(&b, "Format", config->destination_format);
    if (config->destination_account[0])
        s3__xml_buf_element(&b, "AccountId", config->destination_account);
    s3__xml_buf_close(&b, "S3BucketDestination");
    s3__xml_buf_close(&b, "Destination");

    if (config->prefix[0]) {
        s3__xml_buf_open(&b, "Filter");
        s3__xml_buf_element(&b, "Prefix", config->prefix);
        s3__xml_buf_close(&b, "Filter");
    }

    if (config->field_count > 0) {
        s3__xml_buf_open(&b, "OptionalFields");
        for (int i = 0; i < config->field_count; i++)
            s3__xml_buf_element(&b, "Field", config->optional_fields[i]);
        s3__xml_buf_close(&b, "OptionalFields");
    }

    s3_buf_append_str(&b, "</InventoryConfiguration>");

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = qs,
        .upload_data = b.data,
        .upload_len = b.len,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_inventory(s3_client *c, const char *bucket,
                                     const char *id)
{
    if (!c || !bucket || !id)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "inventory&id=%s", id);

    s3_request_params p = {
        .method = "DELETE",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* Inventory list callback */
typedef struct ic_list_acc {
    s3_inventory_config *arr;
    int count;
    int cap;
} ic_list_acc;

static int parse_ic_list_cb(const char *elem, size_t elen, void *ud)
{
    ic_list_acc *a = (ic_list_acc *)ud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_inventory_config *pp = (s3_inventory_config *)S3_REALLOC(
            a->arr, (size_t)nc * sizeof(*pp));
        if (!pp) return -1;
        a->arr = pp;
        a->cap = nc;
    }
    parse_inventory_config(elem, elen, &a->arr[a->count++]);
    return 0;
}

s3_status s3_list_bucket_inventory(s3_client *c, const char *bucket,
                                   const char *continuation_token,
                                   s3_list_inventory_result *result)
{
    if (!c || !bucket || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char qs[1280];
    if (continuation_token && continuation_token[0])
        snprintf(qs, sizeof(qs), "inventory&continuation-token=%s",
                 continuation_token);
    else
        snprintf(qs, sizeof(qs), "inventory");

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    result->is_truncated = xml_get_bool(xml, len, "IsTruncated");
    xml_get_str(xml, len, "ContinuationToken",
                result->continuation_token, sizeof(result->continuation_token));

    ic_list_acc acc = {0};
    s3__xml_each(xml, len, "InventoryConfiguration", parse_ic_list_cb, &acc);
    result->configs = acc.arr;
    result->count = acc.count;

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 18. Analytics
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_analytics_config(const char *xml, size_t len,
                                   s3_analytics_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    xml_get_str(xml, len, "Id", cfg->id, sizeof(cfg->id));

    /* Filter */
    const char *fv;
    size_t fl;
    if (s3__xml_find(xml, len, "Filter", &fv, &fl)) {
        xml_get_str(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));

        tag_acc tacc = {0};
        s3__xml_each(fv, fl, "Tag", parse_tag_cb, &tacc);
        cfg->tags = tacc.tags;
        cfg->tag_count = tacc.count;
    }

    /* StorageClassAnalysis / DataExport / Destination */
    const char *sca_val;
    size_t sca_len;
    if (s3__xml_find(xml, len, "StorageClassAnalysis", &sca_val, &sca_len)) {
        const char *de_val;
        size_t de_len;
        if (s3__xml_find(sca_val, sca_len, "DataExport", &de_val, &de_len)) {
            const char *dest_val;
            size_t dest_len;
            if (s3__xml_find(de_val, de_len, "Destination", &dest_val, &dest_len)) {
                const char *s3bd_val;
                size_t s3bd_len;
                if (s3__xml_find(dest_val, dest_len, "S3BucketDestination",
                                 &s3bd_val, &s3bd_len)) {
                    xml_get_str(s3bd_val, s3bd_len, "Bucket",
                                cfg->export_bucket, sizeof(cfg->export_bucket));
                    xml_get_str(s3bd_val, s3bd_len, "Prefix",
                                cfg->export_prefix, sizeof(cfg->export_prefix));
                    xml_get_str(s3bd_val, s3bd_len, "Format",
                                cfg->export_format, sizeof(cfg->export_format));
                }
            }
        }
    }
}

s3_status s3_get_bucket_analytics(s3_client *c, const char *bucket,
                                  const char *id, s3_analytics_config *config)
{
    if (!c || !bucket || !id || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "analytics&id=%s", id);

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    parse_analytics_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_analytics(s3_client *c, const char *bucket,
                                  const s3_analytics_config *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "analytics&id=%s", config->id);

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<AnalyticsConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&b, "Id", config->id);

    build_filter_with_tags(&b, config->prefix, config->tags, config->tag_count);

    /* StorageClassAnalysis */
    s3__xml_buf_open(&b, "StorageClassAnalysis");
    if (config->export_bucket[0]) {
        s3__xml_buf_open(&b, "DataExport");
        s3__xml_buf_element(&b, "OutputSchemaVersion", "V_1");
        s3__xml_buf_open(&b, "Destination");
        s3__xml_buf_open(&b, "S3BucketDestination");
        s3__xml_buf_element(&b, "Bucket", config->export_bucket);
        if (config->export_prefix[0])
            s3__xml_buf_element(&b, "Prefix", config->export_prefix);
        s3__xml_buf_element(&b, "Format",
                            config->export_format[0] ? config->export_format : "CSV");
        s3__xml_buf_close(&b, "S3BucketDestination");
        s3__xml_buf_close(&b, "Destination");
        s3__xml_buf_close(&b, "DataExport");
    }
    s3__xml_buf_close(&b, "StorageClassAnalysis");

    s3_buf_append_str(&b, "</AnalyticsConfiguration>");

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = qs,
        .upload_data = b.data,
        .upload_len = b.len,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_analytics(s3_client *c, const char *bucket,
                                     const char *id)
{
    if (!c || !bucket || !id)
        return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "analytics&id=%s", id);

    s3_request_params p = {
        .method = "DELETE",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* Analytics list callback */
typedef struct ac_list_acc {
    s3_analytics_config *arr;
    int count;
    int cap;
} ac_list_acc;

static int parse_ac_list_cb(const char *elem, size_t elen, void *ud)
{
    ac_list_acc *a = (ac_list_acc *)ud;
    if (a->count >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 4;
        s3_analytics_config *pp = (s3_analytics_config *)S3_REALLOC(
            a->arr, (size_t)nc * sizeof(*pp));
        if (!pp) return -1;
        a->arr = pp;
        a->cap = nc;
    }
    parse_analytics_config(elem, elen, &a->arr[a->count++]);
    return 0;
}

s3_status s3_list_bucket_analytics(s3_client *c, const char *bucket,
                                   const char *continuation_token,
                                   s3_list_analytics_result *result)
{
    if (!c || !bucket || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char qs[1280];
    if (continuation_token && continuation_token[0])
        snprintf(qs, sizeof(qs), "analytics&continuation-token=%s",
                 continuation_token);
    else
        snprintf(qs, sizeof(qs), "analytics");

    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    result->is_truncated = xml_get_bool(xml, len, "IsTruncated");
    xml_get_str(xml, len, "ContinuationToken",
                result->continuation_token, sizeof(result->continuation_token));

    ac_list_acc acc = {0};
    s3__xml_each(xml, len, "AnalyticsConfiguration", parse_ac_list_cb, &acc);
    result->configs = acc.arr;
    result->count = acc.count;

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 19. Public Access Block
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_public_access_block(s3_client *c, const char *bucket,
                                     s3_public_access_block *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "publicAccessBlock");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    config->block_public_acls = xml_get_bool(xml, len, "BlockPublicAcls");
    config->ignore_public_acls = xml_get_bool(xml, len, "IgnorePublicAcls");
    config->block_public_policy = xml_get_bool(xml, len, "BlockPublicPolicy");
    config->restrict_public_buckets = xml_get_bool(xml, len, "RestrictPublicBuckets");

    return S3_STATUS_OK;
}

s3_status s3_put_public_access_block(s3_client *c, const char *bucket,
                                     const s3_public_access_block *config)
{
    if (!c || !bucket || !config)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element_bool(&b, "BlockPublicAcls", config->block_public_acls);
    s3__xml_buf_element_bool(&b, "IgnorePublicAcls", config->ignore_public_acls);
    s3__xml_buf_element_bool(&b, "BlockPublicPolicy", config->block_public_policy);
    s3__xml_buf_element_bool(&b, "RestrictPublicBuckets", config->restrict_public_buckets);

    s3_buf_append_str(&b, "</PublicAccessBlockConfiguration>");

    s3_status st = bucket_put(c, bucket, "publicAccessBlock", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_public_access_block(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "publicAccessBlock");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 20. Ownership Controls
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_ownership_controls(s3_client *c, const char *bucket,
                                           s3_object_ownership *ownership)
{
    if (!c || !bucket || !ownership)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "ownershipControls");
    if (st != S3_STATUS_OK) return st;

    char val[64] = "";
    xml_get_str(c->response.data, c->response.len,
                "ObjectOwnership", val, sizeof(val));

    if (strcmp(val, "BucketOwnerPreferred") == 0)
        *ownership = S3_OWNERSHIP_BUCKET_OWNER_PREFERRED;
    else if (strcmp(val, "ObjectWriter") == 0)
        *ownership = S3_OWNERSHIP_OBJECT_WRITER;
    else
        *ownership = S3_OWNERSHIP_BUCKET_OWNER_ENFORCED;

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_ownership_controls(s3_client *c, const char *bucket,
                                           s3_object_ownership ownership)
{
    if (!c || !bucket)
        return S3_STATUS_INVALID_ARGUMENT;

    const char *val;
    switch (ownership) {
    case S3_OWNERSHIP_BUCKET_OWNER_PREFERRED:
        val = "BucketOwnerPreferred"; break;
    case S3_OWNERSHIP_OBJECT_WRITER:
        val = "ObjectWriter"; break;
    default:
        val = "BucketOwnerEnforced"; break;
    }

    s3_buf b;
    s3_buf_init(&b);
    s3__xml_buf_declaration(&b);
    s3_buf_append_str(&b,
        "<OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_open(&b, "Rule");
    s3__xml_buf_element(&b, "ObjectOwnership", val);
    s3__xml_buf_close(&b, "Rule");
    s3_buf_append_str(&b, "</OwnershipControls>");

    s3_status st = bucket_put(c, bucket, "ownershipControls", b.data, b.len, nullptr);
    s3_buf_free(&b);
    return st;
}

s3_status s3_delete_bucket_ownership_controls(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "ownershipControls");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Free Functions
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_cors_configuration_free(s3_cors_configuration *r)
{
    if (!r) return;
    for (int i = 0; i < r->rule_count; i++) {
        s3_cors_rule *rule = &r->rules[i];
        free_string_list(rule->allowed_origins, rule->allowed_origin_count);
        free_string_list(rule->allowed_methods, rule->allowed_method_count);
        free_string_list(rule->allowed_headers, rule->allowed_header_count);
        free_string_list(rule->expose_headers, rule->expose_header_count);
    }
    S3_FREE(r->rules);
    r->rules = nullptr;
    r->rule_count = 0;
}

void s3_lifecycle_configuration_free(s3_lifecycle_configuration *r)
{
    if (!r) return;
    for (int i = 0; i < r->rule_count; i++) {
        s3_lifecycle_rule *rule = &r->rules[i];
        S3_FREE(rule->filter.tags);
        S3_FREE(rule->transitions);
        S3_FREE(rule->noncurrent_transitions);
    }
    S3_FREE(r->rules);
    r->rules = nullptr;
    r->rule_count = 0;
}

void s3_website_configuration_free(s3_website_configuration *r)
{
    if (!r) return;
    S3_FREE(r->routing_rules);
    r->routing_rules = nullptr;
    r->routing_rule_count = 0;
}

static void free_notification_configs(s3_notification_config *configs, int count)
{
    if (!configs) return;
    for (int i = 0; i < count; i++) {
        free_string_list(configs[i].events, configs[i].event_count);
        S3_FREE(configs[i].filter_rules);
    }
    S3_FREE(configs);
}

void s3_notification_configuration_free(s3_notification_configuration *r)
{
    if (!r) return;
    free_notification_configs(r->topic_configs, r->topic_count);
    free_notification_configs(r->queue_configs, r->queue_count);
    free_notification_configs(r->lambda_configs, r->lambda_count);
    memset(r, 0, sizeof(*r));
}

void s3_replication_configuration_free(s3_replication_configuration *r)
{
    if (!r) return;
    S3_FREE(r->rules);
    r->rules = nullptr;
    r->rule_count = 0;
}
