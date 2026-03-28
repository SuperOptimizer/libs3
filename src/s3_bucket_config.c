/*
 * libs3 — Bucket Configuration Operations
 *
 * Implements all bucket configuration GET/PUT/DELETE operations:
 *   versioning, lifecycle, policy, CORS, encryption, logging, tagging,
 *   website, notification, replication, accelerate, request payment,
 *   object lock, ACL, intelligent-tiering, metrics, inventory, analytics,
 *   public access block, ownership controls.
 */

#include "s3_internal.h"
#include <inttypes.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers — XML extract into fixed-size buffer
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

static void xml_extract_in(const char *xml, size_t len,
                           const char *parent, const char *child,
                           char *dst, size_t dst_size)
{
    const char *v;
    size_t vlen;
    if (s3__xml_find_in(xml, len, parent, child, &v, &vlen)) {
        s3__xml_decode_entities(v, vlen, dst, dst_size);
    } else {
        dst[0] = '\0';
    }
}

static int xml_extract_int(const char *xml, size_t len, const char *tag)
{
    char buf[32];
    xml_extract(xml, len, tag, buf, sizeof(buf));
    return buf[0] ? (int)strtol(buf, nullptr, 10) : 0;
}

static int64_t xml_extract_int64(const char *xml, size_t len, const char *tag)
{
    char buf[32];
    xml_extract(xml, len, tag, buf, sizeof(buf));
    return buf[0] ? strtoll(buf, nullptr, 10) : 0;
}

static bool xml_extract_bool(const char *xml, size_t len, const char *tag)
{
    char buf[16];
    xml_extract(xml, len, tag, buf, sizeof(buf));
    return (strcmp(buf, "true") == 0 || strcmp(buf, "True") == 0 ||
            strcmp(buf, "Enabled") == 0);
}

/* Simple DELETE helper for bucket sub-resources */
static s3_status bucket_delete(s3_client *c, const char *bucket, const char *subresource)
{
    s3_request_params p = {
        .method = "DELETE",
        .bucket = bucket,
        .query_string = subresource,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* Simple GET helper — returns collected response in c->response */
static s3_status bucket_get(s3_client *c, const char *bucket, const char *qs)
{
    s3_request_params p = {
        .method = "GET",
        .bucket = bucket,
        .query_string = qs,
        .collect_response = true,
    };
    return s3__request(c, &p);
}

/* PUT helper with XML body */
static s3_status bucket_put_xml(s3_client *c, const char *bucket,
                                const char *qs, const s3_buf *body)
{
    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = qs,
        .extra_headers = hdrs,
        .upload_data = body->data,
        .upload_len = body->len,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML builder helper for tags
 * ═══════════════════════════════════════════════════════════════════════════ */

static int build_tag_xml(s3_buf *b, const s3_tag *tag)
{
    if (s3__xml_buf_open(b, "Tag") < 0) return -1;
    if (s3__xml_buf_element(b, "Key", tag->key) < 0) return -1;
    if (s3__xml_buf_element(b, "Value", tag->value) < 0) return -1;
    return s3__xml_buf_close(b, "Tag");
}

/* Parse tags from within an element containing <Tag><Key>...</Key><Value>...</Value></Tag> */
static int parse_tags(const char *xml, size_t len, s3_tag **out_tags, int *out_count)
{
    /* Count tags */
    typedef struct { s3_tag *tags; int count; int cap; } tag_ctx;
    tag_ctx ctx = { nullptr, 0, 0 };

    s3__xml_each(xml, len, "Tag", (s3__xml_each_fn)(void*)nullptr, nullptr);

    /* Just iterate manually */
    int count = 0;
    const char *p = xml;
    size_t rem = len;
    while (rem > 0) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, "Tag", &v, &vl)) break;
        count++;
        const char *after = v + vl;
        /* Skip past </Tag> */
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }

    if (count == 0) {
        *out_tags = nullptr;
        *out_count = 0;
        return 0;
    }

    s3_tag *tags = (s3_tag *)S3_CALLOC((size_t)count, sizeof(s3_tag));
    if (!tags) return -1;

    int idx = 0;
    p = xml;
    rem = len;
    while (rem > 0 && idx < count) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, "Tag", &v, &vl)) break;
        xml_extract(v, vl, "Key", tags[idx].key, sizeof(tags[idx].key));
        xml_extract(v, vl, "Value", tags[idx].value, sizeof(tags[idx].value));
        idx++;
        const char *after = v + vl;
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }

    *out_tags = tags;
    *out_count = idx;
    return 0;
}

/* Helper to count occurrences of a tag using s3__xml_each */
typedef struct count_ctx { int count; } count_ctx;

static int count_cb(const char *el, size_t el_len, void *ud)
{
    S3_UNUSED(el); S3_UNUSED(el_len);
    count_ctx *ctx = (count_ctx *)ud;
    ctx->count++;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Versioning
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_versioning(s3_client *c, const char *bucket,
                                   s3_versioning_status *status, bool *mfa_delete)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "versioning");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    if (status) {
        char buf[32];
        xml_extract(xml, len, "Status", buf, sizeof(buf));
        if (strcmp(buf, "Enabled") == 0)
            *status = S3_VERSIONING_ENABLED;
        else if (strcmp(buf, "Suspended") == 0)
            *status = S3_VERSIONING_SUSPENDED;
        else
            *status = S3_VERSIONING_UNSET;
    }

    if (mfa_delete) {
        char buf[32];
        xml_extract(xml, len, "MfaDelete", buf, sizeof(buf));
        *mfa_delete = (strcmp(buf, "Enabled") == 0);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_versioning(s3_client *c, const char *bucket,
                                   s3_versioning_status status,
                                   bool mfa_delete, const char *mfa)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);

    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    if (status == S3_VERSIONING_ENABLED)
        s3__xml_buf_element(&body, "Status", "Enabled");
    else if (status == S3_VERSIONING_SUSPENDED)
        s3__xml_buf_element(&body, "Status", "Suspended");
    s3__xml_buf_element(&body, "MfaDelete", mfa_delete ? "Enabled" : "Disabled");
    s3__xml_buf_close(&body, "VersioningConfiguration");

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");
    if (mfa) {
        char hdr[512];
        snprintf(hdr, sizeof(hdr), "x-amz-mfa: %s", mfa);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = "versioning",
        .extra_headers = hdrs,
        .upload_data = body.data,
        .upload_len = body.len,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct lifecycle_parse_ctx {
    s3_lifecycle_rule *rules;
    int count;
    int cap;
} lifecycle_parse_ctx;

static int parse_lifecycle_rule(const char *el, size_t el_len, void *ud)
{
    lifecycle_parse_ctx *ctx = (lifecycle_parse_ctx *)ud;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_lifecycle_rule *p = (s3_lifecycle_rule *)S3_REALLOC(
            ctx->rules, (size_t)new_cap * sizeof(s3_lifecycle_rule));
        if (!p) return -1;
        ctx->rules = p;
        ctx->cap = new_cap;
    }

    s3_lifecycle_rule *r = &ctx->rules[ctx->count];
    memset(r, 0, sizeof(*r));

    xml_extract(el, el_len, "ID", r->id, sizeof(r->id));
    xml_extract(el, el_len, "Prefix", r->prefix, sizeof(r->prefix));

    /* Status */
    char status_buf[32];
    xml_extract(el, el_len, "Status", status_buf, sizeof(status_buf));
    r->enabled = (strcmp(status_buf, "Enabled") == 0);

    /* Filter */
    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        xml_extract(fv, fl, "Prefix", r->filter.prefix, sizeof(r->filter.prefix));

        /* Check for And */
        const char *and_v;
        size_t and_l;
        if (s3__xml_find(fv, fl, "And", &and_v, &and_l)) {
            r->filter.has_and = true;
            xml_extract(and_v, and_l, "Prefix", r->filter.prefix, sizeof(r->filter.prefix));
            r->filter.object_size_greater_than = xml_extract_int64(and_v, and_l, "ObjectSizeGreaterThan");
            r->filter.object_size_less_than = xml_extract_int64(and_v, and_l, "ObjectSizeLessThan");
            parse_tags(and_v, and_l, &r->filter.tags, &r->filter.tag_count);
        } else {
            r->filter.object_size_greater_than = xml_extract_int64(fv, fl, "ObjectSizeGreaterThan");
            r->filter.object_size_less_than = xml_extract_int64(fv, fl, "ObjectSizeLessThan");
            /* Single tag */
            const char *tv;
            size_t tl;
            if (s3__xml_find(fv, fl, "Tag", &tv, &tl)) {
                r->filter.tags = (s3_tag *)S3_CALLOC(1, sizeof(s3_tag));
                if (r->filter.tags) {
                    xml_extract(tv, tl, "Key", r->filter.tags[0].key, sizeof(r->filter.tags[0].key));
                    xml_extract(tv, tl, "Value", r->filter.tags[0].value, sizeof(r->filter.tags[0].value));
                    r->filter.tag_count = 1;
                }
            }
        }
    }

    /* Expiration */
    const char *ev;
    size_t el2;
    if (s3__xml_find(el, el_len, "Expiration", &ev, &el2)) {
        r->expiration.days = xml_extract_int(ev, el2, "Days");
        xml_extract(ev, el2, "Date", r->expiration.date, sizeof(r->expiration.date));
        r->expiration.expired_object_delete_marker = xml_extract_bool(ev, el2, "ExpiredObjectDeleteMarker");
    }

    /* Transitions */
    count_ctx tc = {0};
    s3__xml_each(el, el_len, "Transition", count_cb, &tc);
    if (tc.count > 0) {
        r->transitions = (s3_lifecycle_transition *)S3_CALLOC((size_t)tc.count, sizeof(s3_lifecycle_transition));
        if (r->transitions) {
            r->transition_count = 0;
            /* Re-iterate to fill */
            const char *tp = el;
            size_t trem = el_len;
            while (trem > 0 && r->transition_count < tc.count) {
                const char *tv;
                size_t tl;
                if (!s3__xml_find(tp, trem, "Transition", &tv, &tl)) break;
                s3_lifecycle_transition *t = &r->transitions[r->transition_count++];
                t->days = xml_extract_int(tv, tl, "Days");
                xml_extract(tv, tl, "Date", t->date, sizeof(t->date));
                xml_extract(tv, tl, "StorageClass", t->storage_class, sizeof(t->storage_class));
                const char *after = tv + tl;
                const char *gt = memchr(after, '>', (size_t)((el + el_len) - after));
                if (!gt) break;
                trem = (size_t)((el + el_len) - (gt + 1));
                tp = gt + 1;
            }
        }
    }

    /* NoncurrentVersionTransition */
    count_ctx ntc = {0};
    s3__xml_each(el, el_len, "NoncurrentVersionTransition", count_cb, &ntc);
    if (ntc.count > 0) {
        r->noncurrent_transitions = (s3_lifecycle_noncurrent_transition *)S3_CALLOC(
            (size_t)ntc.count, sizeof(s3_lifecycle_noncurrent_transition));
        if (r->noncurrent_transitions) {
            r->noncurrent_transition_count = 0;
            const char *tp = el;
            size_t trem = el_len;
            while (trem > 0 && r->noncurrent_transition_count < ntc.count) {
                const char *tv;
                size_t tl;
                if (!s3__xml_find(tp, trem, "NoncurrentVersionTransition", &tv, &tl)) break;
                s3_lifecycle_noncurrent_transition *t = &r->noncurrent_transitions[r->noncurrent_transition_count++];
                t->noncurrent_days = xml_extract_int(tv, tl, "NoncurrentDays");
                t->newer_noncurrent_versions = xml_extract_int(tv, tl, "NewerNoncurrentVersions");
                xml_extract(tv, tl, "StorageClass", t->storage_class, sizeof(t->storage_class));
                const char *after = tv + tl;
                const char *gt = memchr(after, '>', (size_t)((el + el_len) - after));
                if (!gt) break;
                trem = (size_t)((el + el_len) - (gt + 1));
                tp = gt + 1;
            }
        }
    }

    /* NoncurrentVersionExpiration */
    const char *nev;
    size_t nel;
    if (s3__xml_find(el, el_len, "NoncurrentVersionExpiration", &nev, &nel)) {
        r->noncurrent_expiration.noncurrent_days = xml_extract_int(nev, nel, "NoncurrentDays");
        r->noncurrent_expiration.newer_noncurrent_versions = xml_extract_int(nev, nel, "NewerNoncurrentVersions");
    }

    /* AbortIncompleteMultipartUpload */
    const char *av;
    size_t al;
    if (s3__xml_find(el, el_len, "AbortIncompleteMultipartUpload", &av, &al)) {
        r->abort_incomplete_mpu.days_after_initiation = xml_extract_int(av, al, "DaysAfterInitiation");
    }

    ctx->count++;
    return 0;
}

s3_status s3_get_bucket_lifecycle(s3_client *c, const char *bucket,
                                  s3_lifecycle_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "lifecycle");
    if (st != S3_STATUS_OK) return st;

    lifecycle_parse_ctx ctx = {nullptr, 0, 0};
    s3__xml_each(c->response.data, c->response.len, "Rule", parse_lifecycle_rule, &ctx);

    config->rules = ctx.rules;
    config->rule_count = ctx.count;
    return S3_STATUS_OK;
}

static int build_lifecycle_rule_xml(s3_buf *b, const s3_lifecycle_rule *r)
{
    s3__xml_buf_open(b, "Rule");

    if (r->id[0]) s3__xml_buf_element(b, "ID", r->id);

    /* Filter */
    s3__xml_buf_open(b, "Filter");
    if (r->filter.has_and || r->filter.tag_count > 1) {
        s3__xml_buf_open(b, "And");
        if (r->filter.prefix[0]) s3__xml_buf_element(b, "Prefix", r->filter.prefix);
        for (int i = 0; i < r->filter.tag_count; i++)
            build_tag_xml(b, &r->filter.tags[i]);
        if (r->filter.object_size_greater_than > 0)
            s3__xml_buf_element_int(b, "ObjectSizeGreaterThan", r->filter.object_size_greater_than);
        if (r->filter.object_size_less_than > 0)
            s3__xml_buf_element_int(b, "ObjectSizeLessThan", r->filter.object_size_less_than);
        s3__xml_buf_close(b, "And");
    } else if (r->filter.tag_count == 1) {
        build_tag_xml(b, &r->filter.tags[0]);
    } else if (r->filter.prefix[0]) {
        s3__xml_buf_element(b, "Prefix", r->filter.prefix);
    } else if (r->filter.object_size_greater_than > 0) {
        s3__xml_buf_element_int(b, "ObjectSizeGreaterThan", r->filter.object_size_greater_than);
    } else if (r->filter.object_size_less_than > 0) {
        s3__xml_buf_element_int(b, "ObjectSizeLessThan", r->filter.object_size_less_than);
    }
    s3__xml_buf_close(b, "Filter");

    s3__xml_buf_element(b, "Status", r->enabled ? "Enabled" : "Disabled");

    /* Expiration */
    if (r->expiration.days > 0 || r->expiration.date[0] || r->expiration.expired_object_delete_marker) {
        s3__xml_buf_open(b, "Expiration");
        if (r->expiration.days > 0) s3__xml_buf_element_int(b, "Days", r->expiration.days);
        if (r->expiration.date[0]) s3__xml_buf_element(b, "Date", r->expiration.date);
        if (r->expiration.expired_object_delete_marker)
            s3__xml_buf_element_bool(b, "ExpiredObjectDeleteMarker", true);
        s3__xml_buf_close(b, "Expiration");
    }

    /* Transitions */
    for (int i = 0; i < r->transition_count; i++) {
        const s3_lifecycle_transition *t = &r->transitions[i];
        s3__xml_buf_open(b, "Transition");
        if (t->days > 0) s3__xml_buf_element_int(b, "Days", t->days);
        if (t->date[0]) s3__xml_buf_element(b, "Date", t->date);
        if (t->storage_class[0]) s3__xml_buf_element(b, "StorageClass", t->storage_class);
        s3__xml_buf_close(b, "Transition");
    }

    /* NoncurrentVersionTransitions */
    for (int i = 0; i < r->noncurrent_transition_count; i++) {
        const s3_lifecycle_noncurrent_transition *t = &r->noncurrent_transitions[i];
        s3__xml_buf_open(b, "NoncurrentVersionTransition");
        if (t->noncurrent_days > 0) s3__xml_buf_element_int(b, "NoncurrentDays", t->noncurrent_days);
        if (t->newer_noncurrent_versions > 0) s3__xml_buf_element_int(b, "NewerNoncurrentVersions", t->newer_noncurrent_versions);
        if (t->storage_class[0]) s3__xml_buf_element(b, "StorageClass", t->storage_class);
        s3__xml_buf_close(b, "NoncurrentVersionTransition");
    }

    /* NoncurrentVersionExpiration */
    if (r->noncurrent_expiration.noncurrent_days > 0) {
        s3__xml_buf_open(b, "NoncurrentVersionExpiration");
        s3__xml_buf_element_int(b, "NoncurrentDays", r->noncurrent_expiration.noncurrent_days);
        if (r->noncurrent_expiration.newer_noncurrent_versions > 0)
            s3__xml_buf_element_int(b, "NewerNoncurrentVersions", r->noncurrent_expiration.newer_noncurrent_versions);
        s3__xml_buf_close(b, "NoncurrentVersionExpiration");
    }

    /* AbortIncompleteMultipartUpload */
    if (r->abort_incomplete_mpu.days_after_initiation > 0) {
        s3__xml_buf_open(b, "AbortIncompleteMultipartUpload");
        s3__xml_buf_element_int(b, "DaysAfterInitiation", r->abort_incomplete_mpu.days_after_initiation);
        s3__xml_buf_close(b, "AbortIncompleteMultipartUpload");
    }

    s3__xml_buf_close(b, "Rule");
    return 0;
}

s3_status s3_put_bucket_lifecycle(s3_client *c, const char *bucket,
                                  const s3_lifecycle_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    for (int i = 0; i < config->rule_count; i++)
        build_lifecycle_rule_xml(&body, &config->rules[i]);
    s3__xml_buf_close(&body, "LifecycleConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "lifecycle", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_lifecycle(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "lifecycle");
}

void s3_lifecycle_configuration_free(s3_lifecycle_configuration *r)
{
    if (!r) return;
    for (int i = 0; i < r->rule_count; i++) {
        S3_FREE(r->rules[i].transitions);
        S3_FREE(r->rules[i].noncurrent_transitions);
        S3_FREE(r->rules[i].filter.tags);
    }
    S3_FREE(r->rules);
    r->rules = nullptr;
    r->rule_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Policy
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_policy(s3_client *c, const char *bucket, char **policy_json_out)
{
    if (!c || !bucket || !policy_json_out) return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "policy");
    if (st != S3_STATUS_OK) return st;

    *policy_json_out = s3__strndup(c->response.data, c->response.len);
    if (!*policy_json_out) return S3_STATUS_OUT_OF_MEMORY;
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_policy(s3_client *c, const char *bucket, const char *policy_json)
{
    if (!c || !bucket || !policy_json) return S3_STATUS_INVALID_ARGUMENT;

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = "policy",
        .extra_headers = hdrs,
        .upload_data = policy_json,
        .upload_len = strlen(policy_json),
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    return st;
}

s3_status s3_delete_bucket_policy(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "policy");
}

s3_status s3_get_bucket_policy_status(s3_client *c, const char *bucket, bool *is_public)
{
    if (!c || !bucket || !is_public) return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "policyStatus");
    if (st != S3_STATUS_OK) return st;

    *is_public = xml_extract_bool(c->response.data, c->response.len, "IsPublic");
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CORS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Parse a list of string elements (e.g., <AllowedOrigin>) into a dynamically allocated array */
static int parse_string_list(const char *xml, size_t len, const char *tag,
                             char ***out, int *out_count)
{
    count_ctx cc = {0};
    s3__xml_each(xml, len, tag, count_cb, &cc);
    if (cc.count == 0) {
        *out = nullptr;
        *out_count = 0;
        return 0;
    }

    char **list = (char **)S3_CALLOC((size_t)cc.count, sizeof(char *));
    if (!list) return -1;

    int idx = 0;
    const char *p = xml;
    size_t rem = len;
    while (rem > 0 && idx < cc.count) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, tag, &v, &vl)) break;
        char buf[1024];
        s3__xml_decode_entities(v, vl, buf, sizeof(buf));
        list[idx] = s3__strdup(buf);
        idx++;
        const char *after = v + vl;
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }

    *out = list;
    *out_count = idx;
    return 0;
}

static void free_string_list(char **list, int count)
{
    if (!list) return;
    for (int i = 0; i < count; i++)
        S3_FREE(list[i]);
    S3_FREE(list);
}

typedef struct cors_parse_ctx {
    s3_cors_rule *rules;
    int count;
    int cap;
} cors_parse_ctx;

static int parse_cors_rule(const char *el, size_t el_len, void *ud)
{
    cors_parse_ctx *ctx = (cors_parse_ctx *)ud;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_cors_rule *p = (s3_cors_rule *)S3_REALLOC(
            ctx->rules, (size_t)new_cap * sizeof(s3_cors_rule));
        if (!p) return -1;
        ctx->rules = p;
        ctx->cap = new_cap;
    }

    s3_cors_rule *r = &ctx->rules[ctx->count];
    memset(r, 0, sizeof(*r));

    xml_extract(el, el_len, "ID", r->id, sizeof(r->id));
    r->max_age_seconds = xml_extract_int(el, el_len, "MaxAgeSeconds");

    parse_string_list(el, el_len, "AllowedOrigin", &r->allowed_origins, &r->allowed_origin_count);
    parse_string_list(el, el_len, "AllowedMethod", &r->allowed_methods, &r->allowed_method_count);
    parse_string_list(el, el_len, "AllowedHeader", &r->allowed_headers, &r->allowed_header_count);
    parse_string_list(el, el_len, "ExposeHeader", &r->expose_headers, &r->expose_header_count);

    ctx->count++;
    return 0;
}

s3_status s3_get_bucket_cors(s3_client *c, const char *bucket,
                             s3_cors_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "cors");
    if (st != S3_STATUS_OK) return st;

    cors_parse_ctx ctx = {nullptr, 0, 0};
    s3__xml_each(c->response.data, c->response.len, "CORSRule", parse_cors_rule, &ctx);

    config->rules = ctx.rules;
    config->rule_count = ctx.count;
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_cors(s3_client *c, const char *bucket,
                             const s3_cors_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    for (int i = 0; i < config->rule_count; i++) {
        const s3_cors_rule *r = &config->rules[i];
        s3__xml_buf_open(&body, "CORSRule");

        if (r->id[0]) s3__xml_buf_element(&body, "ID", r->id);

        for (int j = 0; j < r->allowed_origin_count; j++)
            s3__xml_buf_element(&body, "AllowedOrigin", r->allowed_origins[j]);
        for (int j = 0; j < r->allowed_method_count; j++)
            s3__xml_buf_element(&body, "AllowedMethod", r->allowed_methods[j]);
        for (int j = 0; j < r->allowed_header_count; j++)
            s3__xml_buf_element(&body, "AllowedHeader", r->allowed_headers[j]);
        for (int j = 0; j < r->expose_header_count; j++)
            s3__xml_buf_element(&body, "ExposeHeader", r->expose_headers[j]);

        if (r->max_age_seconds > 0)
            s3__xml_buf_element_int(&body, "MaxAgeSeconds", r->max_age_seconds);

        s3__xml_buf_close(&body, "CORSRule");
    }

    s3__xml_buf_close(&body, "CORSConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "cors", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_cors(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "cors");
}

void s3_cors_configuration_free(s3_cors_configuration *r)
{
    if (!r) return;
    for (int i = 0; i < r->rule_count; i++) {
        free_string_list(r->rules[i].allowed_origins, r->rules[i].allowed_origin_count);
        free_string_list(r->rules[i].allowed_methods, r->rules[i].allowed_method_count);
        free_string_list(r->rules[i].allowed_headers, r->rules[i].allowed_header_count);
        free_string_list(r->rules[i].expose_headers, r->rules[i].expose_header_count);
    }
    S3_FREE(r->rules);
    r->rules = nullptr;
    r->rule_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Encryption
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_encryption(s3_client *c, const char *bucket,
                                   s3_bucket_encryption *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "encryption");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    char algo[64];
    xml_extract_in(xml, len, "ApplyServerSideEncryptionByDefault",
                   "SSEAlgorithm", algo, sizeof(algo));

    if (strcmp(algo, "aws:kms") == 0 || strcmp(algo, "aws:kms:dsse") == 0)
        config->default_sse = S3_SSE_KMS;
    else if (strcmp(algo, "AES256") == 0)
        config->default_sse = S3_SSE_S3;
    else
        config->default_sse = S3_SSE_NONE;

    xml_extract_in(xml, len, "ApplyServerSideEncryptionByDefault",
                   "KMSMasterKeyID", config->kms_key_id, sizeof(config->kms_key_id));
    config->bucket_key_enabled = xml_extract_bool(xml, len, "BucketKeyEnabled");

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_encryption(s3_client *c, const char *bucket,
                                   const s3_bucket_encryption *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_open(&body, "Rule");
    s3__xml_buf_open(&body, "ApplyServerSideEncryptionByDefault");

    const char *algo = "AES256";
    if (config->default_sse == S3_SSE_KMS) algo = "aws:kms";
    s3__xml_buf_element(&body, "SSEAlgorithm", algo);

    if (config->kms_key_id[0])
        s3__xml_buf_element(&body, "KMSMasterKeyID", config->kms_key_id);

    s3__xml_buf_close(&body, "ApplyServerSideEncryptionByDefault");
    s3__xml_buf_element_bool(&body, "BucketKeyEnabled", config->bucket_key_enabled);
    s3__xml_buf_close(&body, "Rule");
    s3__xml_buf_close(&body, "ServerSideEncryptionConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "encryption", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_encryption(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "encryption");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Logging
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_logging(s3_client *c, const char *bucket,
                                s3_bucket_logging *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "logging");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    const char *le_v;
    size_t le_l;
    if (s3__xml_find(xml, len, "LoggingEnabled", &le_v, &le_l)) {
        config->enabled = true;
        xml_extract(le_v, le_l, "TargetBucket", config->target_bucket, sizeof(config->target_bucket));
        xml_extract(le_v, le_l, "TargetPrefix", config->target_prefix, sizeof(config->target_prefix));
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_logging(s3_client *c, const char *bucket,
                                const s3_bucket_logging *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if (config->enabled) {
        s3__xml_buf_open(&body, "LoggingEnabled");
        s3__xml_buf_element(&body, "TargetBucket", config->target_bucket);
        s3__xml_buf_element(&body, "TargetPrefix", config->target_prefix);
        s3__xml_buf_close(&body, "LoggingEnabled");
    }

    s3__xml_buf_close(&body, "BucketLoggingStatus");

    s3_status st = bucket_put_xml(c, bucket, "logging", &body);
    s3_buf_free(&body);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Tagging
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_tagging(s3_client *c, const char *bucket, s3_tag_set *tags)
{
    if (!c || !bucket || !tags) return S3_STATUS_INVALID_ARGUMENT;
    tags->tags = nullptr;
    tags->count = 0;

    s3_status st = bucket_get(c, bucket, "tagging");
    if (st != S3_STATUS_OK) return st;

    /* Tags are inside <TagSet><Tag>...</Tag></TagSet> */
    const char *ts_v;
    size_t ts_l;
    if (s3__xml_find(c->response.data, c->response.len, "TagSet", &ts_v, &ts_l)) {
        parse_tags(ts_v, ts_l, &tags->tags, &tags->count);
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_tagging(s3_client *c, const char *bucket,
                                const s3_tag *tags, int tag_count)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_open(&body, "TagSet");
    for (int i = 0; i < tag_count; i++)
        build_tag_xml(&body, &tags[i]);
    s3__xml_buf_close(&body, "TagSet");
    s3__xml_buf_close(&body, "Tagging");

    s3_status st = bucket_put_xml(c, bucket, "tagging", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_tagging(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "tagging");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Website
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_website(s3_client *c, const char *bucket,
                                s3_website_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "website");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    xml_extract_in(xml, len, "IndexDocument", "Suffix",
                   config->index_document, sizeof(config->index_document));
    xml_extract_in(xml, len, "ErrorDocument", "Key",
                   config->error_document, sizeof(config->error_document));

    /* RedirectAllRequestsTo */
    const char *rv;
    size_t rl;
    if (s3__xml_find(xml, len, "RedirectAllRequestsTo", &rv, &rl)) {
        xml_extract(rv, rl, "HostName", config->redirect_hostname, sizeof(config->redirect_hostname));
        xml_extract(rv, rl, "Protocol", config->redirect_protocol, sizeof(config->redirect_protocol));
    }

    /* RoutingRules */
    const char *rr_v;
    size_t rr_l;
    if (s3__xml_find(xml, len, "RoutingRules", &rr_v, &rr_l)) {
        count_ctx cc = {0};
        s3__xml_each(rr_v, rr_l, "RoutingRule", count_cb, &cc);
        if (cc.count > 0) {
            config->routing_rules = (s3_website_redirect_rule *)S3_CALLOC(
                (size_t)cc.count, sizeof(s3_website_redirect_rule));
            if (config->routing_rules) {
                config->routing_rule_count = 0;
                const char *p = rr_v;
                size_t rem = rr_l;
                while (rem > 0 && config->routing_rule_count < cc.count) {
                    const char *v;
                    size_t vl;
                    if (!s3__xml_find(p, rem, "RoutingRule", &v, &vl)) break;

                    s3_website_redirect_rule *rule = &config->routing_rules[config->routing_rule_count++];
                    memset(rule, 0, sizeof(*rule));

                    /* Condition */
                    const char *cv;
                    size_t cl;
                    if (s3__xml_find(v, vl, "Condition", &cv, &cl)) {
                        xml_extract(cv, cl, "KeyPrefixEquals",
                                    rule->condition_key_prefix, sizeof(rule->condition_key_prefix));
                        rule->condition_http_error_code = xml_extract_int(cv, cl, "HttpErrorCodeReturnedEquals");
                    }

                    /* Redirect */
                    const char *rdv;
                    size_t rdl;
                    if (s3__xml_find(v, vl, "Redirect", &rdv, &rdl)) {
                        xml_extract(rdv, rdl, "HostName", rule->redirect_hostname, sizeof(rule->redirect_hostname));
                        xml_extract(rdv, rdl, "Protocol", rule->redirect_protocol, sizeof(rule->redirect_protocol));
                        xml_extract(rdv, rdl, "ReplaceKeyPrefixWith",
                                    rule->redirect_replace_key_prefix, sizeof(rule->redirect_replace_key_prefix));
                        xml_extract(rdv, rdl, "ReplaceKeyWith",
                                    rule->redirect_replace_key, sizeof(rule->redirect_replace_key));
                        rule->redirect_http_code = xml_extract_int(rdv, rdl, "HttpRedirectCode");
                    }

                    const char *after = v + vl;
                    const char *gt = memchr(after, '>', (size_t)((rr_v + rr_l) - after));
                    if (!gt) break;
                    rem = (size_t)((rr_v + rr_l) - (gt + 1));
                    p = gt + 1;
                }
            }
        }
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_website(s3_client *c, const char *bucket,
                                const s3_website_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<WebsiteConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if (config->redirect_hostname[0]) {
        s3__xml_buf_open(&body, "RedirectAllRequestsTo");
        s3__xml_buf_element(&body, "HostName", config->redirect_hostname);
        if (config->redirect_protocol[0])
            s3__xml_buf_element(&body, "Protocol", config->redirect_protocol);
        s3__xml_buf_close(&body, "RedirectAllRequestsTo");
    } else {
        if (config->index_document[0]) {
            s3__xml_buf_open(&body, "IndexDocument");
            s3__xml_buf_element(&body, "Suffix", config->index_document);
            s3__xml_buf_close(&body, "IndexDocument");
        }
        if (config->error_document[0]) {
            s3__xml_buf_open(&body, "ErrorDocument");
            s3__xml_buf_element(&body, "Key", config->error_document);
            s3__xml_buf_close(&body, "ErrorDocument");
        }

        if (config->routing_rule_count > 0) {
            s3__xml_buf_open(&body, "RoutingRules");
            for (int i = 0; i < config->routing_rule_count; i++) {
                const s3_website_redirect_rule *r = &config->routing_rules[i];
                s3__xml_buf_open(&body, "RoutingRule");

                if (r->condition_key_prefix[0] || r->condition_http_error_code > 0) {
                    s3__xml_buf_open(&body, "Condition");
                    if (r->condition_key_prefix[0])
                        s3__xml_buf_element(&body, "KeyPrefixEquals", r->condition_key_prefix);
                    if (r->condition_http_error_code > 0)
                        s3__xml_buf_element_int(&body, "HttpErrorCodeReturnedEquals", r->condition_http_error_code);
                    s3__xml_buf_close(&body, "Condition");
                }

                s3__xml_buf_open(&body, "Redirect");
                if (r->redirect_hostname[0])
                    s3__xml_buf_element(&body, "HostName", r->redirect_hostname);
                if (r->redirect_protocol[0])
                    s3__xml_buf_element(&body, "Protocol", r->redirect_protocol);
                if (r->redirect_replace_key_prefix[0])
                    s3__xml_buf_element(&body, "ReplaceKeyPrefixWith", r->redirect_replace_key_prefix);
                if (r->redirect_replace_key[0])
                    s3__xml_buf_element(&body, "ReplaceKeyWith", r->redirect_replace_key);
                if (r->redirect_http_code > 0)
                    s3__xml_buf_element_int(&body, "HttpRedirectCode", r->redirect_http_code);
                s3__xml_buf_close(&body, "Redirect");

                s3__xml_buf_close(&body, "RoutingRule");
            }
            s3__xml_buf_close(&body, "RoutingRules");
        }
    }

    s3__xml_buf_close(&body, "WebsiteConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "website", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_website(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "website");
}

void s3_website_configuration_free(s3_website_configuration *r)
{
    if (!r) return;
    S3_FREE(r->routing_rules);
    r->routing_rules = nullptr;
    r->routing_rule_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Notification
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct notif_parse_ctx {
    s3_notification_config *configs;
    int count;
    int cap;
} notif_parse_ctx;

static int parse_notification_config(const char *el, size_t el_len, void *ud)
{
    notif_parse_ctx *ctx = (notif_parse_ctx *)ud;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_notification_config *p = (s3_notification_config *)S3_REALLOC(
            ctx->configs, (size_t)new_cap * sizeof(s3_notification_config));
        if (!p) return -1;
        ctx->configs = p;
        ctx->cap = new_cap;
    }

    s3_notification_config *nc = &ctx->configs[ctx->count];
    memset(nc, 0, sizeof(*nc));

    xml_extract(el, el_len, "Id", nc->id, sizeof(nc->id));

    /* Try different ARN element names */
    char arn[256] = "";
    xml_extract(el, el_len, "Topic", arn, sizeof(arn));
    if (!arn[0]) xml_extract(el, el_len, "Queue", arn, sizeof(arn));
    if (!arn[0]) xml_extract(el, el_len, "CloudFunction", arn, sizeof(arn));
    if (!arn[0]) xml_extract(el, el_len, "LambdaFunctionArn", arn, sizeof(arn));
    if (!arn[0]) xml_extract(el, el_len, "TopicArn", arn, sizeof(arn));
    if (!arn[0]) xml_extract(el, el_len, "QueueArn", arn, sizeof(arn));
    memcpy(nc->arn, arn, sizeof(nc->arn));

    /* Events */
    parse_string_list(el, el_len, "Event", &nc->events, &nc->event_count);

    /* Filter rules */
    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        const char *skf_v;
        size_t skf_l;
        if (s3__xml_find(fv, fl, "S3Key", &skf_v, &skf_l)) {
            count_ctx cc = {0};
            s3__xml_each(skf_v, skf_l, "FilterRule", count_cb, &cc);
            if (cc.count > 0) {
                nc->filter_rules = (s3_filter_rule *)S3_CALLOC((size_t)cc.count, sizeof(s3_filter_rule));
                if (nc->filter_rules) {
                    nc->filter_rule_count = 0;
                    const char *p = skf_v;
                    size_t rem = skf_l;
                    while (rem > 0 && nc->filter_rule_count < cc.count) {
                        const char *rv;
                        size_t rl;
                        if (!s3__xml_find(p, rem, "FilterRule", &rv, &rl)) break;
                        s3_filter_rule *fr = &nc->filter_rules[nc->filter_rule_count++];
                        xml_extract(rv, rl, "Name", fr->name, sizeof(fr->name));
                        xml_extract(rv, rl, "Value", fr->value, sizeof(fr->value));
                        const char *after = rv + rl;
                        const char *gt = memchr(after, '>', (size_t)((skf_v + skf_l) - after));
                        if (!gt) break;
                        rem = (size_t)((skf_v + skf_l) - (gt + 1));
                        p = gt + 1;
                    }
                }
            }
        }
    }

    ctx->count++;
    return 0;
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

s3_status s3_get_bucket_notification(s3_client *c, const char *bucket,
                                     s3_notification_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "notification");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    /* Topic configurations */
    notif_parse_ctx topic_ctx = {nullptr, 0, 0};
    s3__xml_each(xml, len, "TopicConfiguration", parse_notification_config, &topic_ctx);
    config->topic_configs = topic_ctx.configs;
    config->topic_count = topic_ctx.count;

    /* Queue configurations */
    notif_parse_ctx queue_ctx = {nullptr, 0, 0};
    s3__xml_each(xml, len, "QueueConfiguration", parse_notification_config, &queue_ctx);
    config->queue_configs = queue_ctx.configs;
    config->queue_count = queue_ctx.count;

    /* Lambda configurations */
    notif_parse_ctx lambda_ctx = {nullptr, 0, 0};
    s3__xml_each(xml, len, "CloudFunctionConfiguration", parse_notification_config, &lambda_ctx);
    config->lambda_configs = lambda_ctx.configs;
    config->lambda_count = lambda_ctx.count;

    return S3_STATUS_OK;
}

static void build_notification_configs(s3_buf *body, const char *wrapper_tag,
                                       const char *arn_tag,
                                       const s3_notification_config *configs, int count)
{
    for (int i = 0; i < count; i++) {
        const s3_notification_config *nc = &configs[i];
        s3__xml_buf_open(body, wrapper_tag);

        if (nc->id[0]) s3__xml_buf_element(body, "Id", nc->id);
        s3__xml_buf_element(body, arn_tag, nc->arn);

        for (int j = 0; j < nc->event_count; j++)
            s3__xml_buf_element(body, "Event", nc->events[j]);

        if (nc->filter_rule_count > 0) {
            s3__xml_buf_open(body, "Filter");
            s3__xml_buf_open(body, "S3Key");
            for (int j = 0; j < nc->filter_rule_count; j++) {
                s3__xml_buf_open(body, "FilterRule");
                s3__xml_buf_element(body, "Name", nc->filter_rules[j].name);
                s3__xml_buf_element(body, "Value", nc->filter_rules[j].value);
                s3__xml_buf_close(body, "FilterRule");
            }
            s3__xml_buf_close(body, "S3Key");
            s3__xml_buf_close(body, "Filter");
        }

        s3__xml_buf_close(body, wrapper_tag);
    }
}

s3_status s3_put_bucket_notification(s3_client *c, const char *bucket,
                                     const s3_notification_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    build_notification_configs(&body, "TopicConfiguration", "Topic",
                               config->topic_configs, config->topic_count);
    build_notification_configs(&body, "QueueConfiguration", "Queue",
                               config->queue_configs, config->queue_count);
    build_notification_configs(&body, "CloudFunctionConfiguration", "CloudFunction",
                               config->lambda_configs, config->lambda_count);

    s3__xml_buf_close(&body, "NotificationConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "notification", &body);
    s3_buf_free(&body);
    return st;
}

void s3_notification_configuration_free(s3_notification_configuration *r)
{
    if (!r) return;
    free_notification_configs(r->topic_configs, r->topic_count);
    free_notification_configs(r->queue_configs, r->queue_count);
    free_notification_configs(r->lambda_configs, r->lambda_count);
    memset(r, 0, sizeof(*r));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Replication
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct repl_parse_ctx {
    s3_replication_rule *rules;
    int count;
    int cap;
} repl_parse_ctx;

static int parse_replication_rule(const char *el, size_t el_len, void *ud)
{
    repl_parse_ctx *ctx = (repl_parse_ctx *)ud;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_replication_rule *p = (s3_replication_rule *)S3_REALLOC(
            ctx->rules, (size_t)new_cap * sizeof(s3_replication_rule));
        if (!p) return -1;
        ctx->rules = p;
        ctx->cap = new_cap;
    }

    s3_replication_rule *r = &ctx->rules[ctx->count];
    memset(r, 0, sizeof(*r));

    xml_extract(el, el_len, "ID", r->id, sizeof(r->id));
    r->priority = xml_extract_int(el, el_len, "Priority");

    /* Prefix — may be top-level or in Filter */
    xml_extract(el, el_len, "Prefix", r->prefix, sizeof(r->prefix));
    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        xml_extract(fv, fl, "Prefix", r->prefix, sizeof(r->prefix));
    }

    char status_buf[32];
    xml_extract(el, el_len, "Status", status_buf, sizeof(status_buf));
    r->enabled = (strcmp(status_buf, "Enabled") == 0);

    /* Destination */
    const char *dv;
    size_t dl;
    if (s3__xml_find(el, el_len, "Destination", &dv, &dl)) {
        xml_extract(dv, dl, "Bucket", r->destination.bucket, sizeof(r->destination.bucket));
        xml_extract(dv, dl, "Account", r->destination.account, sizeof(r->destination.account));
        xml_extract(dv, dl, "StorageClass", r->destination.storage_class, sizeof(r->destination.storage_class));

        const char *ek_v;
        size_t ek_l;
        if (s3__xml_find(dv, dl, "EncryptionConfiguration", &ek_v, &ek_l)) {
            r->destination.replicate_kms = true;
            xml_extract(ek_v, ek_l, "ReplicaKmsKeyID", r->destination.kms_key_id,
                        sizeof(r->destination.kms_key_id));
        }
    }

    /* DeleteMarkerReplication */
    const char *dmr_v;
    size_t dmr_l;
    if (s3__xml_find(el, el_len, "DeleteMarkerReplication", &dmr_v, &dmr_l)) {
        char dmr_status[32];
        xml_extract(dmr_v, dmr_l, "Status", dmr_status, sizeof(dmr_status));
        r->delete_marker_replication = (strcmp(dmr_status, "Enabled") == 0);
    }

    /* ExistingObjectReplication */
    const char *eor_v;
    size_t eor_l;
    if (s3__xml_find(el, el_len, "ExistingObjectReplication", &eor_v, &eor_l)) {
        char eor_status[32];
        xml_extract(eor_v, eor_l, "Status", eor_status, sizeof(eor_status));
        r->existing_object_replication = (strcmp(eor_status, "Enabled") == 0);
    }

    ctx->count++;
    return 0;
}

s3_status s3_get_bucket_replication(s3_client *c, const char *bucket,
                                    s3_replication_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "replication");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    xml_extract(xml, len, "Role", config->role, sizeof(config->role));

    repl_parse_ctx ctx = {nullptr, 0, 0};
    s3__xml_each(xml, len, "Rule", parse_replication_rule, &ctx);

    config->rules = ctx.rules;
    config->rule_count = ctx.count;
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_replication(s3_client *c, const char *bucket,
                                    const s3_replication_configuration *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&body, "Role", config->role);

    for (int i = 0; i < config->rule_count; i++) {
        const s3_replication_rule *r = &config->rules[i];
        s3__xml_buf_open(&body, "Rule");

        if (r->id[0]) s3__xml_buf_element(&body, "ID", r->id);
        if (r->priority > 0) s3__xml_buf_element_int(&body, "Priority", r->priority);

        /* Filter with prefix */
        if (r->prefix[0]) {
            s3__xml_buf_open(&body, "Filter");
            s3__xml_buf_element(&body, "Prefix", r->prefix);
            s3__xml_buf_close(&body, "Filter");
        } else {
            s3_buf_append_str(&body, "<Filter/>");
        }

        s3__xml_buf_element(&body, "Status", r->enabled ? "Enabled" : "Disabled");

        /* Destination */
        s3__xml_buf_open(&body, "Destination");
        s3__xml_buf_element(&body, "Bucket", r->destination.bucket);
        if (r->destination.account[0])
            s3__xml_buf_element(&body, "Account", r->destination.account);
        if (r->destination.storage_class[0])
            s3__xml_buf_element(&body, "StorageClass", r->destination.storage_class);
        if (r->destination.replicate_kms) {
            s3__xml_buf_open(&body, "EncryptionConfiguration");
            if (r->destination.kms_key_id[0])
                s3__xml_buf_element(&body, "ReplicaKmsKeyID", r->destination.kms_key_id);
            s3__xml_buf_close(&body, "EncryptionConfiguration");
        }
        s3__xml_buf_close(&body, "Destination");

        /* DeleteMarkerReplication */
        s3__xml_buf_open(&body, "DeleteMarkerReplication");
        s3__xml_buf_element(&body, "Status", r->delete_marker_replication ? "Enabled" : "Disabled");
        s3__xml_buf_close(&body, "DeleteMarkerReplication");

        if (r->existing_object_replication) {
            s3__xml_buf_open(&body, "ExistingObjectReplication");
            s3__xml_buf_element(&body, "Status", "Enabled");
            s3__xml_buf_close(&body, "ExistingObjectReplication");
        }

        s3__xml_buf_close(&body, "Rule");
    }

    s3__xml_buf_close(&body, "ReplicationConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "replication", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_replication(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "replication");
}

void s3_replication_configuration_free(s3_replication_configuration *r)
{
    if (!r) return;
    S3_FREE(r->rules);
    r->rules = nullptr;
    r->rule_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Accelerate
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_accelerate(s3_client *c, const char *bucket, bool *enabled)
{
    if (!c || !bucket || !enabled) return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "accelerate");
    if (st != S3_STATUS_OK) return st;

    char buf[32];
    xml_extract(c->response.data, c->response.len, "Status", buf, sizeof(buf));
    *enabled = (strcmp(buf, "Enabled") == 0);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_accelerate(s3_client *c, const char *bucket, bool enabled)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<AccelerateConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&body, "Status", enabled ? "Enabled" : "Suspended");
    s3__xml_buf_close(&body, "AccelerateConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "accelerate", &body);
    s3_buf_free(&body);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Request Payment
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_request_payment(s3_client *c, const char *bucket, s3_payer *payer)
{
    if (!c || !bucket || !payer) return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "requestPayment");
    if (st != S3_STATUS_OK) return st;

    char buf[32];
    xml_extract(c->response.data, c->response.len, "Payer", buf, sizeof(buf));
    *payer = (strcmp(buf, "Requester") == 0) ? S3_PAYER_REQUESTER : S3_PAYER_BUCKET_OWNER;
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_request_payment(s3_client *c, const char *bucket, s3_payer payer)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<RequestPaymentConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&body, "Payer",
                        payer == S3_PAYER_REQUESTER ? "Requester" : "BucketOwner");
    s3__xml_buf_close(&body, "RequestPaymentConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "requestPayment", &body);
    s3_buf_free(&body);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Object Lock Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_object_lock_configuration(s3_client *c, const char *bucket,
                                           s3_object_lock_config *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "object-lock");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    char ols[32];
    xml_extract(xml, len, "ObjectLockEnabled", ols, sizeof(ols));
    config->enabled = (strcmp(ols, "Enabled") == 0);

    const char *rule_v;
    size_t rule_l;
    if (s3__xml_find(xml, len, "Rule", &rule_v, &rule_l)) {
        const char *dr_v;
        size_t dr_l;
        if (s3__xml_find(rule_v, rule_l, "DefaultRetention", &dr_v, &dr_l)) {
            char mode_str[32];
            xml_extract(dr_v, dr_l, "Mode", mode_str, sizeof(mode_str));
            if (strcmp(mode_str, "GOVERNANCE") == 0)
                config->default_mode = S3_LOCK_GOVERNANCE;
            else if (strcmp(mode_str, "COMPLIANCE") == 0)
                config->default_mode = S3_LOCK_COMPLIANCE;
            config->default_days = xml_extract_int(dr_v, dr_l, "Days");
            config->default_years = xml_extract_int(dr_v, dr_l, "Years");
        }
    }

    return S3_STATUS_OK;
}

s3_status s3_put_object_lock_configuration(s3_client *c, const char *bucket,
                                           const s3_object_lock_config *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&body, "ObjectLockEnabled", config->enabled ? "Enabled" : "Disabled");

    if (config->default_mode != S3_LOCK_NONE) {
        s3__xml_buf_open(&body, "Rule");
        s3__xml_buf_open(&body, "DefaultRetention");
        s3__xml_buf_element(&body, "Mode",
                            config->default_mode == S3_LOCK_GOVERNANCE ? "GOVERNANCE" : "COMPLIANCE");
        if (config->default_days > 0)
            s3__xml_buf_element_int(&body, "Days", config->default_days);
        if (config->default_years > 0)
            s3__xml_buf_element_int(&body, "Years", config->default_years);
        s3__xml_buf_close(&body, "DefaultRetention");
        s3__xml_buf_close(&body, "Rule");
    }

    s3__xml_buf_close(&body, "ObjectLockConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "object-lock", &body);
    s3_buf_free(&body);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACL
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct acl_parse_ctx {
    s3_grant *grants;
    int count;
    int cap;
} acl_parse_ctx;

static int parse_grant(const char *el, size_t el_len, void *ud)
{
    acl_parse_ctx *ctx = (acl_parse_ctx *)ud;

    if (ctx->count >= ctx->cap) {
        int new_cap = ctx->cap ? ctx->cap * 2 : 8;
        s3_grant *p = (s3_grant *)S3_REALLOC(
            ctx->grants, (size_t)new_cap * sizeof(s3_grant));
        if (!p) return -1;
        ctx->grants = p;
        ctx->cap = new_cap;
    }

    s3_grant *g = &ctx->grants[ctx->count];
    memset(g, 0, sizeof(*g));

    xml_extract(el, el_len, "Permission", g->permission, sizeof(g->permission));

    const char *gv;
    size_t gl;
    if (s3__xml_find(el, el_len, "Grantee", &gv, &gl)) {
        xml_extract(gv, gl, "ID", g->grantee.id, sizeof(g->grantee.id));
        xml_extract(gv, gl, "DisplayName", g->grantee.display_name, sizeof(g->grantee.display_name));
        xml_extract(gv, gl, "EmailAddress", g->grantee.email, sizeof(g->grantee.email));
        xml_extract(gv, gl, "URI", g->grantee.uri, sizeof(g->grantee.uri));

        /* Determine type from content */
        if (g->grantee.id[0])
            snprintf(g->grantee.type, sizeof(g->grantee.type), "CanonicalUser");
        else if (g->grantee.uri[0])
            snprintf(g->grantee.type, sizeof(g->grantee.type), "Group");
        else if (g->grantee.email[0])
            snprintf(g->grantee.type, sizeof(g->grantee.type), "AmazonCustomerByEmail");
    }

    ctx->count++;
    return 0;
}

s3_status s3_get_bucket_acl(s3_client *c, const char *bucket, s3_acl *acl)
{
    if (!c || !bucket || !acl) return S3_STATUS_INVALID_ARGUMENT;
    memset(acl, 0, sizeof(*acl));

    s3_status st = bucket_get(c, bucket, "acl");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    xml_extract_in(xml, len, "Owner", "ID", acl->owner_id, sizeof(acl->owner_id));
    xml_extract_in(xml, len, "Owner", "DisplayName", acl->owner_display_name, sizeof(acl->owner_display_name));

    const char *acl_v;
    size_t acl_l;
    if (s3__xml_find(xml, len, "AccessControlList", &acl_v, &acl_l)) {
        acl_parse_ctx ctx = {nullptr, 0, 0};
        s3__xml_each(acl_v, acl_l, "Grant", parse_grant, &ctx);
        acl->grants = ctx.grants;
        acl->grant_count = ctx.count;
    }

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_acl(s3_client *c, const char *bucket, const s3_acl *acl)
{
    if (!c || !bucket || !acl) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_open(&body, "Owner");
    s3__xml_buf_element(&body, "ID", acl->owner_id);
    if (acl->owner_display_name[0])
        s3__xml_buf_element(&body, "DisplayName", acl->owner_display_name);
    s3__xml_buf_close(&body, "Owner");

    s3__xml_buf_open(&body, "AccessControlList");
    for (int i = 0; i < acl->grant_count; i++) {
        const s3_grant *g = &acl->grants[i];
        s3__xml_buf_open(&body, "Grant");

        /* Grantee with xsi:type attribute */
        char grantee_open[256];
        snprintf(grantee_open, sizeof(grantee_open),
                 "Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"%s\"",
                 g->grantee.type);
        s3__xml_buf_open(&body, grantee_open);

        if (strcmp(g->grantee.type, "CanonicalUser") == 0) {
            s3__xml_buf_element(&body, "ID", g->grantee.id);
            if (g->grantee.display_name[0])
                s3__xml_buf_element(&body, "DisplayName", g->grantee.display_name);
        } else if (strcmp(g->grantee.type, "Group") == 0) {
            s3__xml_buf_element(&body, "URI", g->grantee.uri);
        } else if (strcmp(g->grantee.type, "AmazonCustomerByEmail") == 0) {
            s3__xml_buf_element(&body, "EmailAddress", g->grantee.email);
        }

        s3__xml_buf_close(&body, "Grantee");
        s3__xml_buf_element(&body, "Permission", g->permission);
        s3__xml_buf_close(&body, "Grant");
    }
    s3__xml_buf_close(&body, "AccessControlList");
    s3__xml_buf_close(&body, "AccessControlPolicy");

    s3_status st = bucket_put_xml(c, bucket, "acl", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_put_bucket_acl_canned(s3_client *c, const char *bucket, s3_canned_acl acl)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    const char *acl_str = s3__canned_acl_string(acl);
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "x-amz-acl: %s", acl_str);

    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, hdr);

    s3_request_params p = {
        .method = "PUT",
        .bucket = bucket,
        .query_string = "acl",
        .extra_headers = hdrs,
        .collect_response = true,
    };
    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Intelligent-Tiering
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_intelligent_tiering_config(const char *el, size_t el_len,
                                             s3_intelligent_tiering_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    xml_extract(el, el_len, "Id", cfg->id, sizeof(cfg->id));

    char status_buf[32];
    xml_extract(el, el_len, "Status", status_buf, sizeof(status_buf));
    cfg->enabled = (strcmp(status_buf, "Enabled") == 0);

    /* Filter */
    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        xml_extract(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));
        const char *and_v;
        size_t and_l;
        if (s3__xml_find(fv, fl, "And", &and_v, &and_l)) {
            xml_extract(and_v, and_l, "Prefix", cfg->prefix, sizeof(cfg->prefix));
            parse_tags(and_v, and_l, &cfg->tags, &cfg->tag_count);
        } else {
            const char *tv;
            size_t tl;
            if (s3__xml_find(fv, fl, "Tag", &tv, &tl)) {
                cfg->tags = (s3_tag *)S3_CALLOC(1, sizeof(s3_tag));
                if (cfg->tags) {
                    xml_extract(tv, tl, "Key", cfg->tags[0].key, sizeof(cfg->tags[0].key));
                    xml_extract(tv, tl, "Value", cfg->tags[0].value, sizeof(cfg->tags[0].value));
                    cfg->tag_count = 1;
                }
            }
        }
    }

    /* Tierings */
    count_ctx cc = {0};
    s3__xml_each(el, el_len, "Tiering", count_cb, &cc);
    if (cc.count > 0) {
        cfg->tierings = (s3_tiering *)S3_CALLOC((size_t)cc.count, sizeof(s3_tiering));
        if (cfg->tierings) {
            cfg->tiering_count = 0;
            const char *p = el;
            size_t rem = el_len;
            while (rem > 0 && cfg->tiering_count < cc.count) {
                const char *tv;
                size_t tl;
                if (!s3__xml_find(p, rem, "Tiering", &tv, &tl)) break;
                s3_tiering *t = &cfg->tierings[cfg->tiering_count++];
                xml_extract(tv, tl, "AccessTier", t->access_tier, sizeof(t->access_tier));
                t->days = xml_extract_int(tv, tl, "Days");
                const char *after = tv + tl;
                const char *gt = memchr(after, '>', (size_t)((el + el_len) - after));
                if (!gt) break;
                rem = (size_t)((el + el_len) - (gt + 1));
                p = gt + 1;
            }
        }
    }
}

s3_status s3_get_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                            const char *id,
                                            s3_intelligent_tiering_config *config)
{
    if (!c || !bucket || !id || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "intelligent-tiering&id=%s", id);

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    parse_intelligent_tiering_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

static void build_intelligent_tiering_xml(s3_buf *body,
                                          const s3_intelligent_tiering_config *cfg)
{
    s3__xml_buf_open(body, "IntelligentTieringConfiguration");
    s3__xml_buf_element(body, "Id", cfg->id);
    s3__xml_buf_element(body, "Status", cfg->enabled ? "Enabled" : "Disabled");

    if (cfg->prefix[0] || cfg->tag_count > 0) {
        s3__xml_buf_open(body, "Filter");
        if (cfg->tag_count > 1 || (cfg->prefix[0] && cfg->tag_count > 0)) {
            s3__xml_buf_open(body, "And");
            if (cfg->prefix[0]) s3__xml_buf_element(body, "Prefix", cfg->prefix);
            for (int i = 0; i < cfg->tag_count; i++)
                build_tag_xml(body, &cfg->tags[i]);
            s3__xml_buf_close(body, "And");
        } else if (cfg->tag_count == 1) {
            build_tag_xml(body, &cfg->tags[0]);
        } else {
            s3__xml_buf_element(body, "Prefix", cfg->prefix);
        }
        s3__xml_buf_close(body, "Filter");
    }

    for (int i = 0; i < cfg->tiering_count; i++) {
        s3__xml_buf_open(body, "Tiering");
        s3__xml_buf_element(body, "AccessTier", cfg->tierings[i].access_tier);
        s3__xml_buf_element_int(body, "Days", cfg->tierings[i].days);
        s3__xml_buf_close(body, "Tiering");
    }

    s3__xml_buf_close(body, "IntelligentTieringConfiguration");
}

s3_status s3_put_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                            const s3_intelligent_tiering_config *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "intelligent-tiering&id=%s", config->id);

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<IntelligentTieringConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    /* Build the inner content without the outer wrapper (already opened above) */
    s3__xml_buf_element(&body, "Id", config->id);
    s3__xml_buf_element(&body, "Status", config->enabled ? "Enabled" : "Disabled");

    if (config->prefix[0] || config->tag_count > 0) {
        s3__xml_buf_open(&body, "Filter");
        if (config->tag_count > 1 || (config->prefix[0] && config->tag_count > 0)) {
            s3__xml_buf_open(&body, "And");
            if (config->prefix[0]) s3__xml_buf_element(&body, "Prefix", config->prefix);
            for (int i = 0; i < config->tag_count; i++)
                build_tag_xml(&body, &config->tags[i]);
            s3__xml_buf_close(&body, "And");
        } else if (config->tag_count == 1) {
            build_tag_xml(&body, &config->tags[0]);
        } else {
            s3__xml_buf_element(&body, "Prefix", config->prefix);
        }
        s3__xml_buf_close(&body, "Filter");
    }

    for (int i = 0; i < config->tiering_count; i++) {
        s3__xml_buf_open(&body, "Tiering");
        s3__xml_buf_element(&body, "AccessTier", config->tierings[i].access_tier);
        s3__xml_buf_element_int(&body, "Days", config->tierings[i].days);
        s3__xml_buf_close(&body, "Tiering");
    }

    s3__xml_buf_close(&body, "IntelligentTieringConfiguration");

    s3_status st = bucket_put_xml(c, bucket, qs, &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                               const char *id)
{
    if (!c || !bucket || !id) return S3_STATUS_INVALID_ARGUMENT;
    char qs[256];
    snprintf(qs, sizeof(qs), "intelligent-tiering&id=%s", id);
    return bucket_delete(c, bucket, qs);
}

s3_status s3_list_bucket_intelligent_tiering(s3_client *c, const char *bucket,
                                             s3_intelligent_tiering_config **configs,
                                             int *count)
{
    if (!c || !bucket || !configs || !count) return S3_STATUS_INVALID_ARGUMENT;
    *configs = nullptr;
    *count = 0;

    s3_status st = bucket_get(c, bucket, "intelligent-tiering");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    count_ctx cc = {0};
    s3__xml_each(xml, len, "IntelligentTieringConfiguration", count_cb, &cc);
    if (cc.count == 0) return S3_STATUS_OK;

    s3_intelligent_tiering_config *cfgs = (s3_intelligent_tiering_config *)S3_CALLOC(
        (size_t)cc.count, sizeof(s3_intelligent_tiering_config));
    if (!cfgs) return S3_STATUS_OUT_OF_MEMORY;

    int idx = 0;
    const char *p = xml;
    size_t rem = len;
    while (rem > 0 && idx < cc.count) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, "IntelligentTieringConfiguration", &v, &vl)) break;
        parse_intelligent_tiering_config(v, vl, &cfgs[idx]);
        idx++;
        const char *after = v + vl;
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }

    *configs = cfgs;
    *count = idx;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Metrics
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_metrics_config(const char *el, size_t el_len, s3_metrics_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    xml_extract(el, el_len, "Id", cfg->id, sizeof(cfg->id));

    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        xml_extract(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));
        const char *and_v;
        size_t and_l;
        if (s3__xml_find(fv, fl, "And", &and_v, &and_l)) {
            xml_extract(and_v, and_l, "Prefix", cfg->prefix, sizeof(cfg->prefix));
            parse_tags(and_v, and_l, &cfg->tags, &cfg->tag_count);
        } else {
            const char *tv;
            size_t tl;
            if (s3__xml_find(fv, fl, "Tag", &tv, &tl)) {
                cfg->tags = (s3_tag *)S3_CALLOC(1, sizeof(s3_tag));
                if (cfg->tags) {
                    xml_extract(tv, tl, "Key", cfg->tags[0].key, sizeof(cfg->tags[0].key));
                    xml_extract(tv, tl, "Value", cfg->tags[0].value, sizeof(cfg->tags[0].value));
                    cfg->tag_count = 1;
                }
            }
        }
    }
}

static void build_filter_prefix_tags(s3_buf *body, const char *prefix,
                                     const s3_tag *tags, int tag_count)
{
    if (!prefix[0] && tag_count == 0) return;
    s3__xml_buf_open(body, "Filter");
    if (tag_count > 1 || (prefix[0] && tag_count > 0)) {
        s3__xml_buf_open(body, "And");
        if (prefix[0]) s3__xml_buf_element(body, "Prefix", prefix);
        for (int i = 0; i < tag_count; i++)
            build_tag_xml(body, &tags[i]);
        s3__xml_buf_close(body, "And");
    } else if (tag_count == 1) {
        build_tag_xml(body, &tags[0]);
    } else {
        s3__xml_buf_element(body, "Prefix", prefix);
    }
    s3__xml_buf_close(body, "Filter");
}

s3_status s3_get_bucket_metrics(s3_client *c, const char *bucket, const char *id,
                                s3_metrics_config *config)
{
    if (!c || !bucket || !id || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "metrics&id=%s", id);

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    parse_metrics_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_metrics(s3_client *c, const char *bucket,
                                const s3_metrics_config *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "metrics&id=%s", config->id);

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<MetricsConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element(&body, "Id", config->id);
    build_filter_prefix_tags(&body, config->prefix, config->tags, config->tag_count);
    s3__xml_buf_close(&body, "MetricsConfiguration");

    s3_status st = bucket_put_xml(c, bucket, qs, &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_metrics(s3_client *c, const char *bucket, const char *id)
{
    if (!c || !bucket || !id) return S3_STATUS_INVALID_ARGUMENT;
    char qs[256];
    snprintf(qs, sizeof(qs), "metrics&id=%s", id);
    return bucket_delete(c, bucket, qs);
}

s3_status s3_list_bucket_metrics(s3_client *c, const char *bucket,
                                 const char *continuation_token,
                                 s3_list_metrics_result *result)
{
    if (!c || !bucket || !result) return S3_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));

    char qs[1200];
    if (continuation_token && continuation_token[0])
        snprintf(qs, sizeof(qs), "metrics&continuation-token=%s", continuation_token);
    else
        snprintf(qs, sizeof(qs), "metrics");

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    result->is_truncated = xml_extract_bool(xml, len, "IsTruncated");
    xml_extract(xml, len, "ContinuationToken", result->continuation_token,
                sizeof(result->continuation_token));

    count_ctx cc = {0};
    s3__xml_each(xml, len, "MetricsConfiguration", count_cb, &cc);
    if (cc.count == 0) return S3_STATUS_OK;

    result->configs = (s3_metrics_config *)S3_CALLOC((size_t)cc.count, sizeof(s3_metrics_config));
    if (!result->configs) return S3_STATUS_OUT_OF_MEMORY;

    int idx = 0;
    const char *p = xml;
    size_t rem = len;
    while (rem > 0 && idx < cc.count) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, "MetricsConfiguration", &v, &vl)) break;
        parse_metrics_config(v, vl, &result->configs[idx]);
        idx++;
        const char *after = v + vl;
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }
    result->count = idx;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Inventory
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_inventory_config(const char *el, size_t el_len, s3_inventory_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    xml_extract(el, el_len, "Id", cfg->id, sizeof(cfg->id));

    char enabled_buf[16];
    xml_extract(el, el_len, "IsEnabled", enabled_buf, sizeof(enabled_buf));
    cfg->enabled = (strcmp(enabled_buf, "true") == 0 || strcmp(enabled_buf, "True") == 0);

    xml_extract(el, el_len, "IncludedObjectVersions", cfg->included_versions,
                sizeof(cfg->included_versions));

    /* Schedule */
    xml_extract_in(el, el_len, "Schedule", "Frequency", cfg->schedule, sizeof(cfg->schedule));

    /* Filter */
    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        xml_extract(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));
    }

    /* Destination */
    const char *dv;
    size_t dl;
    if (s3__xml_find(el, el_len, "Destination", &dv, &dl)) {
        const char *s3bd_v;
        size_t s3bd_l;
        if (s3__xml_find(dv, dl, "S3BucketDestination", &s3bd_v, &s3bd_l)) {
            xml_extract(s3bd_v, s3bd_l, "Bucket", cfg->destination_bucket,
                        sizeof(cfg->destination_bucket));
            xml_extract(s3bd_v, s3bd_l, "Prefix", cfg->destination_prefix,
                        sizeof(cfg->destination_prefix));
            xml_extract(s3bd_v, s3bd_l, "Format", cfg->destination_format,
                        sizeof(cfg->destination_format));
            xml_extract(s3bd_v, s3bd_l, "AccountId", cfg->destination_account,
                        sizeof(cfg->destination_account));
        }
    }

    /* Optional fields */
    const char *of_v;
    size_t of_l;
    if (s3__xml_find(el, el_len, "OptionalFields", &of_v, &of_l)) {
        parse_string_list(of_v, of_l, "Field", &cfg->optional_fields, &cfg->field_count);
    }
}

s3_status s3_get_bucket_inventory(s3_client *c, const char *bucket, const char *id,
                                  s3_inventory_config *config)
{
    if (!c || !bucket || !id || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "inventory&id=%s", id);

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    parse_inventory_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_inventory(s3_client *c, const char *bucket,
                                  const s3_inventory_config *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "inventory&id=%s", config->id);

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&body, "Id", config->id);
    s3__xml_buf_element_bool(&body, "IsEnabled", config->enabled);
    s3__xml_buf_element(&body, "IncludedObjectVersions", config->included_versions);

    /* Schedule */
    s3__xml_buf_open(&body, "Schedule");
    s3__xml_buf_element(&body, "Frequency", config->schedule);
    s3__xml_buf_close(&body, "Schedule");

    /* Filter */
    if (config->prefix[0]) {
        s3__xml_buf_open(&body, "Filter");
        s3__xml_buf_element(&body, "Prefix", config->prefix);
        s3__xml_buf_close(&body, "Filter");
    }

    /* Destination */
    s3__xml_buf_open(&body, "Destination");
    s3__xml_buf_open(&body, "S3BucketDestination");
    s3__xml_buf_element(&body, "Bucket", config->destination_bucket);
    if (config->destination_prefix[0])
        s3__xml_buf_element(&body, "Prefix", config->destination_prefix);
    s3__xml_buf_element(&body, "Format", config->destination_format);
    if (config->destination_account[0])
        s3__xml_buf_element(&body, "AccountId", config->destination_account);
    s3__xml_buf_close(&body, "S3BucketDestination");
    s3__xml_buf_close(&body, "Destination");

    /* Optional fields */
    if (config->field_count > 0) {
        s3__xml_buf_open(&body, "OptionalFields");
        for (int i = 0; i < config->field_count; i++)
            s3__xml_buf_element(&body, "Field", config->optional_fields[i]);
        s3__xml_buf_close(&body, "OptionalFields");
    }

    s3__xml_buf_close(&body, "InventoryConfiguration");

    s3_status st = bucket_put_xml(c, bucket, qs, &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_inventory(s3_client *c, const char *bucket, const char *id)
{
    if (!c || !bucket || !id) return S3_STATUS_INVALID_ARGUMENT;
    char qs[256];
    snprintf(qs, sizeof(qs), "inventory&id=%s", id);
    return bucket_delete(c, bucket, qs);
}

s3_status s3_list_bucket_inventory(s3_client *c, const char *bucket,
                                   const char *continuation_token,
                                   s3_list_inventory_result *result)
{
    if (!c || !bucket || !result) return S3_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));

    char qs[1200];
    if (continuation_token && continuation_token[0])
        snprintf(qs, sizeof(qs), "inventory&continuation-token=%s", continuation_token);
    else
        snprintf(qs, sizeof(qs), "inventory");

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    result->is_truncated = xml_extract_bool(xml, len, "IsTruncated");
    xml_extract(xml, len, "ContinuationToken", result->continuation_token,
                sizeof(result->continuation_token));

    count_ctx cc = {0};
    s3__xml_each(xml, len, "InventoryConfiguration", count_cb, &cc);
    if (cc.count == 0) return S3_STATUS_OK;

    result->configs = (s3_inventory_config *)S3_CALLOC((size_t)cc.count, sizeof(s3_inventory_config));
    if (!result->configs) return S3_STATUS_OUT_OF_MEMORY;

    int idx = 0;
    const char *p = xml;
    size_t rem = len;
    while (rem > 0 && idx < cc.count) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, "InventoryConfiguration", &v, &vl)) break;
        parse_inventory_config(v, vl, &result->configs[idx]);
        idx++;
        const char *after = v + vl;
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }
    result->count = idx;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Analytics
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_analytics_config(const char *el, size_t el_len, s3_analytics_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    xml_extract(el, el_len, "Id", cfg->id, sizeof(cfg->id));

    const char *fv;
    size_t fl;
    if (s3__xml_find(el, el_len, "Filter", &fv, &fl)) {
        xml_extract(fv, fl, "Prefix", cfg->prefix, sizeof(cfg->prefix));
        const char *and_v;
        size_t and_l;
        if (s3__xml_find(fv, fl, "And", &and_v, &and_l)) {
            xml_extract(and_v, and_l, "Prefix", cfg->prefix, sizeof(cfg->prefix));
            parse_tags(and_v, and_l, &cfg->tags, &cfg->tag_count);
        } else {
            const char *tv;
            size_t tl;
            if (s3__xml_find(fv, fl, "Tag", &tv, &tl)) {
                cfg->tags = (s3_tag *)S3_CALLOC(1, sizeof(s3_tag));
                if (cfg->tags) {
                    xml_extract(tv, tl, "Key", cfg->tags[0].key, sizeof(cfg->tags[0].key));
                    xml_extract(tv, tl, "Value", cfg->tags[0].value, sizeof(cfg->tags[0].value));
                    cfg->tag_count = 1;
                }
            }
        }
    }

    /* StorageClassAnalysis -> DataExport -> Destination -> S3BucketDestination */
    const char *sc_v;
    size_t sc_l;
    if (s3__xml_find(el, el_len, "StorageClassAnalysis", &sc_v, &sc_l)) {
        const char *de_v;
        size_t de_l;
        if (s3__xml_find(sc_v, sc_l, "DataExport", &de_v, &de_l)) {
            const char *dest_v;
            size_t dest_l;
            if (s3__xml_find(de_v, de_l, "Destination", &dest_v, &dest_l)) {
                const char *s3bd_v;
                size_t s3bd_l;
                if (s3__xml_find(dest_v, dest_l, "S3BucketDestination", &s3bd_v, &s3bd_l)) {
                    xml_extract(s3bd_v, s3bd_l, "Bucket", cfg->export_bucket,
                                sizeof(cfg->export_bucket));
                    xml_extract(s3bd_v, s3bd_l, "Prefix", cfg->export_prefix,
                                sizeof(cfg->export_prefix));
                    xml_extract(s3bd_v, s3bd_l, "Format", cfg->export_format,
                                sizeof(cfg->export_format));
                }
            }
        }
    }
}

s3_status s3_get_bucket_analytics(s3_client *c, const char *bucket, const char *id,
                                  s3_analytics_config *config)
{
    if (!c || !bucket || !id || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "analytics&id=%s", id);

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    parse_analytics_config(c->response.data, c->response.len, config);
    return S3_STATUS_OK;
}

s3_status s3_put_bucket_analytics(s3_client *c, const char *bucket,
                                  const s3_analytics_config *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    char qs[256];
    snprintf(qs, sizeof(qs), "analytics&id=%s", config->id);

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<AnalyticsConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3__xml_buf_element(&body, "Id", config->id);
    build_filter_prefix_tags(&body, config->prefix, config->tags, config->tag_count);

    /* StorageClassAnalysis */
    s3__xml_buf_open(&body, "StorageClassAnalysis");
    if (config->export_bucket[0]) {
        s3__xml_buf_open(&body, "DataExport");
        s3__xml_buf_element(&body, "OutputSchemaVersion", "V_1");
        s3__xml_buf_open(&body, "Destination");
        s3__xml_buf_open(&body, "S3BucketDestination");
        s3__xml_buf_element(&body, "Bucket", config->export_bucket);
        if (config->export_prefix[0])
            s3__xml_buf_element(&body, "Prefix", config->export_prefix);
        s3__xml_buf_element(&body, "Format", config->export_format[0] ? config->export_format : "CSV");
        s3__xml_buf_close(&body, "S3BucketDestination");
        s3__xml_buf_close(&body, "Destination");
        s3__xml_buf_close(&body, "DataExport");
    }
    s3__xml_buf_close(&body, "StorageClassAnalysis");

    s3__xml_buf_close(&body, "AnalyticsConfiguration");

    s3_status st = bucket_put_xml(c, bucket, qs, &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_analytics(s3_client *c, const char *bucket, const char *id)
{
    if (!c || !bucket || !id) return S3_STATUS_INVALID_ARGUMENT;
    char qs[256];
    snprintf(qs, sizeof(qs), "analytics&id=%s", id);
    return bucket_delete(c, bucket, qs);
}

s3_status s3_list_bucket_analytics(s3_client *c, const char *bucket,
                                   const char *continuation_token,
                                   s3_list_analytics_result *result)
{
    if (!c || !bucket || !result) return S3_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));

    char qs[1200];
    if (continuation_token && continuation_token[0])
        snprintf(qs, sizeof(qs), "analytics&continuation-token=%s", continuation_token);
    else
        snprintf(qs, sizeof(qs), "analytics");

    s3_status st = bucket_get(c, bucket, qs);
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    result->is_truncated = xml_extract_bool(xml, len, "IsTruncated");
    xml_extract(xml, len, "ContinuationToken", result->continuation_token,
                sizeof(result->continuation_token));

    count_ctx cc = {0};
    s3__xml_each(xml, len, "AnalyticsConfiguration", count_cb, &cc);
    if (cc.count == 0) return S3_STATUS_OK;

    result->configs = (s3_analytics_config *)S3_CALLOC((size_t)cc.count, sizeof(s3_analytics_config));
    if (!result->configs) return S3_STATUS_OUT_OF_MEMORY;

    int idx = 0;
    const char *p = xml;
    size_t rem = len;
    while (rem > 0 && idx < cc.count) {
        const char *v;
        size_t vl;
        if (!s3__xml_find(p, rem, "AnalyticsConfiguration", &v, &vl)) break;
        parse_analytics_config(v, vl, &result->configs[idx]);
        idx++;
        const char *after = v + vl;
        const char *gt = memchr(after, '>', (size_t)((xml + len) - after));
        if (!gt) break;
        rem = (size_t)((xml + len) - (gt + 1));
        p = gt + 1;
    }
    result->count = idx;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public Access Block
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_public_access_block(s3_client *c, const char *bucket,
                                     s3_public_access_block *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));

    s3_status st = bucket_get(c, bucket, "publicAccessBlock");
    if (st != S3_STATUS_OK) return st;

    const char *xml = c->response.data;
    size_t len = c->response.len;

    config->block_public_acls = xml_extract_bool(xml, len, "BlockPublicAcls");
    config->ignore_public_acls = xml_extract_bool(xml, len, "IgnorePublicAcls");
    config->block_public_policy = xml_extract_bool(xml, len, "BlockPublicPolicy");
    config->restrict_public_buckets = xml_extract_bool(xml, len, "RestrictPublicBuckets");

    return S3_STATUS_OK;
}

s3_status s3_put_public_access_block(s3_client *c, const char *bucket,
                                     const s3_public_access_block *config)
{
    if (!c || !bucket || !config) return S3_STATUS_INVALID_ARGUMENT;

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_element_bool(&body, "BlockPublicAcls", config->block_public_acls);
    s3__xml_buf_element_bool(&body, "IgnorePublicAcls", config->ignore_public_acls);
    s3__xml_buf_element_bool(&body, "BlockPublicPolicy", config->block_public_policy);
    s3__xml_buf_element_bool(&body, "RestrictPublicBuckets", config->restrict_public_buckets);
    s3__xml_buf_close(&body, "PublicAccessBlockConfiguration");

    s3_status st = bucket_put_xml(c, bucket, "publicAccessBlock", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_public_access_block(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "publicAccessBlock");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Ownership Controls
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_get_bucket_ownership_controls(s3_client *c, const char *bucket,
                                           s3_object_ownership *ownership)
{
    if (!c || !bucket || !ownership) return S3_STATUS_INVALID_ARGUMENT;

    s3_status st = bucket_get(c, bucket, "ownershipControls");
    if (st != S3_STATUS_OK) return st;

    char buf[64];
    xml_extract(c->response.data, c->response.len, "ObjectOwnership", buf, sizeof(buf));

    if (strcmp(buf, "BucketOwnerPreferred") == 0)
        *ownership = S3_OWNERSHIP_BUCKET_OWNER_PREFERRED;
    else if (strcmp(buf, "ObjectWriter") == 0)
        *ownership = S3_OWNERSHIP_OBJECT_WRITER;
    else
        *ownership = S3_OWNERSHIP_BUCKET_OWNER_ENFORCED;

    return S3_STATUS_OK;
}

s3_status s3_put_bucket_ownership_controls(s3_client *c, const char *bucket,
                                           s3_object_ownership ownership)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    const char *val;
    switch (ownership) {
        case S3_OWNERSHIP_BUCKET_OWNER_PREFERRED: val = "BucketOwnerPreferred"; break;
        case S3_OWNERSHIP_OBJECT_WRITER:          val = "ObjectWriter";         break;
        default:                                  val = "BucketOwnerEnforced";  break;
    }

    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body, "<OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    s3__xml_buf_open(&body, "Rule");
    s3__xml_buf_element(&body, "ObjectOwnership", val);
    s3__xml_buf_close(&body, "Rule");
    s3__xml_buf_close(&body, "OwnershipControls");

    s3_status st = bucket_put_xml(c, bucket, "ownershipControls", &body);
    s3_buf_free(&body);
    return st;
}

s3_status s3_delete_bucket_ownership_controls(s3_client *c, const char *bucket)
{
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;
    return bucket_delete(c, bucket, "ownershipControls");
}
