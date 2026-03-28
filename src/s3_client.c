/*
 * libs3 — Client lifecycle, utility functions, and enum conversions
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * String Utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

char *s3__strdup(const char *s) {
    if (!s) return nullptr;
    size_t len = strlen(s);
    char *dup = (char *)S3_MALLOC(len + 1);
    if (!dup) return nullptr;
    memcpy(dup, s, len + 1);
    return dup;
}

char *s3__strndup(const char *s, size_t n) {
    if (!s) return nullptr;
    size_t len = strlen(s);
    if (n < len) len = n;
    char *dup = (char *)S3_MALLOC(len + 1);
    if (!dup) return nullptr;
    memcpy(dup, s, len);
    dup[len] = '\0';
    return dup;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Allocator
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_free(void *ptr) {
    S3_FREE(ptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Client Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_client_create(s3_client **out, const s3_config *config) {
    if (!out || !config) {
        return S3_STATUS_INVALID_ARGUMENT;
    }

    *out = nullptr;

    /* Validate: region must be provided and non-empty */
    if (!config->region || config->region[0] == '\0') {
        return S3_STATUS_INVALID_ARGUMENT;
    }

    /* Validate: credentials required unless credential_provider is set */
    if (!config->credential_provider) {
        if (!config->credentials.access_key_id ||
            config->credentials.access_key_id[0] == '\0' ||
            !config->credentials.secret_access_key ||
            config->credentials.secret_access_key[0] == '\0') {
            return S3_STATUS_INVALID_ARGUMENT;
        }
    }

    /* Allocate the client struct (zero-initialized) */
    s3_client *c = (s3_client *)S3_CALLOC(1, sizeof(s3_client));
    if (!c) {
        return S3_STATUS_OUT_OF_MEMORY;
    }

    /* Deep-copy strings. Any allocation failure triggers cleanup. */
    #define DUP_STRING(dst, src) do {                     \
        if ((src)) {                                      \
            (dst) = s3__strdup((src));                    \
            if (!(dst)) goto oom;                         \
        }                                                 \
    } while (0)

    DUP_STRING(c->access_key_id,     config->credentials.access_key_id);
    DUP_STRING(c->secret_access_key, config->credentials.secret_access_key);
    DUP_STRING(c->session_token,     config->credentials.session_token);
    DUP_STRING(c->region,            config->region);
    DUP_STRING(c->endpoint,          config->endpoint);
    DUP_STRING(c->account_id,        config->account_id);

    if (config->user_agent) {
        c->user_agent = s3__strdup(config->user_agent);
    } else {
        c->user_agent = s3__strdup("libs3/1.0");
    }
    if (!c->user_agent) goto oom;

    #undef DUP_STRING

    /* Copy non-string config fields */
    c->use_path_style            = config->use_path_style;
    c->use_transfer_acceleration = config->use_transfer_acceleration;
    c->use_dual_stack            = config->use_dual_stack;
    c->use_fips                  = config->use_fips;
    c->connect_timeout_ms        = config->connect_timeout_ms;
    c->request_timeout_ms        = config->request_timeout_ms;
    c->log_fn                    = config->log_fn;
    c->log_userdata              = config->log_userdata;
    c->log_level                 = config->log_level;
    c->credential_provider       = config->credential_provider;
    c->credential_provider_userdata = config->credential_provider_userdata;

    /*
     * Detect whether the config appears to be zero-initialized (i.e. the caller
     * used calloc or = {0} and only filled in a few fields). We check whether
     * the retry_policy is entirely zeroed, which is a reliable sentinel since a
     * deliberately configured policy will always have non-zero max_retries or
     * base_delay_ms. When zero-init is detected, we apply documented defaults
     * for use_https (true) and the full retry_policy.
     */
    s3_retry_policy rp = config->retry_policy;
    bool retry_uninitialized = (rp.max_retries == 0 &&
                                rp.base_delay_ms == 0 &&
                                rp.max_delay_ms == 0 &&
                                rp.backoff_multiplier == 0.0);

    /* use_https defaults to true; only honour an explicit false when the config
     * has been deliberately populated (retry_policy non-zero). */
    if (retry_uninitialized && !config->use_https) {
        c->use_https = true;
    } else {
        c->use_https = config->use_https;
    }

    if (retry_uninitialized) {
        c->retry_policy.max_retries        = 3;
        c->retry_policy.base_delay_ms      = 100;
        c->retry_policy.max_delay_ms       = 20000;
        c->retry_policy.backoff_multiplier = 2.0;
        c->retry_policy.jitter             = true;
        c->retry_policy.retry_on_throttle  = true;
        c->retry_policy.retry_on_5xx       = true;
        c->retry_policy.retry_on_timeout   = true;
    } else {
        c->retry_policy = rp;
    }

    /* Initialize CURL easy handle */
    c->curl = curl_easy_init();
    if (!c->curl) goto oom;

    /* Initialize response buffer */
    s3_buf_init(&c->response);

    /* Initialize last_error to a clean state */
    memset(&c->last_error, 0, sizeof(c->last_error));

    *out = c;
    return S3_STATUS_OK;

oom:
    s3_client_destroy(c);
    return S3_STATUS_OUT_OF_MEMORY;
}

void s3_client_destroy(s3_client *client) {
    if (!client) return;

    S3_FREE(client->access_key_id);
    S3_FREE(client->secret_access_key);
    S3_FREE(client->session_token);
    S3_FREE(client->region);
    S3_FREE(client->endpoint);
    S3_FREE(client->account_id);
    S3_FREE(client->user_agent);

    if (client->curl) {
        curl_easy_cleanup(client->curl);
        client->curl = nullptr;
    }

    s3_buf_free(&client->response);

    /* Free response metadata */
    if (client->resp_metadata) {
        for (int i = 0; i < client->resp_metadata_count; i++) {
            S3_FREE((void *)client->resp_metadata[i].key);
            S3_FREE((void *)client->resp_metadata[i].value);
        }
        S3_FREE(client->resp_metadata);
    }

    S3_FREE(client);
}

const s3_error *s3_client_last_error(const s3_client *client) {
    if (!client) return nullptr;
    return &client->last_error;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Enum ↔ String Conversions
 * ═══════════════════════════════════════════════════════════════════════════ */

const char *s3__storage_class_string(s3_storage_class sc) {
    switch (sc) {
        case S3_STORAGE_CLASS_STANDARD:            return "STANDARD";
        case S3_STORAGE_CLASS_REDUCED_REDUNDANCY:  return "REDUCED_REDUNDANCY";
        case S3_STORAGE_CLASS_STANDARD_IA:         return "STANDARD_IA";
        case S3_STORAGE_CLASS_ONEZONE_IA:          return "ONEZONE_IA";
        case S3_STORAGE_CLASS_INTELLIGENT_TIERING: return "INTELLIGENT_TIERING";
        case S3_STORAGE_CLASS_GLACIER:             return "GLACIER";
        case S3_STORAGE_CLASS_GLACIER_IR:          return "GLACIER_IR";
        case S3_STORAGE_CLASS_DEEP_ARCHIVE:        return "DEEP_ARCHIVE";
        case S3_STORAGE_CLASS_EXPRESS_ONEZONE:      return "EXPRESS_ONEZONE";
    }
    return "STANDARD";
}

s3_storage_class s3__storage_class_from_string(const char *s) {
    if (!s) return S3_STORAGE_CLASS_STANDARD;

    static const struct { const char *name; s3_storage_class cls; } map[] = {
        { "STANDARD",             S3_STORAGE_CLASS_STANDARD },
        { "REDUCED_REDUNDANCY",   S3_STORAGE_CLASS_REDUCED_REDUNDANCY },
        { "STANDARD_IA",          S3_STORAGE_CLASS_STANDARD_IA },
        { "ONEZONE_IA",           S3_STORAGE_CLASS_ONEZONE_IA },
        { "INTELLIGENT_TIERING",  S3_STORAGE_CLASS_INTELLIGENT_TIERING },
        { "GLACIER",              S3_STORAGE_CLASS_GLACIER },
        { "GLACIER_IR",           S3_STORAGE_CLASS_GLACIER_IR },
        { "DEEP_ARCHIVE",         S3_STORAGE_CLASS_DEEP_ARCHIVE },
        { "EXPRESS_ONEZONE",      S3_STORAGE_CLASS_EXPRESS_ONEZONE },
    };

    for (size_t i = 0; i < S3_ARRAY_LEN(map); i++) {
        if (strcmp(s, map[i].name) == 0) {
            return map[i].cls;
        }
    }
    return S3_STORAGE_CLASS_STANDARD;
}

const char *s3__canned_acl_string(s3_canned_acl acl) {
    switch (acl) {
        case S3_ACL_PRIVATE:                    return "private";
        case S3_ACL_PUBLIC_READ:                return "public-read";
        case S3_ACL_PUBLIC_READ_WRITE:          return "public-read-write";
        case S3_ACL_AUTHENTICATED_READ:         return "authenticated-read";
        case S3_ACL_AWS_EXEC_READ:              return "aws-exec-read";
        case S3_ACL_BUCKET_OWNER_READ:          return "bucket-owner-read";
        case S3_ACL_BUCKET_OWNER_FULL_CONTROL:  return "bucket-owner-full-control";
        case S3_ACL_LOG_DELIVERY_WRITE:         return "log-delivery-write";
    }
    return "private";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Timestamp
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__get_timestamp(char iso8601[17], char datestamp[9]) {
    time_t now = time(nullptr);
    struct tm tm;
    gmtime_r(&now, &tm);

    /* ISO 8601: YYYYMMDD'T'HHMMSS'Z' — 16 chars + null */
    char iso_buf[64];
    snprintf(iso_buf, sizeof(iso_buf), "%04d%02d%02dT%02d%02d%02dZ",
             (int)(tm.tm_year + 1900), (int)(tm.tm_mon + 1), (int)tm.tm_mday,
             (int)tm.tm_hour, (int)tm.tm_min, (int)tm.tm_sec);
    memcpy(iso8601, iso_buf, 17);

    /* Datestamp: YYYYMMDD — 8 chars + null */
    char date_buf[64];
    snprintf(date_buf, sizeof(date_buf), "%04d%02d%02d",
             (int)(tm.tm_year + 1900), (int)(tm.tm_mon + 1), (int)tm.tm_mday);
    memcpy(datestamp, date_buf, 9);
}
