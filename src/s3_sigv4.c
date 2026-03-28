/*
 * libs3 — AWS Signature Version 4 signing engine
 *
 * Implements request signing (Authorization header) and URL presigning
 * per the AWS SigV4 specification.
 */

#include "s3_internal.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_HEADERS       128
#define CANONICAL_BUF_SZ  16384
#define URL_BUF_SZ        8192
#define HEADER_BUF_SZ     8192

static const char HEX_CHARS[] = "0123456789abcdef";

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Convert a byte buffer to lowercase hex string. out must have room for
 * (len * 2 + 1) bytes.
 */
static void to_hex(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_CHARS[in[i] >> 4];
        out[i * 2 + 1] = HEX_CHARS[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/*
 * Lowercase a string in-place.
 */
static void str_tolower(char *s) {
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

/*
 * Trim leading and trailing whitespace in-place. Returns pointer to
 * trimmed start (within the original buffer). Modifies the string
 * by null-terminating after trailing content.
 */
static char *str_trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

/*
 * Header name/value pair for sorting.
 */
typedef struct {
    char name[256];   /* lowercase header name */
    char value[2048]; /* trimmed header value */
} header_entry;

/*
 * qsort comparator for header entries — sort by lowercase name.
 */
static int header_cmp(const void *a, const void *b) {
    return strcmp(((const header_entry *)a)->name,
                 ((const header_entry *)b)->name);
}

/*
 * Key=value pair for query string sorting.
 */
typedef struct {
    char key[1024];
    char value[1024];
} query_param;

/*
 * qsort comparator for query parameters — sort by key, then value.
 */
static int query_param_cmp(const void *a, const void *b) {
    int r = strcmp(((const query_param *)a)->key,
                  ((const query_param *)b)->key);
    if (r != 0) return r;
    return strcmp(((const query_param *)a)->value,
                 ((const query_param *)b)->value);
}

/*
 * Parse a curl_slist of "Name: Value" headers into an array of header_entry.
 * Returns the count of parsed headers.
 */
static int parse_headers(struct curl_slist *headers, header_entry *entries,
                         int max_entries) {
    int count = 0;
    for (struct curl_slist *h = headers; h && count < max_entries; h = h->next) {
        const char *colon = strchr(h->data, ':');
        if (!colon) continue;

        size_t name_len = (size_t)(colon - h->data);
        if (name_len >= sizeof(entries[0].name)) continue;

        memcpy(entries[count].name, h->data, name_len);
        entries[count].name[name_len] = '\0';
        str_tolower(entries[count].name);

        const char *val = colon + 1;
        while (*val && isspace((unsigned char)*val)) val++;
        size_t val_len = strlen(val);
        if (val_len >= sizeof(entries[0].value)) val_len = sizeof(entries[0].value) - 1;
        memcpy(entries[count].value, val, val_len);
        entries[count].value[val_len] = '\0';
        /* Trim trailing whitespace */
        char *trimmed = str_trim(entries[count].value);
        if (trimmed != entries[count].value) {
            memmove(entries[count].value, trimmed, strlen(trimmed) + 1);
        }

        count++;
    }
    return count;
}

/*
 * Parse a query string (without leading '?') into query_param array.
 * Each param is URI-encoded key and URI-encoded value.
 * Returns the count of parsed parameters.
 */
static int parse_query_string(const char *query, query_param *params,
                              int max_params) {
    if (!query || !*query) return 0;

    int count = 0;
    const char *p = query;

    while (*p && count < max_params) {
        const char *amp = strchr(p, '&');
        size_t seg_len = amp ? (size_t)(amp - p) : strlen(p);

        if (seg_len > 0) {
            /* Find '=' within this segment */
            const char *eq = (const char *)memchr(p, '=', seg_len);

            if (eq) {
                size_t key_len = (size_t)(eq - p);
                size_t val_len = seg_len - key_len - 1;

                if (key_len < sizeof(params[0].key) &&
                    val_len < sizeof(params[0].value)) {
                    memcpy(params[count].key, p, key_len);
                    params[count].key[key_len] = '\0';
                    memcpy(params[count].value, eq + 1, val_len);
                    params[count].value[val_len] = '\0';
                    count++;
                }
            } else {
                /* Key with no value */
                if (seg_len < sizeof(params[0].key)) {
                    memcpy(params[count].key, p, seg_len);
                    params[count].key[seg_len] = '\0';
                    params[count].value[0] = '\0';
                    count++;
                }
            }
        }

        if (!amp) break;
        p = amp + 1;
    }

    return count;
}

/*
 * Build the canonical query string from already-parsed query parameters.
 * Parameters are URI-encoded then sorted by key (byte order).
 * Writes to out_buf (must be large enough). Returns length written.
 */
static size_t build_canonical_query(const char *query, char *out_buf,
                                    size_t out_size) {
    query_param params[128];
    int n = parse_query_string(query, params, S3_ARRAY_LEN(params));

    /* Re-encode keys and values for canonical form */
    query_param encoded[128];
    for (int i = 0; i < n; i++) {
        s3__uri_encode(params[i].key, strlen(params[i].key),
                       encoded[i].key, sizeof(encoded[i].key), true);
        s3__uri_encode(params[i].value, strlen(params[i].value),
                       encoded[i].value, sizeof(encoded[i].value), true);
    }

    qsort(encoded, (size_t)n, sizeof(query_param), query_param_cmp);

    size_t pos = 0;
    for (int i = 0; i < n; i++) {
        if (i > 0 && pos < out_size - 1) out_buf[pos++] = '&';
        size_t klen = strlen(encoded[i].key);
        size_t vlen = strlen(encoded[i].value);
        if (pos + klen + 1 + vlen < out_size) {
            memcpy(out_buf + pos, encoded[i].key, klen);
            pos += klen;
            out_buf[pos++] = '=';
            memcpy(out_buf + pos, encoded[i].value, vlen);
            pos += vlen;
        }
    }
    out_buf[pos] = '\0';
    return pos;
}

/*
 * Build canonical URI from the path. URI-encodes each path component
 * individually, preserving '/' separators.
 */
static size_t build_canonical_uri(const char *uri, char *out, size_t out_size) {
    if (!uri || !*uri) {
        if (out_size > 0) {
            out[0] = '/';
            out[1] = '\0';
        }
        return 1;
    }
    return s3__uri_encode_path(uri, strlen(uri), out, out_size);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__derive_signing_key
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__derive_signing_key(const char *secret, const char *date_stamp,
                            const char *region, const char *service,
                            uint8_t key_out[32]) {
    /* Construct "AWS4" + secret_access_key */
    char aws4_key[512];
    int aws4_len = snprintf(aws4_key, sizeof(aws4_key), "AWS4%s", secret);
    if (aws4_len < 0 || (size_t)aws4_len >= sizeof(aws4_key)) {
        /* Secret too long — truncate (should not happen in practice) */
        aws4_len = (int)sizeof(aws4_key) - 1;
    }

    uint8_t k_date[32];
    s3__hmac_sha256(aws4_key, (size_t)aws4_len,
                    date_stamp, strlen(date_stamp), k_date);

    uint8_t k_region[32];
    s3__hmac_sha256(k_date, 32, region, strlen(region), k_region);

    uint8_t k_service[32];
    s3__hmac_sha256(k_region, 32, service, strlen(service), k_service);

    s3__hmac_sha256(k_service, 32, "aws4_request", 12, key_out);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__sign_request
 * ═══════════════════════════════════════════════════════════════════════════ */

int s3__sign_request(s3_client *c, const char *method,
                     const char *uri, const char *query,
                     struct curl_slist **headers,
                     const char *payload_hash) {
    char iso8601[17];   /* YYYYMMDDTHHmmSSZ */
    char datestamp[9];  /* YYYYMMDD */

    /* ── Step (a): Get timestamp ── */
    /* Check if x-amz-date is already set */
    bool have_date = false;
    for (struct curl_slist *h = *headers; h; h = h->next) {
        if (strncasecmp(h->data, "x-amz-date:", 11) == 0) {
            const char *val = h->data + 11;
            while (*val == ' ') val++;
            if (strlen(val) >= 16) {
                memcpy(iso8601, val, 16);
                iso8601[16] = '\0';
                memcpy(datestamp, val, 8);
                datestamp[8] = '\0';
                have_date = true;
            }
            break;
        }
    }
    if (!have_date) {
        s3__get_timestamp(iso8601, datestamp);
    }

    /* ── Step (b): Add required headers ── */
    if (!have_date) {
        char date_hdr[64];
        snprintf(date_hdr, sizeof(date_hdr), "x-amz-date: %s", iso8601);
        *headers = curl_slist_append(*headers, date_hdr);
        if (!*headers) return -1;
    }

    /* x-amz-content-sha256 */
    {
        char sha_hdr[256];
        snprintf(sha_hdr, sizeof(sha_hdr), "x-amz-content-sha256: %s",
                 payload_hash ? payload_hash : "UNSIGNED-PAYLOAD");
        *headers = curl_slist_append(*headers, sha_hdr);
        if (!*headers) return -1;
    }

    /* Host — extract from the URL we'd build, or construct from endpoint/region */
    {
        /* Check if Host is already provided in headers */
        bool have_host = false;
        for (struct curl_slist *h = *headers; h; h = h->next) {
            if (strncasecmp(h->data, "Host:", 5) == 0) {
                have_host = true;
                break;
            }
        }
        if (!have_host) {
            /* Build host from client config */
            char host[512];
            if (c->endpoint) {
                snprintf(host, sizeof(host), "%s", c->endpoint);
            } else {
                snprintf(host, sizeof(host), "s3.%s.amazonaws.com", c->region);
            }
            char host_hdr[600];
            snprintf(host_hdr, sizeof(host_hdr), "Host: %s", host);
            *headers = curl_slist_append(*headers, host_hdr);
            if (!*headers) return -1;
        }
    }

    /* x-amz-security-token if session token is set */
    if (c->session_token && c->session_token[0]) {
        char token_hdr[4096];
        snprintf(token_hdr, sizeof(token_hdr), "x-amz-security-token: %s",
                 c->session_token);
        *headers = curl_slist_append(*headers, token_hdr);
        if (!*headers) return -1;
    }

    /* ── Step (c): Build canonical headers and signed headers ── */
    header_entry entries[MAX_HEADERS];
    int n_headers = parse_headers(*headers, entries, MAX_HEADERS);
    qsort(entries, (size_t)n_headers, sizeof(header_entry), header_cmp);

    char canonical_headers[HEADER_BUF_SZ];
    char signed_headers[HEADER_BUF_SZ];
    size_t ch_pos = 0;
    size_t sh_pos = 0;

    for (int i = 0; i < n_headers; i++) {
        /* canonical header line: "name:value\n" */
        size_t nlen = strlen(entries[i].name);
        size_t vlen = strlen(entries[i].value);
        if (ch_pos + nlen + 1 + vlen + 1 < sizeof(canonical_headers)) {
            memcpy(canonical_headers + ch_pos, entries[i].name, nlen);
            ch_pos += nlen;
            canonical_headers[ch_pos++] = ':';
            memcpy(canonical_headers + ch_pos, entries[i].value, vlen);
            ch_pos += vlen;
            canonical_headers[ch_pos++] = '\n';
        }

        /* signed headers: "name1;name2;name3" */
        if (sh_pos > 0 && sh_pos < sizeof(signed_headers) - 1) {
            signed_headers[sh_pos++] = ';';
        }
        if (sh_pos + nlen < sizeof(signed_headers)) {
            memcpy(signed_headers + sh_pos, entries[i].name, nlen);
            sh_pos += nlen;
        }
    }
    canonical_headers[ch_pos] = '\0';
    signed_headers[sh_pos] = '\0';

    /* ── Step (d): Build canonical URI ── */
    char canonical_uri[URL_BUF_SZ];
    build_canonical_uri(uri, canonical_uri, sizeof(canonical_uri));

    /* ── Step (e): Build canonical query string ── */
    char canonical_query[URL_BUF_SZ];
    build_canonical_query(query ? query : "", canonical_query,
                          sizeof(canonical_query));

    /* ── Step (f): Build canonical request ── */
    char canonical_request[CANONICAL_BUF_SZ];
    int cr_len = snprintf(canonical_request, sizeof(canonical_request),
                          "%s\n%s\n%s\n%s\n%s\n%s",
                          method,
                          canonical_uri,
                          canonical_query,
                          canonical_headers,
                          signed_headers,
                          payload_hash ? payload_hash : "UNSIGNED-PAYLOAD");
    if (cr_len < 0 || (size_t)cr_len >= sizeof(canonical_request)) {
        S3_LOG_ERROR_(c, "canonical request too large");
        return -1;
    }

    S3_LOG_TRACE_(c, "Canonical Request:\n%s", canonical_request);

    /* ── Step (g): Build string to sign ── */
    char scope[256];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request",
             datestamp, c->region);

    char cr_hash[65];
    s3__sha256_hex(canonical_request, (size_t)cr_len, cr_hash);

    char string_to_sign[512];
    int sts_len = snprintf(string_to_sign, sizeof(string_to_sign),
                           "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                           iso8601, scope, cr_hash);
    if (sts_len < 0 || (size_t)sts_len >= sizeof(string_to_sign)) {
        S3_LOG_ERROR_(c, "string to sign too large");
        return -1;
    }

    S3_LOG_TRACE_(c, "String to Sign:\n%s", string_to_sign);

    /* ── Step (h): Derive signing key (with caching) ── */
    if (strcmp(c->signing_key_date, datestamp) != 0 ||
        strcmp(c->signing_key_region, c->region) != 0) {
        s3__derive_signing_key(c->secret_access_key, datestamp,
                               c->region, "s3", c->signing_key);
        memcpy(c->signing_key_date, datestamp, 9);
        snprintf(c->signing_key_region, sizeof(c->signing_key_region),
                 "%s", c->region);
        S3_LOG_DEBUG_(c, "Derived new signing key for %s/%s", datestamp, c->region);
    }

    /* ── Step (i): Compute signature ── */
    uint8_t sig_raw[32];
    s3__hmac_sha256(c->signing_key, 32,
                    string_to_sign, (size_t)sts_len, sig_raw);

    char signature[65];
    to_hex(sig_raw, 32, signature);

    S3_LOG_TRACE_(c, "Signature: %s", signature);

    /* ── Step (j): Build Authorization header ── */
    char auth_header[16384];
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: AWS4-HMAC-SHA256 "
             "Credential=%s/%s, "
             "SignedHeaders=%s, "
             "Signature=%s",
             c->access_key_id, scope, signed_headers, signature);

    /* ── Step (k): Append Authorization header ── */
    *headers = curl_slist_append(*headers, auth_header);
    if (!*headers) return -1;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__presign_url
 * ═══════════════════════════════════════════════════════════════════════════ */

int s3__presign_url(s3_client *c, const char *method,
                    const char *bucket, const char *key,
                    int expires, const char *content_type,
                    const char *extra_query,
                    char *url_buf, size_t url_buf_size) {
    char iso8601[17];
    char datestamp[9];
    s3__get_timestamp(iso8601, datestamp);

    /* ── Build scope ── */
    char scope[256];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request",
             datestamp, c->region);

    /* ── Build credential ── */
    char credential[512];
    snprintf(credential, sizeof(credential), "%s/%s",
             c->access_key_id, scope);

    /* URI-encode the credential for use in query string */
    char credential_encoded[1024];
    s3__uri_encode(credential, strlen(credential),
                   credential_encoded, sizeof(credential_encoded), true);

    /* ── Build the host ── */
    char host[512];
    if (c->endpoint) {
        snprintf(host, sizeof(host), "%s", c->endpoint);
    } else if (c->use_path_style) {
        snprintf(host, sizeof(host), "s3.%s.amazonaws.com", c->region);
    } else if (bucket) {
        snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com",
                 bucket, c->region);
    } else {
        snprintf(host, sizeof(host), "s3.%s.amazonaws.com", c->region);
    }

    /* ── Build the canonical URI ── */
    char path[URL_BUF_SZ];
    if (c->endpoint || c->use_path_style) {
        if (bucket && key && key[0]) {
            snprintf(path, sizeof(path), "/%s/%s", bucket, key);
        } else if (bucket) {
            snprintf(path, sizeof(path), "/%s", bucket);
        } else {
            snprintf(path, sizeof(path), "/");
        }
    } else {
        if (key && key[0]) {
            snprintf(path, sizeof(path), "/%s", key);
        } else {
            snprintf(path, sizeof(path), "/");
        }
    }

    char canonical_uri[URL_BUF_SZ];
    build_canonical_uri(path, canonical_uri, sizeof(canonical_uri));

    /* ── Build the signed headers list ── */
    /* Always include "host". Optionally include "content-type". */
    char signed_headers[256];
    if (content_type && content_type[0]) {
        snprintf(signed_headers, sizeof(signed_headers), "content-type;host");
    } else {
        snprintf(signed_headers, sizeof(signed_headers), "host");
    }

    /* URI-encode signed headers for query string */
    char signed_headers_encoded[512];
    s3__uri_encode(signed_headers, strlen(signed_headers),
                   signed_headers_encoded, sizeof(signed_headers_encoded), true);

    /* ── Build query string with all X-Amz-* params ── */
    s3_buf qbuf;
    s3_buf_init(&qbuf);

    /* Build query params — these will be sorted later via build_canonical_query,
     * but we also need the unsorted form for the final URL.
     * For simplicity, add them in sorted order by key already. */

    char expires_str[32];
    snprintf(expires_str, sizeof(expires_str), "%d", expires);

    /* Collect all query params, then sort */
    s3_buf_append_str(&qbuf, "X-Amz-Algorithm=AWS4-HMAC-SHA256");
    s3_buf_append_str(&qbuf, "&X-Amz-Credential=");
    s3_buf_append_str(&qbuf, credential_encoded);
    s3_buf_append_str(&qbuf, "&X-Amz-Date=");
    s3_buf_append_str(&qbuf, iso8601);
    s3_buf_append_str(&qbuf, "&X-Amz-Expires=");
    s3_buf_append_str(&qbuf, expires_str);

    if (c->session_token && c->session_token[0]) {
        char token_encoded[4096];
        s3__uri_encode(c->session_token, strlen(c->session_token),
                       token_encoded, sizeof(token_encoded), true);
        s3_buf_append_str(&qbuf, "&X-Amz-Security-Token=");
        s3_buf_append_str(&qbuf, token_encoded);
    }

    s3_buf_append_str(&qbuf, "&X-Amz-SignedHeaders=");
    s3_buf_append_str(&qbuf, signed_headers_encoded);

    /* Add extra query params if provided */
    if (extra_query && extra_query[0]) {
        s3_buf_append_str(&qbuf, "&");
        s3_buf_append_str(&qbuf, extra_query);
    }

    /* Build the canonical query string (sorted) */
    char canonical_query[URL_BUF_SZ];
    build_canonical_query(qbuf.data, canonical_query, sizeof(canonical_query));

    /* ── Build canonical headers ── */
    char canonical_headers[1024];
    if (content_type && content_type[0]) {
        snprintf(canonical_headers, sizeof(canonical_headers),
                 "content-type:%s\nhost:%s\n", content_type, host);
    } else {
        snprintf(canonical_headers, sizeof(canonical_headers),
                 "host:%s\n", host);
    }

    /* ── Build canonical request ── */
    char canonical_request[CANONICAL_BUF_SZ];
    int cr_len = snprintf(canonical_request, sizeof(canonical_request),
                          "%s\n%s\n%s\n%s\n%s\n%s",
                          method,
                          canonical_uri,
                          canonical_query,
                          canonical_headers,
                          signed_headers,
                          "UNSIGNED-PAYLOAD");
    if (cr_len < 0 || (size_t)cr_len >= sizeof(canonical_request)) {
        s3_buf_free(&qbuf);
        return -1;
    }

    S3_LOG_TRACE_(c, "Presign Canonical Request:\n%s", canonical_request);

    /* ── Build string to sign ── */
    char cr_hash[65];
    s3__sha256_hex(canonical_request, (size_t)cr_len, cr_hash);

    char string_to_sign[512];
    int sts_len = snprintf(string_to_sign, sizeof(string_to_sign),
                           "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                           iso8601, scope, cr_hash);
    if (sts_len < 0 || (size_t)sts_len >= sizeof(string_to_sign)) {
        s3_buf_free(&qbuf);
        return -1;
    }

    /* ── Derive signing key (with caching) ── */
    if (strcmp(c->signing_key_date, datestamp) != 0 ||
        strcmp(c->signing_key_region, c->region) != 0) {
        s3__derive_signing_key(c->secret_access_key, datestamp,
                               c->region, "s3", c->signing_key);
        memcpy(c->signing_key_date, datestamp, 9);
        snprintf(c->signing_key_region, sizeof(c->signing_key_region),
                 "%s", c->region);
    }

    /* ── Compute signature ── */
    uint8_t sig_raw[32];
    s3__hmac_sha256(c->signing_key, 32,
                    string_to_sign, (size_t)sts_len, sig_raw);

    char signature[65];
    to_hex(sig_raw, 32, signature);

    /* ── Build final URL ── */
    const char *scheme = c->use_https ? "https" : "http";

    int written = snprintf(url_buf, url_buf_size,
                           "%s://%s%s?%s&X-Amz-Signature=%s",
                           scheme, host, canonical_uri,
                           canonical_query, signature);

    s3_buf_free(&qbuf);

    if (written < 0 || (size_t)written >= url_buf_size) {
        S3_LOG_ERROR_(c, "presigned URL too large for buffer");
        return -1;
    }

    return 0;
}
