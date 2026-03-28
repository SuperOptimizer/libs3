/*
 * libs3 -- S3 Express One Zone (CreateSession)
 *
 * Implements the CreateSession API for S3 Express One Zone directory
 * buckets. Returns temporary session credentials for subsequent
 * data plane operations.
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

/* ═══════════════════════════════════════════════════════════════════════════
 * CreateSession
 *
 * GET /?session on a directory bucket.
 *
 * Request headers:
 *   x-amz-create-session-mode: ReadWrite | ReadOnly
 *   (optional SSE headers for server-side encryption)
 *
 * Response XML:
 *   <CreateSessionResult>
 *     <Credentials>
 *       <AccessKeyId>...</AccessKeyId>
 *       <SecretAccessKey>...</SecretAccessKey>
 *       <SessionToken>...</SessionToken>
 *       <Expiration>...</Expiration>
 *     </Credentials>
 *   </CreateSessionResult>
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_session(s3_client *c, const char *bucket,
                            s3_express_session_mode mode,
                            s3_session_credentials *result)
{
    if (!c || !bucket || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build headers */
    struct curl_slist *hdrs = nullptr;

    /* Session mode header */
    const char *mode_str = (mode == S3_SESSION_READ_ONLY)
                               ? "ReadOnly" : "ReadWrite";
    char mode_hdr[128];
    snprintf(mode_hdr, sizeof(mode_hdr),
             "x-amz-create-session-mode: %s", mode_str);
    hdrs = curl_slist_append(hdrs, mode_hdr);

    s3_request_params p = {
        .method            = "GET",
        .bucket            = bucket,
        .query_string      = "session",
        .extra_headers     = hdrs,
        .collect_response  = true,
    };

    s3_status st = s3__request(c, &p);
    curl_slist_free_all(hdrs);

    if (st != S3_STATUS_OK)
        return st;

    /* Parse the response XML */
    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    if (!xml || xml_len == 0)
        return S3_STATUS_INTERNAL_ERROR;

    /*
     * The credentials are nested under <Credentials> inside
     * <CreateSessionResult>. Try both nested and flat tag lookup
     * for robustness.
     */
    const char *cred_xml = xml;
    size_t cred_len = xml_len;

    /* Try to narrow to the <Credentials> block */
    const char *cred_start;
    size_t cred_start_len;
    if (s3__xml_find(xml, xml_len, "Credentials", &cred_start, &cred_start_len)) {
        /* s3__xml_find returns the inner content; we can search within it */
        cred_xml = cred_start;
        cred_len = cred_start_len;
    }

    xml_extract(cred_xml, cred_len, "AccessKeyId",
                result->access_key_id, sizeof(result->access_key_id));
    xml_extract(cred_xml, cred_len, "SecretAccessKey",
                result->secret_access_key, sizeof(result->secret_access_key));
    xml_extract(cred_xml, cred_len, "SessionToken",
                result->session_token, sizeof(result->session_token));
    xml_extract(cred_xml, cred_len, "Expiration",
                result->expiration, sizeof(result->expiration));

    /* Validate that we got at least the access key */
    if (result->access_key_id[0] == '\0')
        return S3_STATUS_INTERNAL_ERROR;

    return S3_STATUS_OK;
}
