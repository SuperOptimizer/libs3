#include "s3_internal.h"

struct curl_slist *s3__apply_sse_headers(struct curl_slist *headers,
                                         const s3_encryption *enc) {
    if (!enc || enc->mode == S3_SSE_NONE) return headers;

    char buf[512];

    switch (enc->mode) {
    case S3_SSE_S3:
        headers = curl_slist_append(headers, "x-amz-server-side-encryption: AES256");
        break;

    case S3_SSE_KMS:
        headers = curl_slist_append(headers, "x-amz-server-side-encryption: aws:kms");
        if (enc->kms_key_id) {
            snprintf(buf, sizeof(buf),
                     "x-amz-server-side-encryption-aws-kms-key-id: %s", enc->kms_key_id);
            headers = curl_slist_append(headers, buf);
        }
        if (enc->kms_context) {
            snprintf(buf, sizeof(buf),
                     "x-amz-server-side-encryption-context: %s", enc->kms_context);
            headers = curl_slist_append(headers, buf);
        }
        if (enc->bucket_key_enabled) {
            headers = curl_slist_append(headers,
                "x-amz-server-side-encryption-bucket-key-enabled: true");
        }
        break;

    case S3_SSE_C: {
        headers = curl_slist_append(headers,
            "x-amz-server-side-encryption-customer-algorithm: AES256");

        if (enc->customer_key) {
            char key_b64[64];
            s3__base64_encode(enc->customer_key, 32, key_b64, sizeof(key_b64));
            snprintf(buf, sizeof(buf),
                     "x-amz-server-side-encryption-customer-key: %s", key_b64);
            headers = curl_slist_append(headers, buf);
        }
        if (enc->customer_key_md5) {
            char md5_b64[32];
            s3__base64_encode(enc->customer_key_md5, 16, md5_b64, sizeof(md5_b64));
            snprintf(buf, sizeof(buf),
                     "x-amz-server-side-encryption-customer-key-MD5: %s", md5_b64);
            headers = curl_slist_append(headers, buf);
        }
        break;
    }

    default:
        break;
    }

    return headers;
}

struct curl_slist *s3__apply_source_sse_headers(struct curl_slist *headers,
                                                const s3_encryption *enc) {
    if (!enc || enc->mode != S3_SSE_C) return headers;

    char buf[512];

    headers = curl_slist_append(headers,
        "x-amz-copy-source-server-side-encryption-customer-algorithm: AES256");

    if (enc->customer_key) {
        char key_b64[64];
        s3__base64_encode(enc->customer_key, 32, key_b64, sizeof(key_b64));
        snprintf(buf, sizeof(buf),
                 "x-amz-copy-source-server-side-encryption-customer-key: %s", key_b64);
        headers = curl_slist_append(headers, buf);
    }
    if (enc->customer_key_md5) {
        char md5_b64[32];
        s3__base64_encode(enc->customer_key_md5, 16, md5_b64, sizeof(md5_b64));
        snprintf(buf, sizeof(buf),
                 "x-amz-copy-source-server-side-encryption-customer-key-MD5: %s", md5_b64);
        headers = curl_slist_append(headers, buf);
    }

    return headers;
}
