/*
 * libs3 -- Presigned URL generation
 *
 * Thin wrappers around s3__presign_url (from s3_sigv4.c) for each HTTP method.
 */

#include "s3_internal.h"

/* Maximum presigned URL expiration per the S3 SigV4 spec: 7 days. */
#define S3_PRESIGN_MAX_EXPIRES 604800

s3_status s3_presign_get(s3_client *c, const char *bucket, const char *key,
                         int expires_seconds, char *url_buf, size_t url_buf_size)
{
    if (!c || !bucket || !key || !url_buf || url_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;
    if (expires_seconds < 1 || expires_seconds > S3_PRESIGN_MAX_EXPIRES)
        return S3_STATUS_INVALID_ARGUMENT;

    int rc = s3__presign_url(c, "GET", bucket, key,
                             expires_seconds, nullptr, nullptr,
                             url_buf, url_buf_size);
    return rc == 0 ? S3_STATUS_OK : S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_presign_put(s3_client *c, const char *bucket, const char *key,
                         int expires_seconds, const char *content_type,
                         char *url_buf, size_t url_buf_size)
{
    if (!c || !bucket || !key || !url_buf || url_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;
    if (expires_seconds < 1 || expires_seconds > S3_PRESIGN_MAX_EXPIRES)
        return S3_STATUS_INVALID_ARGUMENT;

    int rc = s3__presign_url(c, "PUT", bucket, key,
                             expires_seconds, content_type, nullptr,
                             url_buf, url_buf_size);
    return rc == 0 ? S3_STATUS_OK : S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_presign_delete(s3_client *c, const char *bucket, const char *key,
                            int expires_seconds, char *url_buf, size_t url_buf_size)
{
    if (!c || !bucket || !key || !url_buf || url_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;
    if (expires_seconds < 1 || expires_seconds > S3_PRESIGN_MAX_EXPIRES)
        return S3_STATUS_INVALID_ARGUMENT;

    int rc = s3__presign_url(c, "DELETE", bucket, key,
                             expires_seconds, nullptr, nullptr,
                             url_buf, url_buf_size);
    return rc == 0 ? S3_STATUS_OK : S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_presign_head(s3_client *c, const char *bucket, const char *key,
                          int expires_seconds, char *url_buf, size_t url_buf_size)
{
    if (!c || !bucket || !key || !url_buf || url_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;
    if (expires_seconds < 1 || expires_seconds > S3_PRESIGN_MAX_EXPIRES)
        return S3_STATUS_INVALID_ARGUMENT;

    int rc = s3__presign_url(c, "HEAD", bucket, key,
                             expires_seconds, nullptr, nullptr,
                             url_buf, url_buf_size);
    return rc == 0 ? S3_STATUS_OK : S3_STATUS_INTERNAL_ERROR;
}
