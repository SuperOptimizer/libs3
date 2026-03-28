/*
 * libs3 -- Error handling implementation
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_status_string — human-readable string for every s3_status value
 * ═══════════════════════════════════════════════════════════════════════════ */

const char *s3_status_string(s3_status status)
{
    switch (status) {
    case S3_STATUS_OK:                                    return "OK";

    /* Client-side errors */
    case S3_STATUS_INVALID_ARGUMENT:                      return "Invalid argument";
    case S3_STATUS_OUT_OF_MEMORY:                         return "Out of memory";
    case S3_STATUS_INTERNAL_ERROR:                        return "Internal error";
    case S3_STATUS_NOT_INITIALIZED:                       return "Not initialized";
    case S3_STATUS_ABORTED_BY_CALLBACK:                   return "Aborted by callback";

    /* Network / curl errors */
    case S3_STATUS_CURL_ERROR:                            return "CURL error";
    case S3_STATUS_CONNECTION_FAILED:                     return "Connection failed";
    case S3_STATUS_DNS_RESOLUTION_FAILED:                 return "DNS resolution failed";
    case S3_STATUS_TIMEOUT:                               return "Request timed out";
    case S3_STATUS_SSL_ERROR:                             return "SSL error";

    /* S3 service errors */
    case S3_STATUS_ACCESS_DENIED:                         return "Access denied";
    case S3_STATUS_ACCOUNT_PROBLEM:                       return "Account problem";
    case S3_STATUS_ALL_ACCESS_DISABLED:                   return "All access disabled";
    case S3_STATUS_BUCKET_ALREADY_EXISTS:                 return "Bucket already exists";
    case S3_STATUS_BUCKET_ALREADY_OWNED_BY_YOU:           return "Bucket already owned by you";
    case S3_STATUS_BUCKET_NOT_EMPTY:                      return "Bucket not empty";
    case S3_STATUS_CREDENTIALS_NOT_SUPPORTED:             return "Credentials not supported";
    case S3_STATUS_CROSS_LOCATION_LOGGING_PROHIBITED:     return "Cross-location logging prohibited";
    case S3_STATUS_ENTITY_TOO_SMALL:                      return "Entity too small";
    case S3_STATUS_ENTITY_TOO_LARGE:                      return "Entity too large";
    case S3_STATUS_EXPIRED_TOKEN:                         return "Expired token";
    case S3_STATUS_ILLEGAL_LOCATION_CONSTRAINT:           return "Illegal location constraint";
    case S3_STATUS_ILLEGAL_VERSIONING_CONFIGURATION:      return "Illegal versioning configuration";
    case S3_STATUS_INCOMPLETE_BODY:                       return "Incomplete body";
    case S3_STATUS_INCORRECT_NUMBER_OF_FILES_IN_POST:     return "Incorrect number of files in POST";
    case S3_STATUS_INLINE_DATA_TOO_LARGE:                 return "Inline data too large";
    case S3_STATUS_INVALID_ACCESS_KEY_ID:                 return "Invalid access key ID";
    case S3_STATUS_INVALID_ARGUMENT_S3:                   return "Invalid argument (S3)";
    case S3_STATUS_INVALID_BUCKET_NAME:                   return "Invalid bucket name";
    case S3_STATUS_INVALID_BUCKET_STATE:                  return "Invalid bucket state";
    case S3_STATUS_INVALID_DIGEST:                        return "Invalid digest";
    case S3_STATUS_INVALID_ENCRYPTION_ALGORITHM:          return "Invalid encryption algorithm";
    case S3_STATUS_INVALID_LOCATION_CONSTRAINT:           return "Invalid location constraint";
    case S3_STATUS_INVALID_OBJECT_STATE:                  return "Invalid object state";
    case S3_STATUS_INVALID_PART:                          return "Invalid part";
    case S3_STATUS_INVALID_PART_ORDER:                    return "Invalid part order";
    case S3_STATUS_INVALID_PAYER:                         return "Invalid payer";
    case S3_STATUS_INVALID_POLICY_DOCUMENT:               return "Invalid policy document";
    case S3_STATUS_INVALID_RANGE:                         return "Invalid range";
    case S3_STATUS_INVALID_REQUEST:                       return "Invalid request";
    case S3_STATUS_INVALID_SECURITY:                      return "Invalid security";
    case S3_STATUS_INVALID_SOAP_REQUEST:                  return "Invalid SOAP request";
    case S3_STATUS_INVALID_STORAGE_CLASS:                 return "Invalid storage class";
    case S3_STATUS_INVALID_TARGET_BUCKET_FOR_LOGGING:     return "Invalid target bucket for logging";
    case S3_STATUS_INVALID_TOKEN:                         return "Invalid token";
    case S3_STATUS_INVALID_URI:                           return "Invalid URI";
    case S3_STATUS_KEY_TOO_LONG:                          return "Key too long";
    case S3_STATUS_MALFORMED_ACL:                         return "Malformed ACL";
    case S3_STATUS_MALFORMED_POST_REQUEST:                return "Malformed POST request";
    case S3_STATUS_MALFORMED_XML:                         return "Malformed XML";
    case S3_STATUS_MAX_MESSAGE_LENGTH_EXCEEDED:           return "Max message length exceeded";
    case S3_STATUS_MAX_POST_PRE_DATA_LENGTH_EXCEEDED:     return "Max POST pre-data length exceeded";
    case S3_STATUS_METADATA_TOO_LARGE:                    return "Metadata too large";
    case S3_STATUS_METHOD_NOT_ALLOWED:                    return "Method not allowed";
    case S3_STATUS_MISSING_ATTACHMENT:                    return "Missing attachment";
    case S3_STATUS_MISSING_CONTENT_LENGTH:                return "Missing content length";
    case S3_STATUS_MISSING_REQUEST_BODY:                  return "Missing request body";
    case S3_STATUS_MISSING_SECURITY_ELEMENT:              return "Missing security element";
    case S3_STATUS_MISSING_SECURITY_HEADER:               return "Missing security header";
    case S3_STATUS_NO_LOGGING_STATUS_FOR_KEY:             return "No logging status for key";
    case S3_STATUS_NO_SUCH_BUCKET:                        return "No such bucket";
    case S3_STATUS_NO_SUCH_BUCKET_POLICY:                 return "No such bucket policy";
    case S3_STATUS_NO_SUCH_CORS_CONFIGURATION:            return "No such CORS configuration";
    case S3_STATUS_NO_SUCH_KEY:                           return "No such key";
    case S3_STATUS_NO_SUCH_LIFECYCLE_CONFIGURATION:       return "No such lifecycle configuration";
    case S3_STATUS_NO_SUCH_UPLOAD:                        return "No such upload";
    case S3_STATUS_NO_SUCH_VERSION:                       return "No such version";
    case S3_STATUS_NO_SUCH_WEBSITE_CONFIGURATION:         return "No such website configuration";
    case S3_STATUS_NO_SUCH_TAG_SET:                       return "No such tag set";
    case S3_STATUS_NO_SUCH_ACCESS_POINT:                  return "No such access point";
    case S3_STATUS_NOT_IMPLEMENTED_S3:                    return "Not implemented (S3)";
    case S3_STATUS_NOT_SIGNED_UP:                         return "Not signed up";
    case S3_STATUS_OPERATION_ABORTED:                     return "Operation aborted";
    case S3_STATUS_PERMANENT_REDIRECT:                    return "Permanent redirect";
    case S3_STATUS_PRECONDITION_FAILED:                   return "Precondition failed";
    case S3_STATUS_REDIRECT:                              return "Redirect";
    case S3_STATUS_REQUEST_IS_NOT_MULTI_PART_CONTENT:     return "Request is not multi-part content";
    case S3_STATUS_REQUEST_TIMEOUT:                       return "Request timeout";
    case S3_STATUS_REQUEST_TIME_TOO_SKEWED:               return "Request time too skewed";
    case S3_STATUS_REQUEST_TORRENT_OF_BUCKET:             return "Request torrent of bucket";
    case S3_STATUS_RESTORE_ALREADY_IN_PROGRESS:           return "Restore already in progress";
    case S3_STATUS_SERVER_SIDE_ENCRYPTION_CONFIG_NOT_FOUND: return "Server-side encryption configuration not found";
    case S3_STATUS_SERVICE_UNAVAILABLE:                   return "Service unavailable";
    case S3_STATUS_SIGNATURE_DOES_NOT_MATCH:              return "Signature does not match";
    case S3_STATUS_SLOW_DOWN:                             return "Slow down";
    case S3_STATUS_TEMPORARY_REDIRECT:                    return "Temporary redirect";
    case S3_STATUS_TOKEN_REFRESH_REQUIRED:                return "Token refresh required";
    case S3_STATUS_TOO_MANY_BUCKETS:                      return "Too many buckets";
    case S3_STATUS_UNEXPECTED_CONTENT:                    return "Unexpected content";
    case S3_STATUS_UNRESOLVABLE_GRANT_BY_EMAIL:           return "Unresolvable grant by email";
    case S3_STATUS_USER_KEY_MUST_BE_SPECIFIED:             return "User key must be specified";
    case S3_STATUS_NOT_MODIFIED:                          return "Not modified";
    case S3_STATUS_INVALID_TAG:                           return "Invalid tag";

    /* HTTP-only fallbacks */
    case S3_STATUS_HTTP_BAD_REQUEST:                      return "HTTP 400 Bad Request";
    case S3_STATUS_HTTP_FORBIDDEN:                        return "HTTP 403 Forbidden";
    case S3_STATUS_HTTP_NOT_FOUND:                        return "HTTP 404 Not Found";
    case S3_STATUS_HTTP_CONFLICT:                         return "HTTP 409 Conflict";
    case S3_STATUS_HTTP_LENGTH_REQUIRED:                  return "HTTP 411 Length Required";
    case S3_STATUS_HTTP_RANGE_NOT_SATISFIABLE:            return "HTTP 416 Range Not Satisfiable";
    case S3_STATUS_HTTP_INTERNAL_SERVER_ERROR:            return "HTTP 500 Internal Server Error";
    case S3_STATUS_HTTP_NOT_IMPLEMENTED:                  return "HTTP 501 Not Implemented";
    case S3_STATUS_HTTP_BAD_GATEWAY:                      return "HTTP 502 Bad Gateway";
    case S3_STATUS_HTTP_SERVICE_UNAVAILABLE:              return "HTTP 503 Service Unavailable";
    case S3_STATUS_HTTP_GATEWAY_TIMEOUT:                  return "HTTP 504 Gateway Timeout";

    case S3_STATUS_UNKNOWN_ERROR:                         return "Unknown error";
    case S3_STATUS__COUNT:                                break;
    }
    return "Unknown status";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__map_s3_error_code — map S3 XML error code string to s3_status
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *code;
    s3_status   status;
} s3_error_code_entry;

static const s3_error_code_entry s3_error_code_table[] = {
    { "AccessDenied",                          S3_STATUS_ACCESS_DENIED },
    { "AccountProblem",                        S3_STATUS_ACCOUNT_PROBLEM },
    { "AllAccessDisabled",                     S3_STATUS_ALL_ACCESS_DISABLED },
    { "BucketAlreadyExists",                   S3_STATUS_BUCKET_ALREADY_EXISTS },
    { "BucketAlreadyOwnedByYou",               S3_STATUS_BUCKET_ALREADY_OWNED_BY_YOU },
    { "BucketNotEmpty",                        S3_STATUS_BUCKET_NOT_EMPTY },
    { "CredentialsNotSupported",               S3_STATUS_CREDENTIALS_NOT_SUPPORTED },
    { "CrossLocationLoggingProhibited",        S3_STATUS_CROSS_LOCATION_LOGGING_PROHIBITED },
    { "EntityTooSmall",                        S3_STATUS_ENTITY_TOO_SMALL },
    { "EntityTooLarge",                        S3_STATUS_ENTITY_TOO_LARGE },
    { "ExpiredToken",                          S3_STATUS_EXPIRED_TOKEN },
    { "IllegalLocationConstraintException",    S3_STATUS_ILLEGAL_LOCATION_CONSTRAINT },
    { "IllegalVersioningConfigurationException", S3_STATUS_ILLEGAL_VERSIONING_CONFIGURATION },
    { "IncompleteBody",                        S3_STATUS_INCOMPLETE_BODY },
    { "IncorrectNumberOfFilesInPostRequest",   S3_STATUS_INCORRECT_NUMBER_OF_FILES_IN_POST },
    { "InlineDataTooLarge",                    S3_STATUS_INLINE_DATA_TOO_LARGE },
    { "InvalidAccessKeyId",                    S3_STATUS_INVALID_ACCESS_KEY_ID },
    { "InvalidArgument",                       S3_STATUS_INVALID_ARGUMENT_S3 },
    { "InvalidBucketName",                     S3_STATUS_INVALID_BUCKET_NAME },
    { "InvalidBucketState",                    S3_STATUS_INVALID_BUCKET_STATE },
    { "InvalidDigest",                         S3_STATUS_INVALID_DIGEST },
    { "InvalidEncryptionAlgorithmError",       S3_STATUS_INVALID_ENCRYPTION_ALGORITHM },
    { "InvalidLocationConstraint",             S3_STATUS_INVALID_LOCATION_CONSTRAINT },
    { "InvalidObjectState",                    S3_STATUS_INVALID_OBJECT_STATE },
    { "InvalidPart",                           S3_STATUS_INVALID_PART },
    { "InvalidPartOrder",                      S3_STATUS_INVALID_PART_ORDER },
    { "InvalidPayer",                          S3_STATUS_INVALID_PAYER },
    { "InvalidPolicyDocument",                 S3_STATUS_INVALID_POLICY_DOCUMENT },
    { "InvalidRange",                          S3_STATUS_INVALID_RANGE },
    { "InvalidRequest",                        S3_STATUS_INVALID_REQUEST },
    { "InvalidSecurity",                       S3_STATUS_INVALID_SECURITY },
    { "InvalidSOAPRequest",                    S3_STATUS_INVALID_SOAP_REQUEST },
    { "InvalidStorageClass",                   S3_STATUS_INVALID_STORAGE_CLASS },
    { "InvalidTargetBucketForLogging",         S3_STATUS_INVALID_TARGET_BUCKET_FOR_LOGGING },
    { "InvalidToken",                          S3_STATUS_INVALID_TOKEN },
    { "InvalidURI",                            S3_STATUS_INVALID_URI },
    { "KeyTooLongError",                       S3_STATUS_KEY_TOO_LONG },
    { "MalformedACLError",                     S3_STATUS_MALFORMED_ACL },
    { "MalformedPOSTRequest",                  S3_STATUS_MALFORMED_POST_REQUEST },
    { "MalformedXML",                          S3_STATUS_MALFORMED_XML },
    { "MaxMessageLengthExceeded",              S3_STATUS_MAX_MESSAGE_LENGTH_EXCEEDED },
    { "MaxPostPreDataLengthExceededError",     S3_STATUS_MAX_POST_PRE_DATA_LENGTH_EXCEEDED },
    { "MetadataTooLarge",                      S3_STATUS_METADATA_TOO_LARGE },
    { "MethodNotAllowed",                      S3_STATUS_METHOD_NOT_ALLOWED },
    { "MissingAttachment",                     S3_STATUS_MISSING_ATTACHMENT },
    { "MissingContentLength",                  S3_STATUS_MISSING_CONTENT_LENGTH },
    { "MissingRequestBodyError",               S3_STATUS_MISSING_REQUEST_BODY },
    { "MissingSecurityElement",                S3_STATUS_MISSING_SECURITY_ELEMENT },
    { "MissingSecurityHeader",                 S3_STATUS_MISSING_SECURITY_HEADER },
    { "NoLoggingStatusForKey",                 S3_STATUS_NO_LOGGING_STATUS_FOR_KEY },
    { "NoSuchBucket",                          S3_STATUS_NO_SUCH_BUCKET },
    { "NoSuchBucketPolicy",                    S3_STATUS_NO_SUCH_BUCKET_POLICY },
    { "NoSuchCORSConfiguration",               S3_STATUS_NO_SUCH_CORS_CONFIGURATION },
    { "NoSuchKey",                             S3_STATUS_NO_SUCH_KEY },
    { "NoSuchLifecycleConfiguration",          S3_STATUS_NO_SUCH_LIFECYCLE_CONFIGURATION },
    { "NoSuchUpload",                          S3_STATUS_NO_SUCH_UPLOAD },
    { "NoSuchVersion",                         S3_STATUS_NO_SUCH_VERSION },
    { "NoSuchWebsiteConfiguration",            S3_STATUS_NO_SUCH_WEBSITE_CONFIGURATION },
    { "NoSuchTagSet",                          S3_STATUS_NO_SUCH_TAG_SET },
    { "NoSuchAccessPoint",                     S3_STATUS_NO_SUCH_ACCESS_POINT },
    { "NotImplemented",                        S3_STATUS_NOT_IMPLEMENTED_S3 },
    { "NotSignedUp",                           S3_STATUS_NOT_SIGNED_UP },
    { "OperationAborted",                      S3_STATUS_OPERATION_ABORTED },
    { "PermanentRedirect",                     S3_STATUS_PERMANENT_REDIRECT },
    { "PreconditionFailed",                    S3_STATUS_PRECONDITION_FAILED },
    { "Redirect",                              S3_STATUS_REDIRECT },
    { "RequestIsNotMultiPartContent",          S3_STATUS_REQUEST_IS_NOT_MULTI_PART_CONTENT },
    { "RequestTimeout",                        S3_STATUS_REQUEST_TIMEOUT },
    { "RequestTimeTooSkewed",                  S3_STATUS_REQUEST_TIME_TOO_SKEWED },
    { "RequestTorrentOfBucketError",           S3_STATUS_REQUEST_TORRENT_OF_BUCKET },
    { "RestoreAlreadyInProgress",              S3_STATUS_RESTORE_ALREADY_IN_PROGRESS },
    { "ServerSideEncryptionConfigurationNotFoundError", S3_STATUS_SERVER_SIDE_ENCRYPTION_CONFIG_NOT_FOUND },
    { "ServiceUnavailable",                    S3_STATUS_SERVICE_UNAVAILABLE },
    { "SignatureDoesNotMatch",                 S3_STATUS_SIGNATURE_DOES_NOT_MATCH },
    { "SlowDown",                              S3_STATUS_SLOW_DOWN },
    { "TemporaryRedirect",                     S3_STATUS_TEMPORARY_REDIRECT },
    { "TokenRefreshRequired",                  S3_STATUS_TOKEN_REFRESH_REQUIRED },
    { "TooManyBuckets",                        S3_STATUS_TOO_MANY_BUCKETS },
    { "UnexpectedContent",                     S3_STATUS_UNEXPECTED_CONTENT },
    { "UnresolvableGrantByEmailAddress",       S3_STATUS_UNRESOLVABLE_GRANT_BY_EMAIL },
    { "UserKeyMustBeSpecified",                S3_STATUS_USER_KEY_MUST_BE_SPECIFIED },
    { "InvalidTag",                            S3_STATUS_INVALID_TAG },
};

s3_status s3__map_s3_error_code(const char *code)
{
    if (!code)
        return S3_STATUS_UNKNOWN_ERROR;

    for (size_t i = 0; i < S3_ARRAY_LEN(s3_error_code_table); i++) {
        if (strcmp(s3_error_code_table[i].code, code) == 0)
            return s3_error_code_table[i].status;
    }
    return S3_STATUS_UNKNOWN_ERROR;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__map_http_status — map HTTP status code to s3_status
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3__map_http_status(int http_status)
{
    switch (http_status) {
    case 304: return S3_STATUS_NOT_MODIFIED;
    case 400: return S3_STATUS_HTTP_BAD_REQUEST;
    case 403: return S3_STATUS_HTTP_FORBIDDEN;
    case 404: return S3_STATUS_HTTP_NOT_FOUND;
    case 405: return S3_STATUS_METHOD_NOT_ALLOWED;
    case 409: return S3_STATUS_HTTP_CONFLICT;
    case 411: return S3_STATUS_HTTP_LENGTH_REQUIRED;
    case 412: return S3_STATUS_PRECONDITION_FAILED;
    case 416: return S3_STATUS_HTTP_RANGE_NOT_SATISFIABLE;
    case 500: return S3_STATUS_HTTP_INTERNAL_SERVER_ERROR;
    case 501: return S3_STATUS_HTTP_NOT_IMPLEMENTED;
    case 502: return S3_STATUS_HTTP_BAD_GATEWAY;
    case 503: return S3_STATUS_HTTP_SERVICE_UNAVAILABLE;
    case 504: return S3_STATUS_HTTP_GATEWAY_TIMEOUT;
    default:  return S3_STATUS_UNKNOWN_ERROR;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__parse_error_response — parse S3 XML error body, populate last_error
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3__parse_error_response(s3_client *c, long http_status)
{
    s3__clear_error(c);
    c->last_error.http_status = (int)http_status;

    /* If there's no response body, fall back to HTTP status mapping */
    if (!c->response.data || c->response.len == 0) {
        c->last_error.status = s3__map_http_status((int)http_status);
        return c->last_error.status;
    }

    const char *xml = c->response.data;
    size_t xml_len = c->response.len;

    const char *val = nullptr;
    size_t val_len = 0;

    /* Extract <Code> */
    char code_buf[64] = {0};
    if (s3__xml_find(xml, xml_len, "Code", &val, &val_len)) {
        size_t copy_len = S3_MIN(val_len, sizeof(code_buf) - 1);
        memcpy(code_buf, val, copy_len);
        code_buf[copy_len] = '\0';
        snprintf(c->last_error.s3_code, sizeof(c->last_error.s3_code), "%s", code_buf);
    }

    /* Extract <Message> */
    if (s3__xml_find(xml, xml_len, "Message", &val, &val_len)) {
        size_t copy_len = S3_MIN(val_len, sizeof(c->last_error.s3_message) - 1);
        memcpy(c->last_error.s3_message, val, copy_len);
        c->last_error.s3_message[copy_len] = '\0';
    }

    /* Extract <RequestId> */
    if (s3__xml_find(xml, xml_len, "RequestId", &val, &val_len)) {
        size_t copy_len = S3_MIN(val_len, sizeof(c->last_error.s3_request_id) - 1);
        memcpy(c->last_error.s3_request_id, val, copy_len);
        c->last_error.s3_request_id[copy_len] = '\0';
    }

    /* Extract <HostId> */
    if (s3__xml_find(xml, xml_len, "HostId", &val, &val_len)) {
        size_t copy_len = S3_MIN(val_len, sizeof(c->last_error.s3_host_id) - 1);
        memcpy(c->last_error.s3_host_id, val, copy_len);
        c->last_error.s3_host_id[copy_len] = '\0';
    }

    /* Map the error code to a status enum, or fall back to HTTP status */
    if (code_buf[0] != '\0') {
        c->last_error.status = s3__map_s3_error_code(code_buf);
    } else {
        c->last_error.status = s3__map_http_status((int)http_status);
    }

    return c->last_error.status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__set_error — set client's last_error fields directly
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__set_error(s3_client *c, s3_status status, int http_status,
                   const char *s3_code, const char *s3_message)
{
    s3__clear_error(c);
    c->last_error.status = status;
    c->last_error.http_status = http_status;

    if (s3_code) {
        snprintf(c->last_error.s3_code, sizeof(c->last_error.s3_code), "%s", s3_code);
    }
    if (s3_message) {
        snprintf(c->last_error.s3_message, sizeof(c->last_error.s3_message), "%s", s3_message);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__set_curl_error — set last_error from a curl error code
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__set_curl_error(s3_client *c, long curl_code)
{
    s3__clear_error(c);
    c->last_error.status = S3_STATUS_CURL_ERROR;
    c->last_error.curl_code = curl_code;

    /* Copy the curl error buffer if it has content, otherwise use curl_easy_strerror */
    if (c->curl_errbuf[0] != '\0') {
        snprintf(c->last_error.curl_error, sizeof(c->last_error.curl_error),
                 "%s", c->curl_errbuf);
    } else {
        snprintf(c->last_error.curl_error, sizeof(c->last_error.curl_error),
                 "%s", curl_easy_strerror((CURLcode)curl_code));
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3__clear_error — zero out the last_error
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3__clear_error(s3_client *c)
{
    memset(&c->last_error, 0, sizeof(c->last_error));
}
