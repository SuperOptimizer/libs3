# libs3 — Exhaustive Implementation Plan

Pure C23 S3 library built on libcurl. Covers the **entire** Amazon S3 API surface (~350+ operations).

## Architecture

```
s3.h                 — All public types, enums, structs, function declarations
src/
  s3_internal.h      — Internal shared types, macros, helper declarations
  s3_crypto.c        — SHA-256, HMAC-SHA256, CRC32, CRC32C, SHA-1, Base64, URI encoding
  s3_xml.c           — Minimal XML pull parser + XML builder for request bodies
  s3_sigv4.c         — AWS Signature V4 signing (headers + query string presigning)
  s3_http.c          — libcurl integration, URL builder, request dispatcher, header mgmt
  s3_error.c         — S3 XML error parsing, error code → enum mapping
  s3_client.c        — Client lifecycle, config deep-copy, credential management
  s3_async.c         — curl_multi event loop, futures, completion dispatch
  s3_pool.c          — Thread pool, work queue, per-worker curl handles
  s3_retry.c         — Exponential backoff + jitter, retry policy engine
  s3_log.c           — Logging/tracing callbacks
  s3_object.c        — Object CRUD (put/get/delete/head/copy/rename/attributes)
  s3_object_config.c — Object tagging, ACL, legal hold, retention, restore
  s3_list.c          — ListObjectsV2, ListObjectVersions, ListObjectsV1
  s3_multipart.c     — Multipart upload operations
  s3_bucket.c        — Bucket CRUD (create/delete/head/list/location)
  s3_bucket_config.c — All bucket configuration APIs
  s3_presign.c       — Presigned URL generation
  s3_select.c        — SelectObjectContent
  s3_checksum.c      — CRC32, CRC32C, SHA-1, SHA-256 trailing checksums
  s3_sse.c           — SSE-S3, SSE-KMS, SSE-C header helpers
  s3_highlevel.c     — upload_file, download_file, copy_large, sync, etc.
  s3_control.c       — S3 Control API base (different endpoint: s3-control.{region}.amazonaws.com)
  s3_access_point.c  — Access point CRUD + policies
  s3_object_lambda.c — Object Lambda access points
  s3_access_grants.c — Access grants, instances, locations, identity center
  s3_mrap.c          — Multi-Region Access Points
  s3_batch.c         — S3 Batch Operations / Jobs
  s3_storage_lens.c  — Storage Lens configurations + groups
  s3_express.c       — S3 Express One Zone / directory buckets / CreateSession
  s3_tables.c        — S3 Tables (table buckets, namespaces, tables)
  s3_vectors.c       — S3 Vectors (vector buckets, indexes, vector CRUD)
  s3_outposts.c      — S3 on Outposts (endpoints)
tests/
  test_crypto.c      — SHA-256, HMAC, CRC32, Base64, URI encoding (NIST/RFC vectors)
  test_sigv4.c       — Signing against AWS documented examples
  test_xml.c         — Parse sample S3 XML responses
  test_unit.c        — Unit test runner (offline, no network)
  test_integration.c — Full integration tests against MinIO or AWS
  Makefile
examples/
  example_basic.c    — put/get/delete/list
  example_multipart.c— multipart upload
  example_async.c    — async operations with futures
  example_pool.c     — thread pool parallel uploads
  example_presign.c  — presigned URLs
CMakeLists.txt
Makefile
```

## Dependencies

| Dependency | Role | Required |
|---|---|---|
| libcurl | HTTP transport | Yes |
| pthreads | Threading, mutexes, condvars | Yes (for async/pool) |
| libc | Standard C library | Yes |
| (none) | SHA-256, HMAC, CRC32, Base64 all inline | — |

No OpenSSL. All crypto implemented inline.

## C23 Features

| Feature | Usage |
|---|---|
| `nullptr` | All null pointer values |
| `bool` | Direct keyword, no stdbool.h |
| `[[nodiscard]]` | Every function returning `s3_status` |
| `[[maybe_unused]]` | Internal helpers, callback params |
| `constexpr` | SHA-256 K[64], CRC tables, Base64 alphabet |
| `typeof` | Type-safe internal macros (MIN/MAX/container_of) |
| `auto` | Local type inference where clear |
| `static_assert` | Compile-time checks (no message form) |
| `{}` | Zero-initialization everywhere |
| `_Atomic` | Future state, pool shutdown flag |
| `_BitInt` | Not used (no benefit here) |
| `#embed` | Not used initially |

Fallback macros for C11/C17 compat provided via `S3_C23` detection.

## Threading Model

- Each `s3_client` is **not thread-safe** — one client per thread, or external sync
- `s3_pool` manages N workers, each with their own `s3_client` + CURL handle
- `s3_event_loop` runs curl_multi in a dedicated thread (or manual poll mode)
- `s3_future` uses `_Atomic` state + mutex/condvar for wait
- All pool/async APIs are thread-safe

## Error Model

Every function returns `s3_status` (enum). Detailed error via `s3_client_last_error()`:

```c
typedef struct s3_error {
    s3_status   status;
    int         http_status;
    char        s3_code[64];
    char        s3_message[512];
    char        s3_request_id[128];
    char        s3_host_id[256];
    char        curl_error[CURL_ERROR_SIZE];
    long        curl_code;
} s3_error;
```

## Retry Policy

```c
typedef struct s3_retry_policy {
    int     max_retries;         // default 3
    int     base_delay_ms;       // default 100
    int     max_delay_ms;        // default 20000
    double  backoff_multiplier;  // default 2.0
    bool    jitter;              // default true
    bool    retry_on_throttle;   // default true (SlowDown, 503)
    bool    retry_on_5xx;        // default true
    bool    retry_on_timeout;    // default true
} s3_retry_policy;
```

---

# Implementation Checklist

## Phase 0: Project Skeleton
- [ ] `s3.h` — include guard, C23 detection macros, linkage macros, attribute macros
- [ ] `s3.h` — custom allocator hook macros (S3_MALLOC, S3_REALLOC, S3_FREE)
- [ ] `src/s3_internal.h` — internal macros, shared internal types
- [ ] `CMakeLists.txt` — build system
- [ ] `Makefile` — simple make fallback

## Phase 1: Crypto Primitives (`src/s3_crypto.c`)
- [ ] SHA-256 implementation (FIPS 180-4)
  - [ ] `s3__sha256_init`, `s3__sha256_update`, `s3__sha256_final`
  - [ ] `s3__sha256` convenience (single-shot)
  - [ ] `s3__sha256_hex` (output as 64-char hex string)
  - [ ] Test against NIST test vectors
- [ ] HMAC-SHA256 (RFC 2104)
  - [ ] `s3__hmac_sha256`
  - [ ] Test against RFC 4231 test vectors (all 7 cases)
- [ ] SHA-1 implementation (for SHA-1 checksum support)
  - [ ] `s3__sha1_init`, `s3__sha1_update`, `s3__sha1_final`
  - [ ] `s3__sha1` convenience
  - [ ] Test against FIPS 180-4 SHA-1 vectors
- [ ] CRC32 (ISO 3309 / ITU-T V.42, polynomial 0xEDB88320)
  - [ ] `s3__crc32` with lookup table
  - [ ] Test against known vectors
- [ ] CRC32C (Castagnoli, polynomial 0x82F63B78)
  - [ ] `s3__crc32c` with lookup table
  - [ ] Test against known vectors
- [ ] Base64 encoding
  - [ ] `s3__base64_encode`
  - [ ] `s3__base64_decode` (needed for some response parsing)
  - [ ] Test against RFC 4648 vectors
- [ ] URI encoding (AWS-specific rules)
  - [ ] `s3__uri_encode` (unreserved chars: A-Z a-z 0-9 - . _ ~)
  - [ ] `s3__uri_encode_path` (same but preserves /)
  - [ ] Test edge cases: spaces, unicode, $, &, etc.
- [ ] Hex encoding
  - [ ] `s3__hex_encode` (lowercase)
  - [ ] `s3__hex_decode`

## Phase 2: XML Engine (`src/s3_xml.c`)
- [ ] XML pull parser (no DOM, no allocation for simple extractions)
  - [ ] `s3__xml_find` — find `<tag>content</tag>`, return content pointer + length
  - [ ] `s3__xml_find_nested` — find tag within a parent tag context
  - [ ] `s3__xml_each` — iterate repeated child elements with callback
  - [ ] `s3__xml_attr` — extract attribute value from opening tag
  - [ ] Entity decoding: `&amp;` `&lt;` `&gt;` `&quot;` `&apos;` `&#NNN;` `&#xHH;`
  - [ ] Test against sample S3 response XMLs (error, list, multipart, etc.)
- [ ] XML builder (for PUT/POST request bodies)
  - [ ] `s3__xml_buf` — growable buffer
  - [ ] `s3__xml_open`, `s3__xml_close`, `s3__xml_text`, `s3__xml_element`
  - [ ] `s3__xml_declaration` (<?xml version="1.0" encoding="UTF-8"?>)
  - [ ] Entity encoding for text content
  - [ ] Test round-trip: build → parse → verify

## Phase 3: SigV4 Signing Engine (`src/s3_sigv4.c`)
- [ ] Canonical URI construction
  - [ ] Path normalization (double-encode except for path separators)
- [ ] Canonical query string construction
  - [ ] Sort query params, URI-encode keys and values
- [ ] Canonical headers construction
  - [ ] Lowercase header names, trim values, sort, semicolon-separated signed list
- [ ] Canonical request assembly
  - [ ] METHOD + \n + URI + \n + Query + \n + Headers + \n + SignedHeaders + \n + PayloadHash
- [ ] String-to-sign construction
  - [ ] "AWS4-HMAC-SHA256" + \n + timestamp + \n + scope + \n + hash(canonical)
- [ ] Signing key derivation
  - [ ] HMAC chain: "AWS4" + secret → date → region → service → "aws4_request"
  - [ ] Signing key caching (reuse within same date+region+service)
- [ ] Authorization header assembly
  - [ ] `s3__sign_request` — top-level: computes everything, appends Authorization header
- [ ] Presigned URL signing (query string auth)
  - [ ] `s3__presign_url` — X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature
- [ ] S3-specific payload hashing
  - [ ] `UNSIGNED-PAYLOAD` for streaming / presigned
  - [ ] `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` for chunked
  - [ ] Actual SHA-256 hex for known payloads
- [ ] Test against AWS Signature V4 test suite
  - [ ] GET /test.txt example
  - [ ] PUT /test$file.text example
  - [ ] GET with query parameters
  - [ ] POST with headers

## Phase 4: HTTP Layer (`src/s3_http.c`)
- [ ] URL builder
  - [ ] Virtual-hosted style: `https://{bucket}.s3.{region}.amazonaws.com/{key}`
  - [ ] Path style: `https://s3.{region}.amazonaws.com/{bucket}/{key}`
  - [ ] Custom endpoint support
  - [ ] S3 Transfer Acceleration: `https://{bucket}.s3-accelerate.amazonaws.com/{key}`
  - [ ] Dual-stack: `https://{bucket}.s3.dualstack.{region}.amazonaws.com/{key}`
  - [ ] FIPS: `https://{bucket}.s3-fips.{region}.amazonaws.com/{key}`
  - [ ] S3 Control: `https://s3-control.{region}.amazonaws.com/...`
  - [ ] Express One Zone zonal: `https://{bucket}.s3express-{zone}.{region}.amazonaws.com/{key}`
  - [ ] Query string assembly
- [ ] Standard header management
  - [ ] Host, x-amz-date, x-amz-content-sha256
  - [ ] x-amz-security-token (STS)
  - [ ] Content-Type, Content-Length, Content-MD5
  - [ ] x-amz-* custom headers
  - [ ] curl_slist management (build, append, free)
- [ ] Request dispatcher (`s3__request`)
  - [ ] Method selection (GET/PUT/POST/DELETE/HEAD)
  - [ ] Upload from buffer (CURLOPT_POSTFIELDS / CURLOPT_UPLOAD + READFUNCTION)
  - [ ] Upload from callback (s3_read_fn)
  - [ ] Download to internal buffer (response_buf)
  - [ ] Download to callback (s3_write_fn)
  - [ ] Header capture callback (for ETag, x-amz-request-id, etc.)
  - [ ] Progress callback relay
  - [ ] Timeout configuration (connect + request)
  - [ ] HTTP response code extraction
  - [ ] Error detection and routing to error parser
- [ ] Response header parsing
  - [ ] `s3__parse_response_headers` — extract ETag, x-amz-request-id, x-amz-id-2, content-length, content-type, last-modified, x-amz-version-id, etc.

## Phase 5: Error Handling (`src/s3_error.c`)
- [ ] S3 XML error response parser
  - [ ] Parse `<Error><Code>...</Code><Message>...</Message><RequestId>...</RequestId><HostId>...</HostId></Error>`
- [ ] S3 error code → `s3_status` mapping table
  - [ ] AccessDenied, AccountProblem, AllAccessDisabled
  - [ ] BucketAlreadyExists, BucketAlreadyOwnedByYou, BucketNotEmpty
  - [ ] CredentialsNotSupported, CrossLocationLoggingProhibited
  - [ ] EntityTooSmall, EntityTooLarge, ExpiredToken
  - [ ] IllegalLocationConstraintException, IllegalVersioningConfigurationException
  - [ ] IncompleteBody, IncorrectNumberOfFilesInPostRequest
  - [ ] InlineDataTooLarge, InternalError, InvalidAccessKeyId
  - [ ] InvalidArgument, InvalidBucketName, InvalidBucketState
  - [ ] InvalidDigest, InvalidEncryptionAlgorithmError
  - [ ] InvalidLocationConstraint, InvalidObjectState
  - [ ] InvalidPart, InvalidPartOrder, InvalidPayer
  - [ ] InvalidPolicyDocument, InvalidRange, InvalidRequest
  - [ ] InvalidSecurity, InvalidSOAPRequest, InvalidStorageClass
  - [ ] InvalidTargetBucketForLogging, InvalidToken, InvalidURI
  - [ ] KeyTooLongError, MalformedACLError, MalformedPOSTRequest
  - [ ] MalformedXML, MaxMessageLengthExceeded, MaxPostPreDataLengthExceededError
  - [ ] MetadataTooLarge, MethodNotAllowed, MissingAttachment
  - [ ] MissingContentLength, MissingRequestBodyError, MissingSecurityElement
  - [ ] MissingSecurityHeader, NoLoggingStatusForKey, NoSuchBucket
  - [ ] NoSuchBucketPolicy, NoSuchCORSConfiguration, NoSuchKey
  - [ ] NoSuchLifecycleConfiguration, NoSuchUpload, NoSuchVersion
  - [ ] NoSuchWebsiteConfiguration, NoSuchTagSet
  - [ ] NotImplemented, NotSignedUp, OperationAborted
  - [ ] PermanentRedirect, PreconditionFailed, Redirect
  - [ ] RequestIsNotMultiPartContent, RequestTimeout, RequestTimeTooSkewed
  - [ ] RequestTorrentOfBucketError, RestoreAlreadyInProgress
  - [ ] ServerSideEncryptionConfigurationNotFoundError
  - [ ] ServiceUnavailable, SignatureDoesNotMatch, SlowDown
  - [ ] TemporaryRedirect, TokenRefreshRequired, TooManyBuckets
  - [ ] UnexpectedContent, UnresolvableGrantByEmailAddress, UserKeyMustBeSpecified
  - [ ] NoSuchAccessPoint, InvalidTag, etc.
- [ ] HTTP status code → `s3_status` fallback mapping (for non-XML errors)
- [ ] curl error → `s3_status` mapping
- [ ] `s3_status_string()` — human-readable name for every enum value

## Phase 6: Client Lifecycle (`src/s3_client.c`)
- [ ] `s3_client_create` — allocate, deep-copy config strings, init CURL handle
- [ ] `s3_client_destroy` — free everything, curl_easy_cleanup
- [ ] `s3_client_last_error` — return pointer to last_error
- [ ] Config validation (region required, credentials required, etc.)
- [ ] Default config values (use_https=true, user_agent="libs3/1.0", etc.)
- [ ] Deep copy of all config strings (caller can free their originals)
- [ ] Credential refresh callback support (for rotating credentials)
  - [ ] `s3_credential_provider_fn` callback type
  - [ ] Called before each request if set

## Phase 7: Logging (`src/s3_log.c`)
- [ ] Log level enum: TRACE, DEBUG, INFO, WARN, ERROR, NONE
- [ ] `s3_log_fn` callback type
- [ ] Internal `s3__log` macro that checks level and calls callback
- [ ] TRACE: full canonical request, string-to-sign, Authorization header
- [ ] DEBUG: request method + URL, response status code, timing
- [ ] INFO: operation name + bucket/key
- [ ] WARN: retries, slow responses
- [ ] ERROR: failures, parse errors

## Phase 8: Retry Engine (`src/s3_retry.c`)
- [ ] Retry policy struct in config
- [ ] `s3__should_retry` — check status, HTTP code, attempt count
- [ ] `s3__retry_delay` — exponential backoff with jitter
- [ ] Integration into `s3__request` — retry loop wrapping curl_easy_perform
- [ ] Retryable conditions:
  - [ ] HTTP 500, 502, 503, 504
  - [ ] SlowDown (HTTP 503 with specific code)
  - [ ] RequestTimeout, RequestTimeTooSkewed
  - [ ] curl timeout / connection errors
  - [ ] NOT retryable: 400, 403, 404, etc.

## Phase 9: Basic Object Operations (`src/s3_object.c`)
- [ ] `s3_put_object` — PUT, buffer upload
  - [ ] Content-Type, Content-MD5, Cache-Control, Content-Disposition, Content-Encoding
  - [ ] x-amz-storage-class
  - [ ] x-amz-tagging (URL-encoded)
  - [ ] x-amz-acl (canned ACL)
  - [ ] x-amz-meta-* (user metadata)
  - [ ] x-amz-object-lock-mode, x-amz-object-lock-retain-until-date, x-amz-object-lock-legal-hold
  - [ ] SSE headers (S3, KMS, C)
  - [ ] Checksum headers
  - [ ] Parse response: ETag, x-amz-version-id, x-amz-request-id
- [ ] `s3_put_object_stream` — PUT, streaming upload via callback
  - [ ] Known content-length: Content-Length header
  - [ ] Unknown content-length: chunked transfer encoding
  - [ ] UNSIGNED-PAYLOAD for x-amz-content-sha256
- [ ] `s3_get_object` — GET, download to library-allocated buffer
  - [ ] Range header (bytes=start-end)
  - [ ] If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since
  - [ ] x-amz-request-payer
  - [ ] versionId query param
  - [ ] SSE-C headers (for SSE-C encrypted objects)
  - [ ] x-amz-checksum-mode (ENABLED to get checksum in response)
  - [ ] partNumber query param
  - [ ] Parse response headers: Content-Length, Content-Type, ETag, Last-Modified, etc.
  - [ ] Handle 206 Partial Content, 304 Not Modified
- [ ] `s3_get_object_stream` — GET, streaming download via callback
- [ ] `s3_head_object` — HEAD
  - [ ] Same conditional/range/version params as GET
  - [ ] Parse all response headers into `s3_head_object_result`
  - [ ] Content-Length, Content-Type, ETag, Last-Modified, x-amz-storage-class, x-amz-version-id
  - [ ] x-amz-object-lock-mode, x-amz-object-lock-retain-until-date, x-amz-object-lock-legal-hold-status
  - [ ] x-amz-server-side-encryption, x-amz-server-side-encryption-aws-kms-key-id
  - [ ] x-amz-meta-* (user metadata)
  - [ ] x-amz-restore (Glacier restore status)
  - [ ] x-amz-expiration
  - [ ] x-amz-replication-status
  - [ ] x-amz-mp-parts-count
  - [ ] Content-Encoding, Content-Language, Content-Disposition, Cache-Control, Expires
- [ ] `s3_delete_object` — DELETE
  - [ ] versionId query param
  - [ ] x-amz-mfa (for MFA Delete)
  - [ ] x-amz-request-payer
  - [ ] Parse response: x-amz-delete-marker, x-amz-version-id
- [ ] `s3_delete_objects` — POST with `?delete`, batch delete up to 1000 keys
  - [ ] Build XML: `<Delete><Object><Key>...</Key><VersionId>...</VersionId></Object>...</Delete>`
  - [ ] Content-MD5 header (required)
  - [ ] Parse response: `<DeleteResult>` with `<Deleted>` and `<Error>` elements
  - [ ] Quiet mode (only return errors)
- [ ] `s3_copy_object` — PUT with x-amz-copy-source header
  - [ ] x-amz-copy-source: /{bucket}/{key}?versionId={id}
  - [ ] x-amz-metadata-directive: COPY or REPLACE
  - [ ] x-amz-tagging-directive: COPY or REPLACE
  - [ ] x-amz-copy-source-if-match, if-none-match, if-modified-since, if-unmodified-since
  - [ ] All destination headers (storage class, ACL, SSE, tagging, metadata, object lock)
  - [ ] SSE-C for source (x-amz-copy-source-server-side-encryption-customer-*)
  - [ ] Parse response: `<CopyObjectResult><ETag>...</ETag><LastModified>...</LastModified></CopyObjectResult>`
- [ ] `s3_rename_object` — newer API, equivalent to move
- [ ] `s3_get_object_attributes` — GET with `?attributes`
  - [ ] x-amz-object-attributes header (ETag, Checksum, ObjectParts, StorageClass, ObjectSize)
  - [ ] Parse response XML

## Phase 10: Object Configuration (`src/s3_object_config.c`)
- [ ] `s3_get_object_tagging` — GET `?tagging`
  - [ ] versionId query param
  - [ ] Parse `<Tagging><TagSet><Tag><Key>...</Key><Value>...</Value></Tag>...</TagSet></Tagging>`
- [ ] `s3_put_object_tagging` — PUT `?tagging`
  - [ ] Build XML request body
  - [ ] versionId, Content-MD5
- [ ] `s3_delete_object_tagging` — DELETE `?tagging`
  - [ ] versionId
- [ ] `s3_get_object_acl` — GET `?acl`
  - [ ] Parse `<AccessControlPolicy>` XML
- [ ] `s3_put_object_acl` — PUT `?acl`
  - [ ] XML body or canned ACL header
- [ ] `s3_get_object_legal_hold` — GET `?legal-hold`
  - [ ] Parse `<LegalHold><Status>ON|OFF</Status></LegalHold>`
- [ ] `s3_put_object_legal_hold` — PUT `?legal-hold`
  - [ ] Build XML body
- [ ] `s3_get_object_retention` — GET `?retention`
  - [ ] Parse `<Retention><Mode>...</Mode><RetainUntilDate>...</RetainUntilDate></Retention>`
- [ ] `s3_put_object_retention` — PUT `?retention`
  - [ ] Build XML body
  - [ ] x-amz-bypass-governance-retention header
- [ ] `s3_restore_object` — POST `?restore`
  - [ ] Build XML: `<RestoreRequest><Days>N</Days><GlacierJobParameters><Tier>...</Tier></GlacierJobParameters></RestoreRequest>`
  - [ ] Tier: Expedited, Standard, Bulk
  - [ ] S3 Intelligent-Tiering archive access
  - [ ] Select restore (restore + run select)

## Phase 11: List Operations (`src/s3_list.c`)
- [ ] `s3_list_objects_v2` — GET `?list-type=2`
  - [ ] prefix, delimiter, max-keys, continuation-token, start-after, fetch-owner, encoding-type
  - [ ] Parse `<ListBucketResult>`: Name, Prefix, MaxKeys, IsTruncated, Contents[], CommonPrefixes[]
  - [ ] Contents: Key, LastModified, ETag, Size, StorageClass, Owner, ChecksumAlgorithm
  - [ ] Handle encoding-type=url (URL-decode keys)
- [ ] `s3_list_objects_v1` — GET (legacy, no list-type param)
  - [ ] prefix, delimiter, max-keys, marker
  - [ ] Parse `<ListBucketResult>` with Marker, NextMarker
- [ ] `s3_list_object_versions` — GET `?versions`
  - [ ] prefix, delimiter, max-keys, key-marker, version-id-marker
  - [ ] Parse `<ListVersionsResult>`: Version[], DeleteMarker[], CommonPrefixes[]
  - [ ] Version: Key, VersionId, IsLatest, LastModified, ETag, Size, StorageClass, Owner
  - [ ] DeleteMarker: Key, VersionId, IsLatest, LastModified, Owner

## Phase 12: Multipart Upload (`src/s3_multipart.c`)
- [ ] `s3_create_multipart_upload` — POST `?uploads`
  - [ ] All headers from put_object (content-type, ACL, storage class, SSE, tagging, metadata, object lock)
  - [ ] Parse response: `<InitiateMultipartUploadResult><UploadId>...</UploadId></InitiateMultipartUploadResult>`
- [ ] `s3_upload_part` — PUT `?partNumber={N}&uploadId={id}`
  - [ ] Part number (1-10000)
  - [ ] Content-MD5
  - [ ] SSE-C headers (must match create)
  - [ ] Checksum headers
  - [ ] Parse response: ETag
- [ ] `s3_upload_part_stream` — same as upload_part but streaming via callback
- [ ] `s3_upload_part_copy` — PUT `?partNumber={N}&uploadId={id}` with x-amz-copy-source
  - [ ] x-amz-copy-source-range: bytes=start-end
  - [ ] x-amz-copy-source-if-* conditional headers
  - [ ] SSE-C headers for source and destination
  - [ ] Parse response: `<CopyPartResult><ETag>...</ETag><LastModified>...</LastModified></CopyPartResult>`
- [ ] `s3_complete_multipart_upload` — POST `?uploadId={id}`
  - [ ] Build XML: `<CompleteMultipartUpload><Part><PartNumber>N</PartNumber><ETag>...</ETag></Part>...</CompleteMultipartUpload>`
  - [ ] Checksum per part if checksums enabled
  - [ ] Parse response: `<CompleteMultipartUploadResult>` — Location, Bucket, Key, ETag
  - [ ] Handle 200 OK with error body (S3 can return 200 with an error XML!)
- [ ] `s3_abort_multipart_upload` — DELETE `?uploadId={id}`
- [ ] `s3_list_parts` — GET `?uploadId={id}`
  - [ ] max-parts, part-number-marker
  - [ ] Parse `<ListPartsResult>`: Part[] — PartNumber, LastModified, ETag, Size
  - [ ] IsTruncated, NextPartNumberMarker
- [ ] `s3_list_multipart_uploads` — GET `?uploads`
  - [ ] delimiter, prefix, max-uploads, key-marker, upload-id-marker, encoding-type
  - [ ] Parse `<ListMultipartUploadsResult>`: Upload[] — Key, UploadId, Initiated, StorageClass
  - [ ] CommonPrefixes, IsTruncated, NextKeyMarker, NextUploadIdMarker

## Phase 13: Bucket Operations (`src/s3_bucket.c`)
- [ ] `s3_create_bucket` — PUT /
  - [ ] `<CreateBucketConfiguration><LocationConstraint>{region}</LocationConstraint></CreateBucketConfiguration>`
  - [ ] x-amz-acl
  - [ ] x-amz-bucket-object-lock-enabled
  - [ ] Handle us-east-1 special case (no body needed)
- [ ] `s3_delete_bucket` — DELETE /
- [ ] `s3_head_bucket` — HEAD /
  - [ ] Used to check bucket existence and access
  - [ ] x-amz-expected-bucket-owner
- [ ] `s3_list_buckets` — GET / (on s3.amazonaws.com)
  - [ ] prefix, continuation-token, max-buckets (newer API additions)
  - [ ] Parse `<ListAllMyBucketsResult><Buckets><Bucket><Name>...</Name><CreationDate>...</CreationDate></Bucket>...</Buckets></ListAllMyBucketsResult>`
- [ ] `s3_get_bucket_location` — GET `?location`
  - [ ] Parse `<LocationConstraint>region</LocationConstraint>`
  - [ ] Handle empty body (means us-east-1)
- [ ] `s3_list_directory_buckets` — GET / with bucket-type=directory (Express One Zone)

## Phase 14: Bucket Configuration (`src/s3_bucket_config.c`)
- [ ] **Versioning**
  - [ ] `s3_get_bucket_versioning` — GET `?versioning`
  - [ ] `s3_put_bucket_versioning` — PUT `?versioning`
  - [ ] States: unversioned (no element), Enabled, Suspended
  - [ ] MFA Delete: x-amz-mfa header
- [ ] **Lifecycle**
  - [ ] `s3_get_bucket_lifecycle` — GET `?lifecycle`
  - [ ] `s3_put_bucket_lifecycle` — PUT `?lifecycle`
  - [ ] `s3_delete_bucket_lifecycle` — DELETE `?lifecycle`
  - [ ] Complex XML: Rule[], Filter (Prefix, Tag, And), Status, Transition[], Expiration, NoncurrentVersionTransition[], NoncurrentVersionExpiration, AbortIncompleteMultipartUpload
- [ ] **Policy**
  - [ ] `s3_get_bucket_policy` — GET `?policy` (returns JSON, not XML!)
  - [ ] `s3_put_bucket_policy` — PUT `?policy` (JSON body)
  - [ ] `s3_delete_bucket_policy` — DELETE `?policy`
  - [ ] `s3_get_bucket_policy_status` — GET `?policyStatus`
- [ ] **CORS**
  - [ ] `s3_get_bucket_cors` — GET `?cors`
  - [ ] `s3_put_bucket_cors` — PUT `?cors`
  - [ ] `s3_delete_bucket_cors` — DELETE `?cors`
  - [ ] XML: CORSRule[] — AllowedOrigin[], AllowedMethod[], AllowedHeader[], ExposeHeader[], MaxAgeSeconds
- [ ] **Encryption**
  - [ ] `s3_get_bucket_encryption` — GET `?encryption`
  - [ ] `s3_put_bucket_encryption` — PUT `?encryption`
  - [ ] `s3_delete_bucket_encryption` — DELETE `?encryption`
  - [ ] XML: ServerSideEncryptionConfiguration — Rule[] — ApplyServerSideEncryptionByDefault (SSEAlgorithm, KMSMasterKeyID), BucketKeyEnabled
- [ ] **Logging**
  - [ ] `s3_get_bucket_logging` — GET `?logging`
  - [ ] `s3_put_bucket_logging` — PUT `?logging`
  - [ ] XML: BucketLoggingStatus — LoggingEnabled (TargetBucket, TargetPrefix, TargetGrants[])
- [ ] **Tagging**
  - [ ] `s3_get_bucket_tagging` — GET `?tagging`
  - [ ] `s3_put_bucket_tagging` — PUT `?tagging`
  - [ ] `s3_delete_bucket_tagging` — DELETE `?tagging`
- [ ] **Website**
  - [ ] `s3_get_bucket_website` — GET `?website`
  - [ ] `s3_put_bucket_website` — PUT `?website`
  - [ ] `s3_delete_bucket_website` — DELETE `?website`
  - [ ] XML: IndexDocument, ErrorDocument, RedirectAllRequestsTo, RoutingRules[]
- [ ] **Notification**
  - [ ] `s3_get_bucket_notification` — GET `?notification`
  - [ ] `s3_put_bucket_notification` — PUT `?notification`
  - [ ] XML: TopicConfiguration[], QueueConfiguration[], LambdaFunctionConfiguration[]
  - [ ] Each: Id, Arn, Events[], Filter (S3Key — FilterRule[])
- [ ] **Replication**
  - [ ] `s3_get_bucket_replication` — GET `?replication`
  - [ ] `s3_put_bucket_replication` — PUT `?replication`
  - [ ] `s3_delete_bucket_replication` — DELETE `?replication`
  - [ ] XML: ReplicationConfiguration — Role, Rule[] — Status, Priority, Filter, Destination, DeleteMarkerReplication, etc.
- [ ] **Accelerate**
  - [ ] `s3_get_bucket_accelerate` — GET `?accelerate`
  - [ ] `s3_put_bucket_accelerate` — PUT `?accelerate`
  - [ ] Status: Enabled, Suspended
- [ ] **Request Payment**
  - [ ] `s3_get_bucket_request_payment` — GET `?requestPayment`
  - [ ] `s3_put_bucket_request_payment` — PUT `?requestPayment`
  - [ ] Payer: BucketOwner, Requester
- [ ] **Object Lock Configuration**
  - [ ] `s3_get_object_lock_configuration` — GET `?object-lock`
  - [ ] `s3_put_object_lock_configuration` — PUT `?object-lock`
  - [ ] XML: ObjectLockConfiguration — ObjectLockEnabled, Rule (DefaultRetention: Mode, Days/Years)
- [ ] **ACL**
  - [ ] `s3_get_bucket_acl` — GET `?acl`
  - [ ] `s3_put_bucket_acl` — PUT `?acl`
- [ ] **Intelligent-Tiering**
  - [ ] `s3_get_bucket_intelligent_tiering` — GET `?intelligent-tiering&id={id}`
  - [ ] `s3_put_bucket_intelligent_tiering` — PUT `?intelligent-tiering&id={id}`
  - [ ] `s3_delete_bucket_intelligent_tiering` — DELETE `?intelligent-tiering&id={id}`
  - [ ] `s3_list_bucket_intelligent_tiering` — GET `?intelligent-tiering`
  - [ ] XML: IntelligentTieringConfiguration — Id, Status, Filter, Tiering[] (AccessTier, Days)
- [ ] **Metrics**
  - [ ] `s3_get_bucket_metrics` — GET `?metrics&id={id}`
  - [ ] `s3_put_bucket_metrics` — PUT `?metrics&id={id}`
  - [ ] `s3_delete_bucket_metrics` — DELETE `?metrics&id={id}`
  - [ ] `s3_list_bucket_metrics` — GET `?metrics`
- [ ] **Inventory**
  - [ ] `s3_get_bucket_inventory` — GET `?inventory&id={id}`
  - [ ] `s3_put_bucket_inventory` — PUT `?inventory&id={id}`
  - [ ] `s3_delete_bucket_inventory` — DELETE `?inventory&id={id}`
  - [ ] `s3_list_bucket_inventory` — GET `?inventory`
  - [ ] XML: InventoryConfiguration — Destination, IsEnabled, Filter, Id, IncludedObjectVersions, OptionalFields[], Schedule
- [ ] **Analytics**
  - [ ] `s3_get_bucket_analytics` — GET `?analytics&id={id}`
  - [ ] `s3_put_bucket_analytics` — PUT `?analytics&id={id}`
  - [ ] `s3_delete_bucket_analytics` — DELETE `?analytics&id={id}`
  - [ ] `s3_list_bucket_analytics` — GET `?analytics`
- [ ] **Public Access Block**
  - [ ] `s3_get_public_access_block` — GET `?publicAccessBlock`
  - [ ] `s3_put_public_access_block` — PUT `?publicAccessBlock`
  - [ ] `s3_delete_public_access_block` — DELETE `?publicAccessBlock`
  - [ ] XML: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets
- [ ] **Ownership Controls**
  - [ ] `s3_get_bucket_ownership_controls` — GET `?ownershipControls`
  - [ ] `s3_put_bucket_ownership_controls` — PUT `?ownershipControls`
  - [ ] `s3_delete_bucket_ownership_controls` — DELETE `?ownershipControls`
  - [ ] XML: OwnershipControlsRule — ObjectOwnership (BucketOwnerPreferred, ObjectWriter, BucketOwnerEnforced)

## Phase 15: SSE Helpers (`src/s3_sse.c`)
- [ ] SSE-S3: `x-amz-server-side-encryption: AES256`
- [ ] SSE-KMS:
  - [ ] `x-amz-server-side-encryption: aws:kms`
  - [ ] `x-amz-server-side-encryption-aws-kms-key-id: {key-arn}`
  - [ ] `x-amz-server-side-encryption-context: {base64-json}`
  - [ ] `x-amz-server-side-encryption-bucket-key-enabled: true`
- [ ] SSE-C:
  - [ ] `x-amz-server-side-encryption-customer-algorithm: AES256`
  - [ ] `x-amz-server-side-encryption-customer-key: {base64-key}`
  - [ ] `x-amz-server-side-encryption-customer-key-MD5: {base64-md5}`
- [ ] SSE-C for copy source:
  - [ ] `x-amz-copy-source-server-side-encryption-customer-algorithm`
  - [ ] `x-amz-copy-source-server-side-encryption-customer-key`
  - [ ] `x-amz-copy-source-server-side-encryption-customer-key-MD5`
- [ ] Helper to apply SSE headers to any curl_slist based on `s3_encryption` config

## Phase 16: Checksum Support (`src/s3_checksum.c`)
- [ ] Checksum algorithm enum: CRC32, CRC32C, SHA1, SHA256
- [ ] Compute checksum on upload (trailing or full-object)
  - [ ] `x-amz-checksum-crc32`, `x-amz-checksum-crc32c`, `x-amz-checksum-sha1`, `x-amz-checksum-sha256`
  - [ ] `x-amz-checksum-algorithm` header
- [ ] Request checksum on download
  - [ ] `x-amz-checksum-mode: ENABLED`
  - [ ] Validate returned checksum against computed
- [ ] Multipart checksums
  - [ ] Per-part checksum in UploadPart
  - [ ] Composite checksum in CompleteMultipartUpload
- [ ] `x-amz-content-sha256` values:
  - [ ] Actual SHA-256 hex (small known payloads)
  - [ ] `UNSIGNED-PAYLOAD` (presigned, streaming)
  - [ ] `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked)
  - [ ] `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` (chunked + trailing checksum)

## Phase 17: Presigned URLs (`src/s3_presign.c`)
- [ ] `s3_presign_get` — GET presigned URL
- [ ] `s3_presign_put` — PUT presigned URL, optional content-type
- [ ] `s3_presign_delete` — DELETE presigned URL
- [ ] `s3_presign_head` — HEAD presigned URL
- [ ] `s3_presign_create_multipart_upload` — POST ?uploads
- [ ] `s3_presign_upload_part` — PUT ?partNumber&uploadId
- [ ] `s3_presign_complete_multipart_upload` — POST ?uploadId
- [ ] Expiry: 1 second to 7 days (604800)
- [ ] Custom query parameters passthrough
- [ ] STS token in query string (X-Amz-Security-Token)

## Phase 18: SelectObjectContent (`src/s3_select.c`)
- [ ] `s3_select_object_content` — POST `?select&select-type=2`
  - [ ] Build XML request: Expression, ExpressionType (SQL), InputSerialization, OutputSerialization
  - [ ] Input formats: CSV, JSON, Parquet
  - [ ] CSV options: FileHeaderInfo, Comments, QuoteEscapeCharacter, RecordDelimiter, FieldDelimiter, QuoteCharacter, AllowQuotedRecordDelimiter
  - [ ] JSON options: Type (DOCUMENT, LINES)
  - [ ] Output formats: CSV, JSON
  - [ ] Parse binary event stream response (Records, Stats, Progress, Cont, End events)
  - [ ] Event stream framing: prelude (total length, headers length), headers, payload, CRC
  - [ ] ScanRange: Start, End (byte offsets)
  - [ ] Note: deprecated for new customers but still functional

## Phase 19: Async Layer (`src/s3_async.c`)
- [ ] `s3_event_loop_create` — init CURLM, optionally spawn background thread
  - [ ] `S3_LOOP_AUTO` — library manages thread
  - [ ] `S3_LOOP_MANUAL` — user calls `s3_event_loop_poll`
  - [ ] max_concurrent option
- [ ] `s3_event_loop_destroy` — signal shutdown, join thread, curl_multi_cleanup
- [ ] `s3_event_loop_poll` — call curl_multi_poll + curl_multi_perform, dispatch completions
- [ ] `s3_future_wait` — block on condvar until done
- [ ] `s3_future_is_done` — atomic load of state
- [ ] `s3_future_status` — get result s3_status
- [ ] `s3_future_result` — get operation-specific result data
- [ ] `s3_future_on_complete` — attach completion callback
- [ ] `s3_future_destroy` — free future and its result
- [ ] Internal: transfer context struct linking CURL easy handle to future
- [ ] Internal: completion dispatch — parse response, populate future, fire callback
- [ ] Every sync API function gets an `_async` variant:
  - [ ] `s3_put_object_async`
  - [ ] `s3_get_object_async`
  - [ ] `s3_delete_object_async`
  - [ ] `s3_head_object_async`
  - [ ] `s3_copy_object_async`
  - [ ] `s3_list_objects_async`
  - [ ] `s3_delete_objects_async`
  - [ ] (... every operation ...)
- [ ] Rewrite sync functions as `_async` + `s3_future_wait` internally

## Phase 20: Thread Pool (`src/s3_pool.c`)
- [ ] `s3_pool_create` — spawn N worker threads, each with own `s3_client`
  - [ ] Deep-copy config per worker
  - [ ] Init per-worker CURL handle
- [ ] `s3_pool_destroy` — signal shutdown, drain queue, join threads
- [ ] Work queue
  - [ ] Ring buffer or linked list with mutex + condvar
  - [ ] Work item struct: function pointer + args + future pointer
  - [ ] Worker loop: dequeue → execute → complete future
- [ ] `s3_pool_submit` — generic work submission (function pointer + void* args)
- [ ] Convenience wrappers:
  - [ ] `s3_pool_put_object`
  - [ ] `s3_pool_get_object`
  - [ ] `s3_pool_delete_object`
  - [ ] `s3_pool_delete_objects`
  - [ ] (... etc for all operations ...)
- [ ] Pool stats: active workers, queue depth, completed count

## Phase 21: High-Level Helpers (`src/s3_highlevel.c`)
- [ ] `s3_upload_file` — upload file from filesystem path
  - [ ] Auto-detect content type from extension
  - [ ] If size > threshold (default 64MB): auto multipart
  - [ ] Configurable part size (default 8MB, min 5MB)
  - [ ] Progress callback
  - [ ] Checksum computation
- [ ] `s3_upload_file_parallel` — parallel multipart via pool
  - [ ] max_concurrent_parts option
  - [ ] Create multipart → fan out parts across pool → complete
  - [ ] On failure: abort multipart upload
- [ ] `s3_download_file` — download object to filesystem path
  - [ ] Create file, write via streaming callback
  - [ ] Progress callback
  - [ ] Checksum validation
- [ ] `s3_download_file_parallel` — parallel range reads via pool
  - [ ] HEAD to get size → compute ranges → fan out GET with Range header → assemble
- [ ] `s3_copy_large_object` — multipart copy for objects >5GB
  - [ ] HEAD source to get size → create multipart → upload_part_copy for each range → complete
  - [ ] Parallel via pool
- [ ] `s3_object_exists` — HEAD, return bool (true if 200, false if 404, error otherwise)
- [ ] `s3_list_all_objects` — auto-paginate ListObjectsV2, return full list
  - [ ] Callback variant: `s3_list_all_objects_cb` — call user function per page
- [ ] `s3_list_all_object_versions` — auto-paginate ListObjectVersions
- [ ] `s3_sync_upload` — sync local directory → S3 prefix
  - [ ] Compare local files vs S3 listing (by size, ETag/MD5, or last-modified)
  - [ ] Upload new/changed files, optionally delete removed
  - [ ] Include/exclude filters (glob patterns)
  - [ ] Dry-run mode
- [ ] `s3_sync_download` — sync S3 prefix → local directory
  - [ ] Same comparison logic in reverse
- [ ] `s3_delete_all_objects` — list + batch delete all objects under a prefix
  - [ ] Auto-paginate + batch in groups of 1000
  - [ ] Optional: delete all versions (for versioned buckets)
- [ ] `s3_delete_bucket_force` — delete all objects + versions + delete markers, then delete bucket
- [ ] Content type detection from file extension
  - [ ] Static table of common MIME types

## Phase 22: S3 Control API Base (`src/s3_control.c`)
- [ ] Different endpoint: `https://{account-id}.s3-control.{region}.amazonaws.com`
- [ ] Account ID in config / per-call
- [ ] x-amz-account-id header
- [ ] Control API uses same SigV4 signing but service = "s3"
- [ ] Shared request infrastructure reuse

## Phase 23: Access Points (`src/s3_access_point.c`)
- [ ] `s3_create_access_point` — PUT `/v20180820/accesspoint/{name}`
  - [ ] XML: CreateAccessPointRequest — Bucket, VpcConfiguration, PublicAccessBlockConfiguration, BucketAccountId
- [ ] `s3_delete_access_point` — DELETE `/v20180820/accesspoint/{name}`
- [ ] `s3_get_access_point` — GET `/v20180820/accesspoint/{name}`
  - [ ] Parse: Name, Bucket, NetworkOrigin, VpcConfiguration, PublicAccessBlockConfiguration, CreationDate, Alias, AccessPointArn, Endpoints, BucketAccountId
- [ ] `s3_list_access_points` — GET `/v20180820/accesspoint`
  - [ ] bucket, next-token, max-results query params
  - [ ] Parse: AccessPointList, NextToken
- [ ] `s3_get_access_point_policy` — GET `/v20180820/accesspoint/{name}/policy`
  - [ ] Returns JSON policy
- [ ] `s3_put_access_point_policy` — PUT `/v20180820/accesspoint/{name}/policy`
  - [ ] JSON body
- [ ] `s3_delete_access_point_policy` — DELETE `/v20180820/accesspoint/{name}/policy`
- [ ] `s3_get_access_point_policy_status` — GET `/v20180820/accesspoint/{name}/policyStatus`
- [ ] Using access points in object operations:
  - [ ] Support access point ARN as bucket name in all object ops
  - [ ] URL format: `https://{ap-name}-{account}.s3-accesspoint.{region}.amazonaws.com/{key}`

## Phase 24: Object Lambda Access Points (`src/s3_object_lambda.c`)
- [ ] `s3_create_access_point_for_object_lambda` — PUT `/v20180820/accesspointforobjectlambda/{name}`
  - [ ] XML: ObjectLambdaConfiguration — SupportingAccessPoint, TransformationConfigurations[]
  - [ ] TransformationConfiguration: Actions (GetObject, HeadObject, ListObjects), ContentTransformation (AwsLambda — FunctionArn, FunctionPayload)
- [ ] `s3_delete_access_point_for_object_lambda` — DELETE `/v20180820/accesspointforobjectlambda/{name}`
- [ ] `s3_get_access_point_for_object_lambda` — GET `/v20180820/accesspointforobjectlambda/{name}`
- [ ] `s3_list_access_points_for_object_lambda` — GET `/v20180820/accesspointforobjectlambda`
- [ ] `s3_get_access_point_policy_for_object_lambda` — GET `/v20180820/accesspointforobjectlambda/{name}/policy`
- [ ] `s3_put_access_point_policy_for_object_lambda` — PUT
- [ ] `s3_delete_access_point_policy_for_object_lambda` — DELETE
- [ ] `s3_get_access_point_configuration_for_object_lambda` — GET `.../configuration`
- [ ] `s3_put_access_point_configuration_for_object_lambda` — PUT `.../configuration`

## Phase 25: Access Grants (`src/s3_access_grants.c`)
- [ ] `s3_create_access_grants_instance` — POST `/v20180820/accessgrantsinstance`
  - [ ] IdentityCenterArn, Tags
- [ ] `s3_delete_access_grants_instance` — DELETE `/v20180820/accessgrantsinstance`
- [ ] `s3_get_access_grants_instance` — GET `/v20180820/accessgrantsinstance`
- [ ] `s3_list_access_grants_instances` — GET (with pagination)
- [ ] `s3_associate_access_grants_identity_center` — POST `.../identitycenter`
- [ ] `s3_dissociate_access_grants_identity_center` — DELETE `.../identitycenter`
- [ ] `s3_create_access_grants_location` — POST `/v20180820/accessgrantsinstance/location`
  - [ ] IAMRoleArn, LocationScope
- [ ] `s3_delete_access_grants_location` — DELETE `.../location/{id}`
- [ ] `s3_get_access_grants_location` — GET `.../location/{id}`
- [ ] `s3_list_access_grants_locations` — GET `.../location`
  - [ ] next-token, max-results, location-scope
- [ ] `s3_update_access_grants_location` — PUT `.../location/{id}`
- [ ] `s3_create_access_grant` — POST `/v20180820/accessgrantsinstance/grant`
  - [ ] AccessGrantsLocationId, AccessGrantsLocationConfiguration, Grantee, Permission, ApplicationArn, Tags
- [ ] `s3_delete_access_grant` — DELETE `.../grant/{id}`
- [ ] `s3_get_access_grant` — GET `.../grant/{id}`
- [ ] `s3_list_access_grants` — GET `.../grant`
  - [ ] next-token, max-results, grantee-type, grantee-identifier, permission, grant-scope
- [ ] `s3_get_data_access` — GET `/v20180820/accessgrantsinstance/dataaccess`
  - [ ] AccountId, Target, Permission, DurationSeconds, Privilege, TargetType

## Phase 26: Multi-Region Access Points (`src/s3_mrap.c`)
- [ ] `s3_create_multi_region_access_point` — POST `/v20180820/async-requests/mrap/create`
  - [ ] XML: CreateMultiRegionAccessPointInput — Name, PublicAccessBlock, Regions[]
  - [ ] Async operation — returns request token
- [ ] `s3_delete_multi_region_access_point` — POST `/v20180820/async-requests/mrap/delete`
  - [ ] Async operation
- [ ] `s3_get_multi_region_access_point` — GET `/v20180820/mrap/instances/{name}`
- [ ] `s3_list_multi_region_access_points` — GET `/v20180820/mrap/instances`
  - [ ] next-token, max-results
- [ ] `s3_get_multi_region_access_point_policy` — GET `.../instances/{name}/policy`
- [ ] `s3_put_multi_region_access_point_policy` — POST `/v20180820/async-requests/mrap/put-policy`
  - [ ] Async operation
- [ ] `s3_get_multi_region_access_point_routes` — GET `.../instances/{name}/routes`
- [ ] `s3_describe_multi_region_access_point_operation` — GET `/v20180820/async-requests/mrap/{token}`
  - [ ] Check status of async create/delete/put-policy
- [ ] SigV4A signing for MRAP requests (multi-region signing — uses ECDSA P-256!)
  - [ ] This requires implementing SigV4A — a separate signing algorithm
  - [ ] Service = "s3", region = "*"

## Phase 27: S3 Batch Operations (`src/s3_batch.c`)
- [ ] `s3_create_job` — POST `/v20180820/jobs`
  - [ ] XML: CreateJobRequest — AccountId, ConfirmationRequired, Description, Manifest, ManifestGenerator, Operation, Priority, Report, RoleArn, Tags
  - [ ] Operations: LambdaInvoke, S3PutObjectCopy, S3PutObjectAcl, S3PutObjectTagging, S3DeleteObjectTagging, S3InitiateRestoreObject, S3PutObjectLegalHold, S3PutObjectRetention, S3ReplicateObject
  - [ ] Manifest: Location (ObjectArn, ETag), Spec (Format, Fields)
  - [ ] ManifestGenerator: S3JobManifestGenerator
  - [ ] Report: Bucket, Format, Enabled, Prefix, ReportScope
- [ ] `s3_describe_job` — GET `/v20180820/jobs/{id}`
  - [ ] Parse: Job description with status, progress, failure reasons
- [ ] `s3_list_jobs` — GET `/v20180820/jobs`
  - [ ] jobStatuses, next-token, max-results
- [ ] `s3_update_job_priority` — POST `/v20180820/jobs/{id}/priority`
  - [ ] priority query param
- [ ] `s3_update_job_status` — POST `/v20180820/jobs/{id}/status`
  - [ ] requestedJobStatus: Ready, Cancelled
  - [ ] statusUpdateReason

## Phase 28: Storage Lens (`src/s3_storage_lens.c`)
- [ ] `s3_get_storage_lens_configuration` — GET `/v20180820/storagelens/{id}`
- [ ] `s3_put_storage_lens_configuration` — PUT `/v20180820/storagelens/{id}`
  - [ ] XML: StorageLensConfiguration — Id, AccountLevel (BucketLevel, ActivityMetrics, etc.), Include/Exclude, DataExport, IsEnabled
- [ ] `s3_delete_storage_lens_configuration` — DELETE `/v20180820/storagelens/{id}`
- [ ] `s3_list_storage_lens_configurations` — GET `/v20180820/storagelens`
  - [ ] next-token
- [ ] `s3_create_storage_lens_group` — POST `/v20180820/storagelens/group`
  - [ ] XML: StorageLensGroup — Name, Filter, Tags
- [ ] `s3_delete_storage_lens_group` — DELETE `/v20180820/storagelens/group/{name}`
- [ ] `s3_get_storage_lens_group` — GET `/v20180820/storagelens/group/{name}`
- [ ] `s3_list_storage_lens_groups` — GET `/v20180820/storagelens/group`
  - [ ] next-token
- [ ] `s3_update_storage_lens_group` — PUT `/v20180820/storagelens/group/{name}`
- [ ] `s3_tag_resource` — POST `/v20180820/tags/{arn}`
- [ ] `s3_untag_resource` — DELETE `/v20180820/tags/{arn}`
- [ ] `s3_list_tags_for_resource` — GET `/v20180820/tags/{arn}`

## Phase 29: S3 Express One Zone / Directory Buckets (`src/s3_express.c`)
- [ ] `s3_create_session` — GET `?session` on directory bucket
  - [ ] Returns temporary session credentials (SessionCredentials: AccessKeyId, SecretAccessKey, SessionToken, Expiration)
  - [ ] Session mode: ReadOnly, ReadWrite
  - [ ] SSE-KMS headers for session
- [ ] Session credential caching and refresh
- [ ] Directory bucket creation (different params than general-purpose)
  - [ ] DataRedundancy: SingleAvailabilityZone
  - [ ] BucketType: Directory
  - [ ] LocationConstraint: availability-zone-id (e.g., use1-az4)
- [ ] Zonal endpoints: `https://{bucket}.s3express-{az}.{region}.amazonaws.com`
- [ ] Object operations on directory buckets
  - [ ] Same API but different endpoint, session auth
  - [ ] No versioning, no object lock, no tagging on objects (limited feature set)
  - [ ] CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload supported
  - [ ] ListObjectsV2, HeadObject, DeleteObject, DeleteObjects supported
  - [ ] CopyObject supported (within same AZ only)
- [ ] `s3_list_directory_buckets` — GET with bucket-type=directory query

## Phase 30: S3 Tables (`src/s3_tables.c`)
- [ ] **Table Buckets**
  - [ ] `s3_create_table_bucket` — create table bucket
  - [ ] `s3_delete_table_bucket` — delete table bucket
  - [ ] `s3_get_table_bucket` — get table bucket metadata
  - [ ] `s3_list_table_buckets` — list all table buckets
- [ ] **Table Bucket Configuration**
  - [ ] `s3_get_table_bucket_encryption` / `s3_put_table_bucket_encryption`
  - [ ] `s3_get_table_bucket_policy` / `s3_put_table_bucket_policy` / `s3_delete_table_bucket_policy`
  - [ ] `s3_get_table_bucket_maintenance_configuration` / `s3_put_table_bucket_maintenance_configuration`
- [ ] **Namespaces**
  - [ ] `s3_create_namespace` — create namespace within table bucket
  - [ ] `s3_delete_namespace` — delete namespace
  - [ ] `s3_get_namespace` — get namespace metadata
  - [ ] `s3_list_namespaces` — list namespaces in table bucket
- [ ] **Tables**
  - [ ] `s3_create_table` — create table in namespace
  - [ ] `s3_delete_table` — delete table
  - [ ] `s3_get_table` — get table metadata (schema, location, etc.)
  - [ ] `s3_list_tables` — list tables in namespace
  - [ ] `s3_rename_table` — rename table
  - [ ] `s3_update_table_metadata_location` — update Iceberg metadata location
- [ ] **Table Configuration**
  - [ ] `s3_get_table_encryption` / `s3_put_table_encryption`
  - [ ] `s3_get_table_policy` / `s3_put_table_policy` / `s3_delete_table_policy`
  - [ ] `s3_get_table_maintenance_configuration` / `s3_put_table_maintenance_configuration`
  - [ ] `s3_get_table_maintenance_job_status`
- [ ] Note: S3 Tables has its own endpoint, not the standard S3 endpoint

## Phase 31: S3 Vectors (`src/s3_vectors.c`)
- [ ] **Vector Buckets**
  - [ ] `s3_create_vector_bucket` — create vector bucket
  - [ ] `s3_delete_vector_bucket` — delete vector bucket
  - [ ] `s3_get_vector_bucket` — get vector bucket metadata
  - [ ] `s3_list_vector_buckets` — list vector buckets
- [ ] **Vector Bucket Policy**
  - [ ] `s3_get_vector_bucket_policy` / `s3_put_vector_bucket_policy` / `s3_delete_vector_bucket_policy`
- [ ] **Indexes**
  - [ ] `s3_create_index` — create vector index (dimension, distance metric)
  - [ ] `s3_delete_index` — delete index
  - [ ] `s3_get_index` — get index metadata
  - [ ] `s3_list_indexes` — list indexes in vector bucket
- [ ] **Vector CRUD**
  - [ ] `s3_put_vectors` — insert/upsert vectors (batch)
  - [ ] `s3_get_vectors` — get vectors by key (batch)
  - [ ] `s3_delete_vectors` — delete vectors by key (batch)
  - [ ] `s3_list_vectors` — list all vectors in index
  - [ ] `s3_query_vectors` — k-nearest-neighbor query
    - [ ] Query vector, top-k, filter expression, metadata fields to return
- [ ] Note: S3 Vectors has its own endpoint

## Phase 32: S3 on Outposts (`src/s3_outposts.c`)
- [ ] `s3_create_endpoint` — create S3 on Outposts endpoint
  - [ ] OutpostId, SubnetId, SecurityGroupId, AccessType (Private, CustomerOwnedIp)
- [ ] `s3_delete_endpoint` — delete endpoint
- [ ] `s3_list_endpoints` — list endpoints
  - [ ] next-token, max-results
- [ ] `s3_list_outposts_with_s3` — list Outposts with S3 capacity
- [ ] `s3_list_shared_endpoints` — list shared endpoints for an Outpost
- [ ] Note: Uses S3 Outposts endpoint (`s3-outposts.{region}.amazonaws.com`)
- [ ] Object operations on Outposts use access point ARN addressing

## Phase 33: SigV4A (for Multi-Region Access Points) (`src/s3_sigv4.c` extension)
- [ ] ECDSA P-256 key derivation from AWS secret key
  - [ ] Derive signing key using HMAC chain
  - [ ] Convert to EC private key
- [ ] SigV4A canonical request (same as SigV4 but region = "*")
- [ ] ECDSA-P256-SHA256 signature computation
  - [ ] This requires implementing or importing EC point operations
  - [ ] Alternative: optional OpenSSL dependency just for SigV4A
- [ ] `x-amz-region-set: *` header
- [ ] Decision: inline ECDSA implementation (~500 lines) or optional `-lssl -lcrypto` for this one feature

## Phase 34: Additional Testing
- [ ] Unit tests for every crypto primitive
- [ ] SigV4 test suite (AWS published test cases)
- [ ] SigV4A test suite
- [ ] XML parser fuzzing / edge cases
- [ ] Integration tests (MinIO):
  - [ ] Object CRUD round-trip
  - [ ] Multipart upload (small + large)
  - [ ] Streaming upload/download
  - [ ] Batch delete
  - [ ] Presigned URLs (generate + use with plain curl)
  - [ ] SSE-S3, SSE-C round-trip
  - [ ] Versioning (enable, put versions, list versions, get specific version)
  - [ ] Object tagging CRUD
  - [ ] Object lock (retention, legal hold)
  - [ ] Bucket configuration (lifecycle, CORS, policy, etc.)
  - [ ] Async operations
  - [ ] Thread pool parallel upload
  - [ ] Retry on simulated failures
  - [ ] List pagination (>1000 objects)
  - [ ] Directory buckets (if MinIO supports)
- [ ] Integration tests (AWS):
  - [ ] All MinIO tests + AWS-specific:
  - [ ] SSE-KMS
  - [ ] Transfer Acceleration
  - [ ] Glacier restore
  - [ ] Select Object Content
  - [ ] Access Points
  - [ ] Multi-Region Access Points
  - [ ] S3 Express One Zone
  - [ ] Batch Operations
  - [ ] Storage Lens

## Phase 35: Examples and Documentation
- [ ] `examples/example_basic.c` — put/get/delete/list
- [ ] `examples/example_multipart.c` — multipart upload
- [ ] `examples/example_async.c` — async ops with futures
- [ ] `examples/example_pool.c` — thread pool parallel upload
- [ ] `examples/example_presign.c` — presigned URLs
- [ ] `examples/example_streaming.c` — streaming upload/download
- [ ] `examples/example_sync.c` — directory sync
- [ ] `examples/example_sse.c` — server-side encryption
- [ ] `examples/example_select.c` — S3 Select SQL
- [ ] `examples/example_versioning.c` — versioned objects
- [ ] API documentation in header comments (every public function)

---

# Summary

| Category | Operations | Phase |
|---|---|---|
| Project skeleton + build | — | 0 |
| Crypto primitives | 8 algorithms | 1 |
| XML engine | parser + builder | 2 |
| SigV4 signing | — | 3 |
| HTTP layer | — | 4 |
| Error handling | ~80 error codes | 5 |
| Client lifecycle | 3 | 6 |
| Logging | — | 7 |
| Retry engine | — | 8 |
| Object CRUD | ~12 | 9 |
| Object config (tag/ACL/lock/restore) | ~10 | 10 |
| List operations | ~3 | 11 |
| Multipart upload | ~8 | 12 |
| Bucket CRUD | ~6 | 13 |
| Bucket configuration | ~50 | 14 |
| SSE helpers | — | 15 |
| Checksum support | — | 16 |
| Presigned URLs | ~7 | 17 |
| SelectObjectContent | 1 | 18 |
| Async (curl_multi + futures) | all ops × 2 | 19 |
| Thread pool | — | 20 |
| High-level helpers | ~12 | 21 |
| S3 Control base | — | 22 |
| Access Points | ~8 | 23 |
| Object Lambda | ~9 | 24 |
| Access Grants | ~16 | 25 |
| Multi-Region Access Points | ~8 | 26 |
| Batch Operations | ~5 | 27 |
| Storage Lens | ~11 | 28 |
| Express One Zone | ~5 | 29 |
| S3 Tables | ~25 | 30 |
| S3 Vectors | ~17 | 31 |
| S3 on Outposts | ~5 | 32 |
| SigV4A (ECDSA) | — | 33 |
| Testing | — | 34 |
| Examples + docs | ~10 | 35 |
| **TOTAL** | **~350+** | **35 phases** |

Estimated total: ~15,000–20,000 lines of C across s3.h + src/*.c
