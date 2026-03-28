/*
 * libs3 -- S3 Control API base
 *
 * Architecture:
 * The S3 Control API uses a different endpoint from the standard S3 data plane:
 *   https://{account_id}.s3-control.{region}.amazonaws.com
 *
 * All control API operations (Access Points, Object Lambda, Batch Operations,
 * Storage Lens, Access Grants, Multi-Region Access Points, etc.) share this
 * endpoint and require the x-amz-account-id header.
 *
 * Rather than a shared helper function, each control API file uses s3__request
 * directly with use_control_endpoint=true. The s3__build_url function in
 * s3_http.c already handles control endpoint URL construction using the
 * client's account_id and region. Each file adds the required
 * x-amz-account-id header via extra_headers.
 *
 * The API path is passed as the `key` parameter (e.g.,
 * "v20180820/accesspoint/my-ap"), and bucket is set to nullptr since these
 * are account-level operations routed through the control endpoint.
 *
 * This file exists as the architectural anchor for control API operations.
 * If shared helpers become necessary in the future (e.g., common XML
 * namespace handling or pagination), they should be added here and declared
 * in s3_internal.h.
 */

#include "s3_internal.h"

/* Currently no shared helpers are needed -- each control API file
 * (s3_access_point.c, s3_object_lambda.c, s3_batch_ops.c, etc.) calls
 * s3__request directly with:
 *
 *   .use_control_endpoint = true
 *   .bucket               = nullptr
 *   .key                  = "v20180820/accesspoint/{name}"  (or similar path)
 *   .extra_headers        = curl_slist containing "x-amz-account-id: ..."
 *
 * The signing module (s3_sigv4.c) handles the "s3" service name for
 * standard requests. For control API requests routed through
 * use_control_endpoint, the host-based routing ensures the correct
 * endpoint is hit.
 */
