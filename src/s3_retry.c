/*
 * libs3 — Retry logic with exponential backoff and jitter
 */

#include "s3_internal.h"

bool s3__should_retry(const s3_client *c, s3_status status, int attempt) {
    if (!c) return false;
    if (attempt >= c->retry_policy.max_retries) return false;

    /* Always retry transient CURL errors (DNS failures, connection resets, etc.) */
    if (status == S3_STATUS_CURL_ERROR) {
        return true;
    }

    /* Throttling errors */
    if (c->retry_policy.retry_on_throttle) {
        if (status == S3_STATUS_SLOW_DOWN ||
            status == S3_STATUS_SERVICE_UNAVAILABLE) {
            return true;
        }
    }

    /* 5xx server errors */
    if (c->retry_policy.retry_on_5xx) {
        if (status == S3_STATUS_HTTP_INTERNAL_SERVER_ERROR ||
            status == S3_STATUS_HTTP_BAD_GATEWAY ||
            status == S3_STATUS_HTTP_SERVICE_UNAVAILABLE ||
            status == S3_STATUS_HTTP_GATEWAY_TIMEOUT) {
            return true;
        }
    }

    /* Timeout / connection errors */
    if (c->retry_policy.retry_on_timeout) {
        if (status == S3_STATUS_TIMEOUT ||
            status == S3_STATUS_REQUEST_TIMEOUT ||
            status == S3_STATUS_CONNECTION_FAILED) {
            return true;
        }
    }

    return false;
}

int s3__retry_delay_ms(const s3_client *c, int attempt) {
    if (!c) return 0;

    const s3_retry_policy *rp = &c->retry_policy;

    /* Compute base delay: base_delay_ms * backoff_multiplier^attempt */
    double delay = (double)rp->base_delay_ms;
    for (int i = 0; i < attempt; i++) {
        delay *= rp->backoff_multiplier;
    }

    /* Cap at max_delay_ms */
    if (delay > (double)rp->max_delay_ms) {
        delay = (double)rp->max_delay_ms;
    }

    /* Apply jitter: multiply by random factor in [0.5, 1.0) */
    if (rp->jitter) {
        double jitter_factor = 0.5 + ((double)rand() / (double)RAND_MAX) * 0.5;
        delay *= jitter_factor;
    }

    return (int)delay;
}
