/*
 * libs3 -- S3 Control API: Batch Operations
 *
 * CreateJob, DescribeJob, ListJobs,
 * UpdateJobPriority, UpdateJobStatus, result free.
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Build the x-amz-account-id header list
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *account_id_header(const s3_client *c)
{
    char hdr[256];
    snprintf(hdr, sizeof(hdr), "x-amz-account-id: %s",
             c->account_id ? c->account_id : "");
    return curl_slist_append(nullptr, hdr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Parse job status enum from string
 * ═══════════════════════════════════════════════════════════════════════════ */

static s3_batch_job_status parse_job_status_string(const char *s)
{
    if (!s || !s[0]) return S3_JOB_STATUS_NEW;

    if (strcmp(s, "Active") == 0)      return S3_JOB_STATUS_ACTIVE;
    if (strcmp(s, "Cancelled") == 0)   return S3_JOB_STATUS_CANCELLED;
    if (strcmp(s, "Cancelling") == 0)  return S3_JOB_STATUS_CANCELLING;
    if (strcmp(s, "Complete") == 0)    return S3_JOB_STATUS_COMPLETE;
    if (strcmp(s, "Completing") == 0)  return S3_JOB_STATUS_COMPLETING;
    if (strcmp(s, "Failed") == 0)      return S3_JOB_STATUS_FAILED;
    if (strcmp(s, "Failing") == 0)     return S3_JOB_STATUS_FAILING;
    if (strcmp(s, "New") == 0)         return S3_JOB_STATUS_NEW;
    if (strcmp(s, "Paused") == 0)      return S3_JOB_STATUS_PAUSED;
    if (strcmp(s, "Pausing") == 0)     return S3_JOB_STATUS_PAUSING;
    if (strcmp(s, "Preparing") == 0)   return S3_JOB_STATUS_PREPARING;
    if (strcmp(s, "Ready") == 0)       return S3_JOB_STATUS_READY;
    if (strcmp(s, "Suspended") == 0)   return S3_JOB_STATUS_SUSPENDED;

    return S3_JOB_STATUS_NEW;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper — Parse s3_job from XML
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_job(const char *xml, size_t len, s3_job *job)
{
    const char *val;
    size_t vlen;

    if (s3__xml_find(xml, len, "JobId", &val, &vlen))
        s3__xml_decode_entities(val, vlen, job->job_id, sizeof(job->job_id));

    if (s3__xml_find(xml, len, "Status", &val, &vlen)) {
        char tmp[64];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        job->status = parse_job_status_string(tmp);
    }

    if (s3__xml_find(xml, len, "Description", &val, &vlen))
        s3__xml_decode_entities(val, vlen, job->description, sizeof(job->description));

    if (s3__xml_find(xml, len, "Priority", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        job->priority = (int)strtol(tmp, nullptr, 10);
    }

    if (s3__xml_find(xml, len, "CreationTime", &val, &vlen))
        s3__xml_decode_entities(val, vlen, job->creation_time, sizeof(job->creation_time));

    if (s3__xml_find(xml, len, "TerminationDate", &val, &vlen))
        s3__xml_decode_entities(val, vlen, job->termination_date, sizeof(job->termination_date));

    /* Progress counters */
    if (s3__xml_find_in(xml, len, "ProgressSummary", "TotalNumberOfTasks", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        job->total_objects = strtoll(tmp, nullptr, 10);
    }

    if (s3__xml_find_in(xml, len, "ProgressSummary", "NumberOfTasksSucceeded", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        job->succeeded = strtoll(tmp, nullptr, 10);
    }

    if (s3__xml_find_in(xml, len, "ProgressSummary", "NumberOfTasksFailed", &val, &vlen)) {
        char tmp[32];
        size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
        memcpy(tmp, val, n);
        tmp[n] = '\0';
        job->failed = strtoll(tmp, nullptr, 10);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_create_job
 * POST /v20180820/jobs
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_create_job(
    s3_client *c, const char *manifest_xml, const char *operation_xml,
    const char *report_xml, const char *role_arn,
    int priority, bool confirmation_required,
    const char *description, char *job_id_out, size_t job_id_buf_size)
{
    if (!c || !manifest_xml || !operation_xml || !report_xml ||
        !role_arn || !job_id_out || job_id_buf_size == 0)
        return S3_STATUS_INVALID_ARGUMENT;

    job_id_out[0] = '\0';

    /* Build XML body */
    s3_buf body;
    s3_buf_init(&body);
    s3__xml_buf_declaration(&body);
    s3_buf_append_str(&body,
        "<CreateJobRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">");

    /* Manifest — caller provides pre-built XML fragment */
    s3_buf_append_str(&body, manifest_xml);

    /* Operation — caller provides pre-built XML fragment */
    s3_buf_append_str(&body, operation_xml);

    /* Report — caller provides pre-built XML fragment */
    s3_buf_append_str(&body, report_xml);

    s3__xml_buf_element(&body, "RoleArn", role_arn);
    s3__xml_buf_element_int(&body, "Priority", priority);
    s3__xml_buf_element_bool(&body, "ConfirmationRequired", confirmation_required);

    if (description && description[0])
        s3__xml_buf_element(&body, "Description", description);

    s3_buf_append_str(&body, "</CreateJobRequest>");

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = "v20180820/jobs",
        .extra_headers       = hdrs,
        .upload_data         = body.data,
        .upload_len          = body.len,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *val;
        size_t vlen;
        if (s3__xml_find(c->response.data, c->response.len,
                         "JobId", &val, &vlen)) {
            size_t n = vlen < job_id_buf_size - 1 ? vlen : job_id_buf_size - 1;
            memcpy(job_id_out, val, n);
            job_id_out[n] = '\0';
        }
    }

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_describe_job
 * GET /v20180820/jobs/{id}
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_describe_job(s3_client *c, const char *job_id, s3_job *result)
{
    if (!c || !job_id || !job_id[0] || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    char path[512];
    snprintf(path, sizeof(path), "v20180820/jobs/%s", job_id);

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = path,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data)
        parse_job(c->response.data, c->response.len, result);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_jobs
 * GET /v20180820/jobs?...
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    s3_job *items;
    int     count;
    int     cap;
} job_array;

static int job_array_cb(const char *element, size_t element_len, void *userdata)
{
    job_array *arr = (job_array *)userdata;

    if (arr->count >= arr->cap) {
        int new_cap = arr->cap ? arr->cap * 2 : 16;
        s3_job *p = (s3_job *)S3_REALLOC(
            arr->items, (size_t)new_cap * sizeof(s3_job));
        if (!p) return -1;
        arr->items = p;
        arr->cap = new_cap;
    }

    s3_job *job = &arr->items[arr->count];
    memset(job, 0, sizeof(*job));
    parse_job(element, element_len, job);
    arr->count++;
    return 0;
}

s3_status s3_list_jobs(
    s3_client *c, const char *const *statuses, int status_count,
    const char *next_token, int max_results, s3_list_jobs_result *result)
{
    if (!c || !result)
        return S3_STATUS_INVALID_ARGUMENT;

    memset(result, 0, sizeof(*result));

    /* Build query string */
    s3_buf qbuf;
    s3_buf_init(&qbuf);

    for (int i = 0; i < status_count; i++) {
        if (!statuses || !statuses[i]) continue;
        if (qbuf.len > 0) s3_buf_append_str(&qbuf, "&");
        s3_buf_append_str(&qbuf, "jobStatuses=");
        s3_buf_append_str(&qbuf, statuses[i]);
    }

    if (next_token && next_token[0]) {
        if (qbuf.len > 0) s3_buf_append_str(&qbuf, "&");
        s3_buf_append_str(&qbuf, "nextToken=");
        s3_buf_append_str(&qbuf, next_token);
    }

    if (max_results > 0) {
        if (qbuf.len > 0) s3_buf_append_str(&qbuf, "&");
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "maxResults=%d", max_results);
        s3_buf_append_str(&qbuf, tmp);
    }

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "GET",
        .bucket              = nullptr,
        .key                 = "v20180820/jobs",
        .query_string        = qbuf.len > 0 ? qbuf.data : nullptr,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    if (status == S3_STATUS_OK && c->response.data) {
        const char *xml = c->response.data;
        size_t len = c->response.len;

        /* Parse job list — each job is inside a <Member> element */
        job_array arr = {0};
        s3__xml_each(xml, len, "Member", job_array_cb, &arr);

        result->jobs = arr.items;
        result->job_count = arr.count;

        /* Parse NextToken */
        const char *val;
        size_t vlen;
        if (s3__xml_find(xml, len, "NextToken", &val, &vlen))
            s3__xml_decode_entities(val, vlen, result->next_token,
                                    sizeof(result->next_token));
    }

    curl_slist_free_all(hdrs);
    s3_buf_free(&qbuf);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_update_job_priority
 * POST /v20180820/jobs/{id}/priority?priority=N
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_update_job_priority(
    s3_client *c, const char *job_id, int priority)
{
    if (!c || !job_id || !job_id[0])
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/jobs/%s/priority", job_id);

    char query[64];
    snprintf(query, sizeof(query), "priority=%d", priority);

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = path,
        .query_string        = query,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_update_job_status
 * POST /v20180820/jobs/{id}/status?requestedJobStatus=X&statusUpdateReason=Y
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_update_job_status(
    s3_client *c, const char *job_id, const char *requested_status,
    const char *reason)
{
    if (!c || !job_id || !job_id[0] || !requested_status)
        return S3_STATUS_INVALID_ARGUMENT;

    char path[512];
    snprintf(path, sizeof(path), "v20180820/jobs/%s/status", job_id);

    char query[2048];
    if (reason && reason[0]) {
        snprintf(query, sizeof(query),
                 "requestedJobStatus=%s&statusUpdateReason=%s",
                 requested_status, reason);
    } else {
        snprintf(query, sizeof(query),
                 "requestedJobStatus=%s", requested_status);
    }

    struct curl_slist *hdrs = account_id_header(c);

    s3_request_params params = {
        .method              = "POST",
        .bucket              = nullptr,
        .key                 = path,
        .query_string        = query,
        .extra_headers       = hdrs,
        .collect_response    = true,
        .use_control_endpoint = true,
    };

    s3_status status = s3__request(c, &params);

    curl_slist_free_all(hdrs);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_jobs_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_list_jobs_result_free(s3_list_jobs_result *r)
{
    if (!r) return;
    S3_FREE(r->jobs);
    r->jobs = nullptr;
    r->job_count = 0;
    r->next_token[0] = '\0';
}
