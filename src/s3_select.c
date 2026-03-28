/*
 * libs3 -- S3 Select (SelectObjectContent)
 *
 * Implements the SelectObjectContent API which allows running SQL
 * expressions against objects stored in S3 (CSV, JSON, Parquet).
 *
 * NOTE: The S3 Select response uses a binary event stream format.
 * This initial implementation passes the raw response bytes to the
 * user's write_fn callback. Full event stream parsing (extracting
 * Records, Stats, Progress, End events) can be added in a future
 * iteration.
 */

#define _POSIX_C_SOURCE 200809L
#include "s3_internal.h"
#include <strings.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct curl_slist *add_header_if(struct curl_slist *h,
                                        const char *name, const char *value)
{
    if (value && value[0]) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s: %s", name, value);
        h = curl_slist_append(h, buf);
    }
    return h;
}

/*
 * Append a single XML element only if `value` is non-null and non-empty.
 */
static int xml_element_if(s3_buf *b, const char *tag, const char *value)
{
    if (value && value[0])
        return s3__xml_buf_element(b, tag, value);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Build the SelectObjectContent XML request body
 * ═══════════════════════════════════════════════════════════════════════════ */

static int build_select_request_xml(s3_buf *body, const s3_select_object_opts *opts)
{
    if (s3__xml_buf_declaration(body) < 0) return -1;
    if (s3_buf_append_str(body,
            "<SelectObjectContentRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">") < 0)
        return -1;

    /* Expression */
    if (s3__xml_buf_element(body, "Expression", opts->expression) < 0)
        return -1;

    /* ExpressionType is always SQL */
    if (s3__xml_buf_element(body, "ExpressionType", "SQL") < 0)
        return -1;

    /* ── InputSerialization ── */
    if (s3__xml_buf_open(body, "InputSerialization") < 0) return -1;

    if (opts->input_format) {
        if (strcasecmp(opts->input_format, "CSV") == 0) {
            if (s3__xml_buf_open(body, "CSV") < 0) return -1;
            xml_element_if(body, "FileHeaderInfo", opts->csv_file_header_info);
            xml_element_if(body, "RecordDelimiter", opts->csv_record_delimiter);
            xml_element_if(body, "FieldDelimiter", opts->csv_field_delimiter);
            xml_element_if(body, "QuoteCharacter", opts->csv_quote_character);
            xml_element_if(body, "QuoteEscapeCharacter", opts->csv_quote_escape_character);
            xml_element_if(body, "Comments", opts->csv_comments);
            if (opts->csv_allow_quoted_record_delimiter) {
                s3__xml_buf_element_bool(body, "AllowQuotedRecordDelimiter", true);
            }
            if (s3__xml_buf_close(body, "CSV") < 0) return -1;
        } else if (strcasecmp(opts->input_format, "JSON") == 0) {
            if (s3__xml_buf_open(body, "JSON") < 0) return -1;
            xml_element_if(body, "Type", opts->json_type);
            if (s3__xml_buf_close(body, "JSON") < 0) return -1;
        } else if (strcasecmp(opts->input_format, "Parquet") == 0) {
            /* Parquet has no configurable options */
            if (s3_buf_append_str(body, "<Parquet/>") < 0) return -1;
        }
    }

    if (s3__xml_buf_close(body, "InputSerialization") < 0) return -1;

    /* ── OutputSerialization ── */
    if (s3__xml_buf_open(body, "OutputSerialization") < 0) return -1;

    if (opts->output_format) {
        if (strcasecmp(opts->output_format, "CSV") == 0) {
            if (s3__xml_buf_open(body, "CSV") < 0) return -1;
            xml_element_if(body, "RecordDelimiter", opts->csv_out_record_delimiter);
            xml_element_if(body, "FieldDelimiter", opts->csv_out_field_delimiter);
            xml_element_if(body, "QuoteCharacter", opts->csv_out_quote_character);
            xml_element_if(body, "QuoteEscapeCharacter", opts->csv_out_quote_escape_character);
            if (s3__xml_buf_close(body, "CSV") < 0) return -1;
        } else if (strcasecmp(opts->output_format, "JSON") == 0) {
            if (s3__xml_buf_open(body, "JSON") < 0) return -1;
            xml_element_if(body, "RecordDelimiter", opts->json_out_record_delimiter);
            if (s3__xml_buf_close(body, "JSON") < 0) return -1;
        }
    }

    if (s3__xml_buf_close(body, "OutputSerialization") < 0) return -1;

    /* ── ScanRange (optional) ── */
    if (opts->scan_start > 0 || opts->scan_end > 0) {
        if (s3__xml_buf_open(body, "ScanRange") < 0) return -1;
        if (opts->scan_start > 0)
            s3__xml_buf_element_int(body, "Start", opts->scan_start);
        if (opts->scan_end > 0)
            s3__xml_buf_element_int(body, "End", opts->scan_end);
        if (s3__xml_buf_close(body, "ScanRange") < 0) return -1;
    }

    if (s3_buf_append_str(body, "</SelectObjectContentRequest>") < 0)
        return -1;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SelectObjectContent
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_select_object_content(s3_client *c, const char *bucket,
                                   const char *key,
                                   const s3_select_object_opts *opts,
                                   s3_write_fn write_fn, void *userdata)
{
    if (!c || !bucket || !key || !opts || !opts->expression)
        return S3_STATUS_INVALID_ARGUMENT;

    /* Build the XML request body */
    s3_buf body;
    s3_buf_init(&body);

    if (build_select_request_xml(&body, opts) < 0) {
        s3_buf_free(&body);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    /* Headers */
    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");
    hdrs = add_header_if(hdrs, "x-amz-expected-bucket-owner",
                         opts->expected_bucket_owner);
    if (opts->request_payer)
        hdrs = curl_slist_append(hdrs, "x-amz-request-payer: requester");

    /* Query: select&select-type=2 */
    s3_request_params p = {
        .method            = "POST",
        .bucket            = bucket,
        .key               = key,
        .query_string      = "select&select-type=2",
        .extra_headers     = hdrs,
        .upload_data       = body.data,
        .upload_len        = body.len,
        .write_fn          = write_fn,
        .write_userdata    = userdata,
        .collect_response  = false,
    };

    /*
     * NOTE: The response is a binary event stream (application/octet-stream).
     * We pass the raw bytes directly to the caller's write_fn callback.
     * Full event stream parsing (Records, Stats, Progress, End, Continuation
     * messages) can be added in a future iteration by implementing the
     * AWS event stream binary format decoder.
     */
    s3_status st = s3__request(c, &p);

    curl_slist_free_all(hdrs);
    s3_buf_free(&body);
    return st;
}
