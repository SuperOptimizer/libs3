/*
 * libs3 — High-level helper functions
 */

#include "s3_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define S3_DEFAULT_PART_SIZE      (64 * 1024 * 1024)   /* 64 MB */
#define S3_MIN_PART_SIZE          (5 * 1024 * 1024)    /* 5 MB */
#define S3_MAX_DELETE_BATCH       1000
#define S3_LIST_MAX_KEYS          1000

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_upload_file
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_upload_file(s3_client *c, const char *bucket, const char *key,
                         const char *filepath, const s3_upload_file_opts *opts,
                         s3_put_object_result *result) {
    if (!c || !bucket || !key || !filepath)
        return S3_STATUS_INVALID_ARGUMENT;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return S3_STATUS_INTERNAL_ERROR;

    /* Determine file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return S3_STATUS_INTERNAL_ERROR;
    }
    long fsize = ftell(fp);
    if (fsize < 0) {
        fclose(fp);
        return S3_STATUS_INTERNAL_ERROR;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return S3_STATUS_INTERNAL_ERROR;
    }

    size_t file_size = (size_t)fsize;
    size_t part_size = (opts && opts->part_size >= S3_MIN_PART_SIZE)
                           ? opts->part_size : S3_DEFAULT_PART_SIZE;

    /* Detect content type if not specified */
    const char *content_type = (opts && opts->content_type)
                                   ? opts->content_type
                                   : s3_detect_content_type(filepath);

    s3_status status;

    if (file_size <= part_size) {
        /* Single-part upload: read entire file into memory */
        void *buf = S3_MALLOC(file_size > 0 ? file_size : 1);
        if (!buf) {
            fclose(fp);
            return S3_STATUS_OUT_OF_MEMORY;
        }

        if (file_size > 0) {
            size_t nread = fread(buf, 1, file_size, fp);
            if (nread != file_size) {
                S3_FREE(buf);
                fclose(fp);
                return S3_STATUS_INTERNAL_ERROR;
            }
        }
        fclose(fp);

        s3_put_object_opts put_opts;
        memset(&put_opts, 0, sizeof(put_opts));
        put_opts.content_type = content_type;
        if (opts) {
            put_opts.storage_class = opts->storage_class;
            put_opts.acl = opts->acl;
            put_opts.encryption = opts->encryption;
            put_opts.tagging = opts->tagging;
            put_opts.metadata = opts->metadata;
            put_opts.metadata_count = opts->metadata_count;
            put_opts.progress_fn = opts->progress_fn;
            put_opts.progress_userdata = opts->progress_userdata;
            if (opts->checksum_algorithm != S3_CHECKSUM_NONE) {
                put_opts.checksum.algorithm = opts->checksum_algorithm;
            }
        }

        status = s3_put_object(c, bucket, key, buf, file_size, &put_opts, result);
        S3_FREE(buf);
        return status;
    }

    /* Multipart upload */
    s3_create_multipart_upload_opts mpu_opts;
    memset(&mpu_opts, 0, sizeof(mpu_opts));
    mpu_opts.content_type = content_type;
    if (opts) {
        mpu_opts.storage_class = opts->storage_class;
        mpu_opts.acl = opts->acl;
        mpu_opts.encryption = opts->encryption;
        mpu_opts.tagging = opts->tagging;
        mpu_opts.metadata = opts->metadata;
        mpu_opts.metadata_count = opts->metadata_count;
        mpu_opts.checksum_algorithm = opts->checksum_algorithm;
    }

    s3_multipart_upload upload;
    memset(&upload, 0, sizeof(upload));
    status = s3_create_multipart_upload(c, bucket, key, &mpu_opts, &upload);
    if (status != S3_STATUS_OK) {
        fclose(fp);
        return status;
    }

    /* Calculate number of parts */
    int num_parts = (int)((file_size + part_size - 1) / part_size);
    s3_upload_part_result *parts = (s3_upload_part_result *)S3_CALLOC(
        (size_t)num_parts, sizeof(s3_upload_part_result));
    if (!parts) {
        fclose(fp);
        (void)s3_abort_multipart_upload(c, bucket, key, upload.upload_id);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    void *buf = S3_MALLOC(part_size);
    if (!buf) {
        S3_FREE(parts);
        fclose(fp);
        (void)s3_abort_multipart_upload(c, bucket, key, upload.upload_id);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    s3_upload_part_opts up_opts;
    memset(&up_opts, 0, sizeof(up_opts));
    if (opts) {
        up_opts.encryption = opts->encryption;
        up_opts.progress_fn = opts->progress_fn;
        up_opts.progress_userdata = opts->progress_userdata;
    }

    for (int i = 0; i < num_parts; i++) {
        size_t this_part_size = part_size;
        if ((size_t)(i + 1) * part_size > file_size) {
            this_part_size = file_size - (size_t)i * part_size;
        }

        size_t nread = fread(buf, 1, this_part_size, fp);
        if (nread != this_part_size) {
            S3_FREE(buf);
            S3_FREE(parts);
            fclose(fp);
            (void)s3_abort_multipart_upload(c, bucket, key, upload.upload_id);
            return S3_STATUS_INTERNAL_ERROR;
        }

        status = s3_upload_part(c, bucket, key, upload.upload_id,
                                i + 1, buf, this_part_size,
                                &up_opts, &parts[i]);
        if (status != S3_STATUS_OK) {
            S3_FREE(buf);
            S3_FREE(parts);
            fclose(fp);
            (void)s3_abort_multipart_upload(c, bucket, key, upload.upload_id);
            return status;
        }
    }

    S3_FREE(buf);
    fclose(fp);

    /* Complete multipart upload */
    s3_complete_multipart_result complete_result;
    memset(&complete_result, 0, sizeof(complete_result));
    status = s3_complete_multipart_upload(c, bucket, key, upload.upload_id,
                                          parts, num_parts, &complete_result);
    S3_FREE(parts);

    if (status != S3_STATUS_OK) {
        (void)s3_abort_multipart_upload(c, bucket, key, upload.upload_id);
        return status;
    }

    /* Populate result from complete_result */
    if (result) {
        memset(result, 0, sizeof(*result));
        memcpy(result->etag, complete_result.etag, sizeof(result->etag));
        memcpy(result->version_id, complete_result.version_id, sizeof(result->version_id));
        memcpy(result->checksum_crc32, complete_result.checksum_crc32,
               sizeof(result->checksum_crc32));
        memcpy(result->checksum_crc32c, complete_result.checksum_crc32c,
               sizeof(result->checksum_crc32c));
        memcpy(result->checksum_sha1, complete_result.checksum_sha1,
               sizeof(result->checksum_sha1));
        memcpy(result->checksum_sha256, complete_result.checksum_sha256,
               sizeof(result->checksum_sha256));
    }

    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_download_file — Write callback for streaming to a FILE*
 * ═══════════════════════════════════════════════════════════════════════════ */

static int s3__download_write_cb(const void *data, size_t len, void *userdata) {
    FILE *fp = (FILE *)userdata;
    size_t written = fwrite(data, 1, len, fp);
    return (written == len) ? 0 : -1;
}

s3_status s3_download_file(s3_client *c, const char *bucket, const char *key,
                           const char *filepath, const s3_download_file_opts *opts) {
    if (!c || !bucket || !key || !filepath)
        return S3_STATUS_INVALID_ARGUMENT;

    FILE *fp = fopen(filepath, "wb");
    if (!fp) return S3_STATUS_INTERNAL_ERROR;

    s3_get_object_opts get_opts;
    memset(&get_opts, 0, sizeof(get_opts));
    if (opts) {
        get_opts.encryption = opts->encryption;
        get_opts.version_id = opts->version_id;
        get_opts.checksum_mode = opts->checksum_mode;
        get_opts.progress_fn = opts->progress_fn;
        get_opts.progress_userdata = opts->progress_userdata;
    }

    s3_status status = s3_get_object_stream(c, bucket, key,
                                             s3__download_write_cb, fp,
                                             &get_opts);
    if (fclose(fp) != 0 && status == S3_STATUS_OK) {
        status = S3_STATUS_INTERNAL_ERROR;
    }

    /* On failure, remove the partially written file */
    if (status != S3_STATUS_OK) {
        remove(filepath);
    }

    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_object_exists
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_object_exists(s3_client *c, const char *bucket, const char *key,
                           bool *exists) {
    if (!c || !bucket || !key || !exists)
        return S3_STATUS_INVALID_ARGUMENT;

    s3_head_object_result head_result;
    memset(&head_result, 0, sizeof(head_result));

    s3_status status = s3_head_object(c, bucket, key, nullptr, &head_result);

    if (status == S3_STATUS_OK) {
        *exists = true;
        return S3_STATUS_OK;
    }

    if (status == S3_STATUS_NO_SUCH_KEY ||
        status == S3_STATUS_HTTP_NOT_FOUND) {
        *exists = false;
        return S3_STATUS_OK;
    }

    /* Propagate other errors */
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_list_all_objects
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_list_all_objects(s3_client *c, const char *bucket,
                              const s3_list_objects_opts *opts,
                              s3_object_info **objects_out, int *count_out) {
    if (!c || !bucket || !objects_out || !count_out)
        return S3_STATUS_INVALID_ARGUMENT;

    *objects_out = nullptr;
    *count_out = 0;

    s3_object_info *all_objects = nullptr;
    int total_count = 0;
    int total_cap = 0;

    s3_list_objects_opts local_opts;
    if (opts) {
        memcpy(&local_opts, opts, sizeof(local_opts));
    } else {
        memset(&local_opts, 0, sizeof(local_opts));
    }
    local_opts.continuation_token = nullptr;

    char continuation_token[1024];
    continuation_token[0] = '\0';

    do {
        if (continuation_token[0] != '\0') {
            local_opts.continuation_token = continuation_token;
        }

        s3_list_objects_result page;
        memset(&page, 0, sizeof(page));

        s3_status status = s3_list_objects_v2(c, bucket, &local_opts, &page);
        if (status != S3_STATUS_OK) {
            S3_FREE(all_objects);
            return status;
        }

        if (page.object_count > 0) {
            int new_count = total_count + page.object_count;
            if (new_count > total_cap) {
                int new_cap = total_cap ? total_cap : 128;
                while (new_cap < new_count) new_cap *= 2;
                s3_object_info *tmp = (s3_object_info *)S3_REALLOC(
                    all_objects, (size_t)new_cap * sizeof(s3_object_info));
                if (!tmp) {
                    S3_FREE(page.objects);
                    S3_FREE(all_objects);
                    return S3_STATUS_OUT_OF_MEMORY;
                }
                all_objects = tmp;
                total_cap = new_cap;
            }

            memcpy(&all_objects[total_count], page.objects,
                   (size_t)page.object_count * sizeof(s3_object_info));
            total_count = new_count;
        }

        /* Save continuation token for next iteration */
        if (page.is_truncated && page.next_continuation_token[0] != '\0') {
            strncpy(continuation_token, page.next_continuation_token,
                    sizeof(continuation_token) - 1);
            continuation_token[sizeof(continuation_token) - 1] = '\0';
        } else {
            continuation_token[0] = '\0';
        }

        /* Free page results */
        S3_FREE(page.objects);
        for (int i = 0; i < page.prefix_count; i++) {
            S3_FREE(page.common_prefixes[i]);
        }
        S3_FREE(page.common_prefixes);

        if (!page.is_truncated) break;

    } while (true);

    *objects_out = all_objects;
    *count_out = total_count;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_all_objects
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_all_objects(s3_client *c, const char *bucket, const char *prefix,
                                bool include_versions, int *deleted_count) {
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    S3_UNUSED(include_versions); /* TODO: support version deletion */

    int total_deleted = 0;
    s3_status status;

    /* List all objects with the given prefix */
    s3_list_objects_opts list_opts;
    memset(&list_opts, 0, sizeof(list_opts));
    list_opts.prefix = prefix;

    s3_object_info *objects = nullptr;
    int object_count = 0;

    status = s3_list_all_objects(c, bucket, &list_opts, &objects, &object_count);
    if (status != S3_STATUS_OK) return status;

    if (object_count == 0) {
        S3_FREE(objects);
        if (deleted_count) *deleted_count = 0;
        return S3_STATUS_OK;
    }

    /* Delete in batches of 1000 */
    s3_delete_object_entry *entries = (s3_delete_object_entry *)S3_CALLOC(
        S3_MAX_DELETE_BATCH, sizeof(s3_delete_object_entry));
    if (!entries) {
        S3_FREE(objects);
        return S3_STATUS_OUT_OF_MEMORY;
    }

    int offset = 0;
    while (offset < object_count) {
        int batch_size = S3_MIN(S3_MAX_DELETE_BATCH, object_count - offset);

        for (int i = 0; i < batch_size; i++) {
            entries[i].key = objects[offset + i].key;
            entries[i].version_id = nullptr;
        }

        s3_delete_objects_result del_result;
        memset(&del_result, 0, sizeof(del_result));

        status = s3_delete_objects(c, bucket, entries, batch_size, true, &del_result);

        /* quiet=true: S3 only returns errors. Count successes as batch - errors. */
            total_deleted += batch_size - del_result.error_count;
            S3_FREE(del_result.deleted);
        /* end quiet fix */
        S3_FREE(del_result.errors);

        if (status != S3_STATUS_OK) {
            S3_FREE(entries);
            S3_FREE(objects);
            if (deleted_count) *deleted_count = total_deleted;
            return status;
        }

        offset += batch_size;
    }

    S3_FREE(entries);
    S3_FREE(objects);
    if (deleted_count) *deleted_count = total_deleted;
    return S3_STATUS_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_delete_bucket_force
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_delete_bucket_force(s3_client *c, const char *bucket) {
    if (!c || !bucket) return S3_STATUS_INVALID_ARGUMENT;

    int deleted_count = 0;
    s3_status status = s3_delete_all_objects(c, bucket, nullptr, false, &deleted_count);
    if (status != S3_STATUS_OK) return status;

    return s3_delete_bucket(c, bucket);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_detect_content_type — Extension to MIME type lookup
 * ═══════════════════════════════════════════════════════════════════════════ */

static const struct {
    const char *ext;
    const char *mime;
} s3__mime_types[] = {
    /* Text */
    { ".html",  "text/html" },
    { ".htm",   "text/html" },
    { ".css",   "text/css" },
    { ".csv",   "text/csv" },
    { ".txt",   "text/plain" },
    { ".xml",   "text/xml" },
    { ".md",    "text/markdown" },
    { ".rtf",   "text/rtf" },
    { ".tsv",   "text/tab-separated-values" },

    /* Application */
    { ".js",    "application/javascript" },
    { ".mjs",   "application/javascript" },
    { ".json",  "application/json" },
    { ".pdf",   "application/pdf" },
    { ".zip",   "application/zip" },
    { ".gz",    "application/gzip" },
    { ".gzip",  "application/gzip" },
    { ".tar",   "application/x-tar" },
    { ".bz2",   "application/x-bzip2" },
    { ".xz",    "application/x-xz" },
    { ".zst",   "application/zstd" },
    { ".7z",    "application/x-7z-compressed" },
    { ".rar",   "application/vnd.rar" },
    { ".doc",   "application/msword" },
    { ".docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    { ".xls",   "application/vnd.ms-excel" },
    { ".xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
    { ".ppt",   "application/vnd.ms-powerpoint" },
    { ".pptx",  "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
    { ".wasm",  "application/wasm" },
    { ".bin",   "application/octet-stream" },
    { ".exe",   "application/octet-stream" },
    { ".dll",   "application/octet-stream" },
    { ".so",    "application/octet-stream" },
    { ".dmg",   "application/octet-stream" },
    { ".iso",   "application/octet-stream" },
    { ".parquet", "application/vnd.apache.parquet" },
    { ".avro",  "application/avro" },
    { ".yaml",  "application/x-yaml" },
    { ".yml",   "application/x-yaml" },
    { ".toml",  "application/toml" },

    /* Image */
    { ".png",   "image/png" },
    { ".jpg",   "image/jpeg" },
    { ".jpeg",  "image/jpeg" },
    { ".gif",   "image/gif" },
    { ".bmp",   "image/bmp" },
    { ".ico",   "image/x-icon" },
    { ".svg",   "image/svg+xml" },
    { ".webp",  "image/webp" },
    { ".tiff",  "image/tiff" },
    { ".tif",   "image/tiff" },
    { ".avif",  "image/avif" },
    { ".heic",  "image/heic" },
    { ".heif",  "image/heif" },

    /* Audio */
    { ".mp3",   "audio/mpeg" },
    { ".wav",   "audio/wav" },
    { ".ogg",   "audio/ogg" },
    { ".flac",  "audio/flac" },
    { ".aac",   "audio/aac" },
    { ".wma",   "audio/x-ms-wma" },
    { ".m4a",   "audio/mp4" },

    /* Video */
    { ".mp4",   "video/mp4" },
    { ".avi",   "video/x-msvideo" },
    { ".mkv",   "video/x-matroska" },
    { ".mov",   "video/quicktime" },
    { ".webm",  "video/webm" },
    { ".wmv",   "video/x-ms-wmv" },
    { ".flv",   "video/x-flv" },
    { ".m4v",   "video/mp4" },

    /* Font */
    { ".woff",  "font/woff" },
    { ".woff2", "font/woff2" },
    { ".ttf",   "font/ttf" },
    { ".otf",   "font/otf" },
    { ".eot",   "application/vnd.ms-fontobject" },
};

const char *s3_detect_content_type(const char *filename) {
    if (!filename) return "application/octet-stream";

    /* Find the last dot in the filename */
    const char *dot = strrchr(filename, '.');
    if (!dot) return "application/octet-stream";

    /* Case-insensitive extension match */
    for (size_t i = 0; i < S3_ARRAY_LEN(s3__mime_types); i++) {
        const char *ext = s3__mime_types[i].ext;
        const char *d = dot;

        /* Simple case-insensitive compare */
        bool match = true;
        for (size_t j = 0; ext[j] != '\0'; j++) {
            if (d[j] == '\0') { match = false; break; }
            char a = (d[j] >= 'A' && d[j] <= 'Z') ? (char)(d[j] + 32) : d[j];
            char b = ext[j]; /* ext is already lowercase */
            if (a != b) { match = false; break; }
        }
        /* Ensure the extension matches completely (no trailing chars) */
        if (match && d[strlen(ext)] == '\0') {
            return s3__mime_types[i].mime;
        }
    }

    return "application/octet-stream";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * s3_sync_result_free
 * ═══════════════════════════════════════════════════════════════════════════ */

void s3_sync_result_free(s3_sync_result *r) {
    /* No-op: s3_sync_result has no heap allocations */
    S3_UNUSED(r);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Stubs — Pool-dependent operations (not yet wired up)
 * ═══════════════════════════════════════════════════════════════════════════ */

s3_status s3_upload_file_parallel(s3_pool *pool, const char *bucket, const char *key,
                                  const char *filepath, const s3_upload_file_opts *opts,
                                  s3_future **future) {
    /* TODO: implement parallel multipart upload using thread pool */
    S3_UNUSED(pool);
    S3_UNUSED(bucket);
    S3_UNUSED(key);
    S3_UNUSED(filepath);
    S3_UNUSED(opts);
    S3_UNUSED(future);
    return S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_download_file_parallel(s3_pool *pool, const char *bucket, const char *key,
                                    const char *filepath, const s3_download_file_opts *opts,
                                    s3_future **future) {
    /* TODO: implement parallel range-based download using thread pool */
    S3_UNUSED(pool);
    S3_UNUSED(bucket);
    S3_UNUSED(key);
    S3_UNUSED(filepath);
    S3_UNUSED(opts);
    S3_UNUSED(future);
    return S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_copy_large_object(s3_pool *pool,
                               const char *src_bucket, const char *src_key,
                               const char *dst_bucket, const char *dst_key,
                               size_t part_size, int max_concurrent,
                               const s3_copy_object_opts *opts, s3_future **future) {
    /* TODO: implement multipart copy for large objects using thread pool */
    S3_UNUSED(pool);
    S3_UNUSED(src_bucket);
    S3_UNUSED(src_key);
    S3_UNUSED(dst_bucket);
    S3_UNUSED(dst_key);
    S3_UNUSED(part_size);
    S3_UNUSED(max_concurrent);
    S3_UNUSED(opts);
    S3_UNUSED(future);
    return S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_sync_upload(s3_client *c, const char *bucket,
                         const char *local_dir, const s3_sync_opts *opts,
                         s3_sync_result *result) {
    /* TODO: implement directory-to-S3 sync with incremental upload */
    S3_UNUSED(c);
    S3_UNUSED(bucket);
    S3_UNUSED(local_dir);
    S3_UNUSED(opts);
    S3_UNUSED(result);
    return S3_STATUS_INTERNAL_ERROR;
}

s3_status s3_sync_download(s3_client *c, const char *bucket,
                           const char *local_dir, const s3_sync_opts *opts,
                           s3_sync_result *result) {
    /* TODO: implement S3-to-directory sync with incremental download */
    S3_UNUSED(c);
    S3_UNUSED(bucket);
    S3_UNUSED(local_dir);
    S3_UNUSED(opts);
    S3_UNUSED(result);
    return S3_STATUS_INTERNAL_ERROR;
}
