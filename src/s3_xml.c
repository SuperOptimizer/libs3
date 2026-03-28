/*
 * libs3 — Minimal XML parser and builder
 * Pull-style parser with no DOM and no allocations for simple extractions.
 * Hand-written XML builder for constructing S3 request bodies.
 */

#include "s3_internal.h"
#include <inttypes.h>
#include <ctype.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Find the opening tag <tag> starting from pos within xml[0..len).
 * Returns pointer to the character after '>', or nullptr if not found.
 * Sets *tag_start to point at the '<' of the opening tag.
 * Handles self-closing tags by setting *is_self_closing = true.
 */
static const char *find_open_tag(const char *xml, size_t len,
                                 const char *tag, size_t tag_len,
                                 const char **tag_start,
                                 bool *is_self_closing)
{
    const char *end = xml + len;
    const char *p = xml;

    while (p < end) {
        /* Find next '<' */
        const char *lt = (const char *)memchr(p, '<', (size_t)(end - p));
        if (!lt || lt + 1 + tag_len >= end) return nullptr;

        /* Skip processing instructions, comments, closing tags */
        if (lt[1] == '?' || lt[1] == '!' || lt[1] == '/') {
            p = lt + 1;
            continue;
        }

        /* Check if tag name matches */
        if (memcmp(lt + 1, tag, tag_len) != 0) {
            p = lt + 1;
            continue;
        }

        /* The character after the tag name must be '>', '/', or whitespace */
        char after = lt[1 + tag_len];
        if (after != '>' && after != '/' && after != ' ' &&
            after != '\t' && after != '\n' && after != '\r') {
            p = lt + 1;
            continue;
        }

        /* Found the tag — now find the closing '>' */
        const char *gt = (const char *)memchr(lt + 1, '>', (size_t)(end - lt - 1));
        if (!gt) return nullptr;

        if (tag_start) *tag_start = lt;

        /* Check for self-closing: .../> */
        if (gt > lt + 1 && gt[-1] == '/') {
            if (is_self_closing) *is_self_closing = true;
            return gt + 1;
        }

        if (is_self_closing) *is_self_closing = false;
        return gt + 1;
    }

    return nullptr;
}

/*
 * Find the matching closing tag </tag> starting from pos within xml.
 * Handles nested tags of the same name by counting depth.
 * Returns pointer to the '<' of </tag>, or nullptr if not found.
 */
static const char *find_close_tag(const char *xml, size_t len,
                                  const char *tag, size_t tag_len)
{
    const char *end = xml + len;
    const char *p = xml;
    int depth = 1;

    while (p < end) {
        const char *lt = (const char *)memchr(p, '<', (size_t)(end - p));
        if (!lt) return nullptr;

        if (lt + 1 >= end) return nullptr;

        if (lt[1] == '/') {
            /* Closing tag */
            if (lt + 2 + tag_len <= end &&
                memcmp(lt + 2, tag, tag_len) == 0 &&
                (lt[2 + tag_len] == '>' || lt[2 + tag_len] == ' ' ||
                 lt[2 + tag_len] == '\t')) {
                depth--;
                if (depth == 0) return lt;
            }
            p = lt + 2;
            continue;
        }

        if (lt[1] != '?' && lt[1] != '!') {
            /* Possible opening tag of same name — check for nesting */
            if (lt + 1 + tag_len <= end &&
                memcmp(lt + 1, tag, tag_len) == 0) {
                char after = lt[1 + tag_len];
                if (after == '>' || after == ' ' || after == '\t' ||
                    after == '\n' || after == '\r') {
                    /* Find closing > to check for self-closing */
                    const char *gt = (const char *)memchr(lt + 1, '>', (size_t)(end - lt - 1));
                    if (gt && gt[-1] == '/') {
                        /* Self-closing, does not increase depth */
                    } else if (after == '>') {
                        depth++;
                    } else if (gt) {
                        depth++;
                    }
                    p = gt ? gt + 1 : lt + 1;
                    continue;
                }
            }
        }

        p = lt + 1;
    }

    return nullptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML Parser — Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

bool s3__xml_find(const char *xml, size_t len,
                  const char *tag, const char **value, size_t *value_len)
{
    if (!xml || !len || !tag) return false;

    size_t tag_len = strlen(tag);
    if (tag_len == 0) return false;

    bool self_closing = false;
    const char *content_start = find_open_tag(xml, len, tag, tag_len,
                                              nullptr, &self_closing);
    if (!content_start) return false;

    if (self_closing) {
        /* Self-closing tag: <tag/> — content is empty */
        if (value) *value = content_start;
        if (value_len) *value_len = 0;
        return true;
    }

    /* Find closing tag */
    size_t remaining = (size_t)((xml + len) - content_start);
    const char *close = find_close_tag(content_start, remaining, tag, tag_len);
    if (!close) return false;

    if (value) *value = content_start;
    if (value_len) *value_len = (size_t)(close - content_start);
    return true;
}

bool s3__xml_find_in(const char *xml, size_t len,
                     const char *parent_tag,
                     const char *child_tag,
                     const char **value, size_t *value_len)
{
    if (!xml || !len || !parent_tag || !child_tag) return false;

    /* First, find the parent element's inner content */
    const char *parent_content = nullptr;
    size_t parent_len = 0;
    if (!s3__xml_find(xml, len, parent_tag, &parent_content, &parent_len))
        return false;

    /* Then find the child within the parent's content */
    return s3__xml_find(parent_content, parent_len, child_tag, value, value_len);
}

int s3__xml_each(const char *xml, size_t len,
                 const char *tag,
                 s3__xml_each_fn fn, void *userdata)
{
    if (!xml || !len || !tag || !fn) return 0;

    size_t tag_len = strlen(tag);
    if (tag_len == 0) return 0;

    int count = 0;
    const char *p = xml;
    size_t remaining = len;

    while (remaining > 0) {
        bool self_closing = false;
        const char *tag_start = nullptr;
        const char *content_start = find_open_tag(p, remaining, tag, tag_len,
                                                  &tag_start, &self_closing);
        if (!content_start) break;

        const char *element_end;
        const char *content_end;

        if (self_closing) {
            content_end = content_start; /* empty content */
            element_end = content_start; /* past the /> */
        } else {
            size_t rem = (size_t)((xml + len) - content_start);
            const char *close = find_close_tag(content_start, rem, tag, tag_len);
            if (!close) break;

            content_end = close;

            /* Skip past </tag> */
            const char *gt = (const char *)memchr(close, '>',
                                                  (size_t)((xml + len) - close));
            if (!gt) break;
            element_end = gt + 1;
        }

        size_t content_len = (size_t)(content_end - content_start);
        int rc = fn(content_start, content_len, userdata);
        count++;

        if (rc != 0) break;

        /* Advance past this element */
        remaining = (size_t)((xml + len) - element_end);
        p = element_end;
    }

    return count;
}

void s3__xml_decode_entities(const char *in, size_t in_len, char *out, size_t out_size)
{
    if (!out || out_size == 0) return;
    if (!in || in_len == 0) {
        out[0] = '\0';
        return;
    }

    const char *end = in + in_len;
    size_t oi = 0;

    while (in < end && oi + 1 < out_size) {
        if (*in == '&') {
            const char *semi = (const char *)memchr(in, ';', (size_t)(end - in));
            if (!semi) {
                /* No semicolon found — copy '&' literally */
                out[oi++] = *in++;
                continue;
            }

            size_t entity_len = (size_t)(semi - in - 1); /* length after '&', before ';' */
            const char *entity = in + 1;

            char decoded = 0;
            bool matched = false;

            if (entity_len == 3 && memcmp(entity, "amp", 3) == 0) {
                decoded = '&'; matched = true;
            } else if (entity_len == 2 && memcmp(entity, "lt", 2) == 0) {
                decoded = '<'; matched = true;
            } else if (entity_len == 2 && memcmp(entity, "gt", 2) == 0) {
                decoded = '>'; matched = true;
            } else if (entity_len == 4 && memcmp(entity, "quot", 4) == 0) {
                decoded = '"'; matched = true;
            } else if (entity_len == 4 && memcmp(entity, "apos", 4) == 0) {
                decoded = '\''; matched = true;
            } else if (entity_len >= 2 && entity[0] == '#') {
                /* Numeric character reference */
                unsigned long cp = 0;
                if (entity[1] == 'x' || entity[1] == 'X') {
                    /* Hexadecimal: &#xHH; */
                    for (size_t i = 2; i < entity_len; i++) {
                        char c = entity[i];
                        unsigned digit;
                        if (c >= '0' && c <= '9') digit = (unsigned)(c - '0');
                        else if (c >= 'a' && c <= 'f') digit = (unsigned)(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') digit = (unsigned)(c - 'A' + 10);
                        else { cp = 0; break; }
                        cp = cp * 16 + digit;
                    }
                } else {
                    /* Decimal: &#NNN; */
                    for (size_t i = 1; i < entity_len; i++) {
                        char c = entity[i];
                        if (c >= '0' && c <= '9') {
                            cp = cp * 10 + (unsigned long)(c - '0');
                        } else {
                            cp = 0;
                            break;
                        }
                    }
                }
                if (cp > 0 && cp <= 127) {
                    decoded = (char)cp;
                    matched = true;
                } else if (cp > 127 && cp <= 0x10FFFF) {
                    /* Encode as UTF-8 */
                    uint8_t utf8[4];
                    int utf8_len = 0;
                    if (cp <= 0x7F) {
                        utf8[0] = (uint8_t)cp;
                        utf8_len = 1;
                    } else if (cp <= 0x7FF) {
                        utf8[0] = (uint8_t)(0xC0 | (cp >> 6));
                        utf8[1] = (uint8_t)(0x80 | (cp & 0x3F));
                        utf8_len = 2;
                    } else if (cp <= 0xFFFF) {
                        utf8[0] = (uint8_t)(0xE0 | (cp >> 12));
                        utf8[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                        utf8[2] = (uint8_t)(0x80 | (cp & 0x3F));
                        utf8_len = 3;
                    } else {
                        utf8[0] = (uint8_t)(0xF0 | (cp >> 18));
                        utf8[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
                        utf8[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                        utf8[3] = (uint8_t)(0x80 | (cp & 0x3F));
                        utf8_len = 4;
                    }
                    for (int i = 0; i < utf8_len && oi + 1 < out_size; i++) {
                        out[oi++] = (char)utf8[i];
                    }
                    in = semi + 1;
                    continue;
                }
            }

            if (matched) {
                out[oi++] = decoded;
                in = semi + 1;
            } else {
                /* Unknown entity — copy literally */
                out[oi++] = *in++;
            }
        } else {
            out[oi++] = *in++;
        }
    }

    out[oi] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XML Builder
 * ═══════════════════════════════════════════════════════════════════════════ */

int s3__xml_buf_declaration(s3_buf *b)
{
    return s3_buf_append_str(b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
}

int s3__xml_buf_open(s3_buf *b, const char *tag)
{
    if (s3_buf_append_str(b, "<") < 0) return -1;
    if (s3_buf_append_str(b, tag) < 0) return -1;
    return s3_buf_append_str(b, ">");
}

int s3__xml_buf_close(s3_buf *b, const char *tag)
{
    if (s3_buf_append_str(b, "</") < 0) return -1;
    if (s3_buf_append_str(b, tag) < 0) return -1;
    return s3_buf_append_str(b, ">");
}

/*
 * Append text with XML entity encoding for the 5 predefined entities.
 */
static int xml_buf_append_escaped(s3_buf *b, const char *text)
{
    while (*text) {
        const char *run = text;
        /* Find next character that needs escaping */
        while (*text && *text != '&' && *text != '<' && *text != '>' &&
               *text != '"' && *text != '\'') {
            text++;
        }
        /* Append the run of safe characters */
        if (text > run) {
            if (s3_buf_append(b, run, (size_t)(text - run)) < 0) return -1;
        }
        if (!*text) break;

        const char *esc;
        switch (*text) {
            case '&':  esc = "&amp;";  break;
            case '<':  esc = "&lt;";   break;
            case '>':  esc = "&gt;";   break;
            case '"':  esc = "&quot;"; break;
            case '\'': esc = "&apos;"; break;
            default:   esc = nullptr;  break;
        }
        if (esc) {
            if (s3_buf_append_str(b, esc) < 0) return -1;
        }
        text++;
    }
    return 0;
}

int s3__xml_buf_element(s3_buf *b, const char *tag, const char *text)
{
    if (s3__xml_buf_open(b, tag) < 0) return -1;
    if (text) {
        if (xml_buf_append_escaped(b, text) < 0) return -1;
    }
    return s3__xml_buf_close(b, tag);
}

int s3__xml_buf_element_int(s3_buf *b, const char *tag, int64_t value)
{
    char num[32];
    snprintf(num, sizeof(num), "%" PRId64, value);
    if (s3__xml_buf_open(b, tag) < 0) return -1;
    if (s3_buf_append_str(b, num) < 0) return -1;
    return s3__xml_buf_close(b, tag);
}

int s3__xml_buf_element_bool(s3_buf *b, const char *tag, bool value)
{
    if (s3__xml_buf_open(b, tag) < 0) return -1;
    if (s3_buf_append_str(b, value ? "true" : "false") < 0) return -1;
    return s3__xml_buf_close(b, tag);
}
