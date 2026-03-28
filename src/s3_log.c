/*
 * libs3 -- Logging implementation
 */

#include "s3_internal.h"
#include <stdarg.h>

void s3__log(s3_client *c, s3_log_level level, const char *fmt, ...)
{
    if (!c || !c->log_fn)
        return;
    if (level < c->log_level)
        return;

    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    c->log_fn(level, buf, c->log_userdata);
}
