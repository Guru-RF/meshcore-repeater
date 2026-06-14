/* log.c */
#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static log_level_t g_level = LOG_LEVEL_INFO;
static const char *TAG[] = { "ERR", "WARN", "INFO", "DBG" };

void log_set_level(log_level_t level)
{
    g_level = level;
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    if (level > g_level)
        return;

    char ts[20];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);

    fprintf(stderr, "[%s %-4s] ", ts, TAG[level]);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
    fflush(stderr);
}
