/* log.h - tiny leveled logger to stderr. */
#ifndef MC_LOG_H
#define MC_LOG_H

typedef enum {
    LOG_LEVEL_ERR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

void log_set_level(log_level_t level);
void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_err(...)   log_msg(LOG_LEVEL_ERR,  __VA_ARGS__)
#define log_warn(...)  log_msg(LOG_LEVEL_WARN, __VA_ARGS__)
#define log_info(...)  log_msg(LOG_LEVEL_INFO, __VA_ARGS__)
#define log_debug(...) log_msg(LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif /* MC_LOG_H */
