#pragma once

#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UTILITIES_APP_NAME "HoneyDew"
#define UTILITIES_VERSION "1.0.0"
#define UTILITIES_TZ "CST"

#define UTILITIES_LOG_BUFFER_SIZE 4096
#define UTILITIES_MASK_PREFIX_LEN 4

typedef enum {
  UTILITIES_DEBUG,
  UTILITIES_INFO,
  UTILITIES_WARN,
  UTILITIES_ERROR,
  UTILITIES_VERBOSE
} UtilitiesLogLevel;

typedef void (*utilities_error_cb_t)(const char *msg);

extern UtilitiesLogLevel utilities_current_level;
extern bool utilities_cloudwatch_mode;

void utilities_set_log_level(const char *level);
void utilities_register_error_callback(utilities_error_cb_t cb);

const char *utilities_bold(const char *text);
const char *utilities_log_level_str(UtilitiesLogLevel level);
const char *utilities_log_level_cloudwatch(UtilitiesLogLevel level);

void utilities_log(UtilitiesLogLevel level, const char *format, ...);
void utilities_logf(const char *component, const char *operation,
                    UtilitiesLogLevel level, const char *status,
                    long long elapsed_ms, const char *caller,
                    const char *details[]);

#define UTILITIES_LOGF(comp, op, lvl, status, elapsed, ...)                    \
  utilities_logf((comp), (op), (lvl), (status), (elapsed), __func__,           \
                 ((const char *[]){__VA_ARGS__, NULL}))

#define UTILITIES_LOG_ERROR(...) utilities_log(UTILITIES_ERROR, __VA_ARGS__)
#define UTILITIES_LOG_INFO(...) utilities_log(UTILITIES_INFO, __VA_ARGS__)
#define UTILITIES_LOG_DEBUG(...) utilities_log(UTILITIES_DEBUG, __VA_ARGS__)
#define UTILITIES_LOG_WARN(...) utilities_log(UTILITIES_WARN, __VA_ARGS__)

void utilities_log_progress(const char *component, const char *operation,
                            const char *msg, const char *details[]);
void utilities_log_start(const char *component, const char *operation);
void utilities_log_success(const char *component, const char *operation,
                           long long elapsed_ms, const char *details[]);
void utilities_log_error(const char *component, const char *operation,
                         const char *error_msg, long long elapsed_ms,
                         const char *details[]);
void utilities_log_warn(const char *component, const char *operation,
                        const char *warn_msg, long long elapsed_ms,
                        const char *details[]);

const char *utilities_mask(const char *sensitive);
bool utilities_retry_with_backoff(const char *name, int max_attempts,
                                  long long backoff_ms,
                                  bool (*fn)(void *userdata), void *userdata);

#ifdef __cplusplus
}
#endif

#endif
