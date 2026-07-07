#include "../../include/logger.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

UtilitiesLogLevel utilities_current_level = UTILITIES_VERBOSE;
bool utilities_cloudwatch_mode = false;
bool utilities_file_logging = false;
const char *utilities_log_file_path = NULL;

static utilities_error_cb_t s_error_callback = NULL;
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *s_log_file = NULL;

static const char *s_ansi_reset = "\033[0m";
static const char *s_ansi_bold = "\033[1m";
static const char *s_ansi_dim = "\033[90m";

static const char *level_color(UtilitiesLogLevel level) {
  switch (level) {
  case UTILITIES_VERBOSE:
    return "\033[35m";
  case UTILITIES_DEBUG:
    return "\033[36m";
  case UTILITIES_INFO:
    return "\033[32m";
  case UTILITIES_WARN:
    return "\033[33m";
  case UTILITIES_ERROR:
    return "\033[31m";
  default:
    return "\033[0m";
  }
}

static void current_timestamp_iso8601(char *buf, size_t buf_size) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  struct tm tm_info;
  localtime_r(&ts.tv_sec, &tm_info);

  size_t offset = strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", &tm_info);
  snprintf(buf + offset, buf_size - offset, ".%03ld", ts.tv_nsec / 1000000L);
}

static void current_timestamp_display(char *buf, size_t buf_size) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  struct tm tm_info;
  localtime_r(&ts.tv_sec, &tm_info);

  size_t offset = strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &tm_info);
  snprintf(buf + offset, buf_size - offset, ".%03ld", ts.tv_nsec / 1000000L);
}

const char *utilities_log_level_str(UtilitiesLogLevel level) {
  switch (level) {
  case UTILITIES_VERBOSE:
    return "详细";
  case UTILITIES_DEBUG:
    return "调试";
  case UTILITIES_INFO:
    return "信息";
  case UTILITIES_WARN:
    return "警告";
  case UTILITIES_ERROR:
    return "错误";
  default:
    return "未知";
  }
}

const char *utilities_log_level_cloudwatch(UtilitiesLogLevel level) {
  switch (level) {
  case UTILITIES_VERBOSE:
    return "VERBOSE";
  case UTILITIES_DEBUG:
    return "DEBUG";
  case UTILITIES_INFO:
    return "INFO";
  case UTILITIES_WARN:
    return "WARN";
  case UTILITIES_ERROR:
    return "ERROR";
  default:
    return "INFO";
  }
}

void utilities_set_log_level(const char *level) {
  if (!level)
    return;

  if (strcmp(level, "详细") == 0 || strcmp(level, "VERBOSE") == 0)
    utilities_current_level = UTILITIES_VERBOSE;
  else if (strcmp(level, "调试") == 0 || strcmp(level, "DEBUG") == 0)
    utilities_current_level = UTILITIES_DEBUG;
  else if (strcmp(level, "信息") == 0 || strcmp(level, "INFO") == 0)
    utilities_current_level = UTILITIES_INFO;
  else if (strcmp(level, "警告") == 0 || strcmp(level, "WARN") == 0)
    utilities_current_level = UTILITIES_WARN;
  else if (strcmp(level, "错误") == 0 || strcmp(level, "ERROR") == 0)
    utilities_current_level = UTILITIES_ERROR;
}

void utilities_enable_cloudwatch_mode(bool enable) {
  utilities_cloudwatch_mode = enable;
}

void utilities_enable_file_logging(const char *file_path) {
  if (!file_path)
    return;

  pthread_mutex_lock(&s_log_mutex);

  if (s_log_file) {
    fclose(s_log_file);
    s_log_file = NULL;
  }

  s_log_file = fopen(file_path, "a");
  if (s_log_file) {
    utilities_file_logging = true;
    utilities_log_file_path = file_path;
  }

  pthread_mutex_unlock(&s_log_mutex);
}

void utilities_register_error_callback(utilities_error_cb_t cb) {
  s_error_callback = cb;
}

const char *utilities_bold(const char *text) {
  if (!text)
    return "";
  if (utilities_cloudwatch_mode)
    return text;

  static __thread char buf[512];
  snprintf(buf, sizeof(buf), "%s%s%s", s_ansi_bold, text, s_ansi_reset);
  return buf;
}

static void escape_json_string(const char *src, char *dst, size_t dst_size) {
  size_t j = 0;
  for (size_t i = 0; src[i] && j < dst_size - 2; i++) {
    switch (src[i]) {
    case '"':
      if (j + 2 < dst_size) {
        dst[j++] = '\\';
        dst[j++] = '"';
      }
      break;
    case '\\':
      if (j + 2 < dst_size) {
        dst[j++] = '\\';
        dst[j++] = '\\';
      }
      break;
    case '\n':
      if (j + 2 < dst_size) {
        dst[j++] = '\\';
        dst[j++] = 'n';
      }
      break;
    case '\r':
      if (j + 2 < dst_size) {
        dst[j++] = '\\';
        dst[j++] = 'r';
      }
      break;
    case '\t':
      if (j + 2 < dst_size) {
        dst[j++] = '\\';
        dst[j++] = 't';
      }
      break;
    default:
      dst[j++] = src[i];
      break;
    }
  }
  dst[j] = '\0';
}

void utilities_log(UtilitiesLogLevel level, const char *format, ...) {
  if ((int)level < (int)utilities_current_level && level != UTILITIES_ERROR) {
    return;
  }

  va_list args;
  va_start(args, format);
  char message[UTILITIES_LOG_BUFFER_SIZE];
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);

  pthread_mutex_lock(&s_log_mutex);

  if (utilities_cloudwatch_mode) {
    char ts_iso[64];
    current_timestamp_iso8601(ts_iso, sizeof(ts_iso));

    char escaped_msg[UTILITIES_LOG_BUFFER_SIZE];
    escape_json_string(message, escaped_msg, sizeof(escaped_msg));

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
      strncpy(hostname, "unknown", sizeof(hostname) - 1);
    }

    fprintf(stdout,
            "{\"timestamp\":\"%s\","
            "\"level\":\"%s\","
            "\"level_cn\":\"%s\","
            "\"application\":\"%s\","
            "\"version\":\"%s\","
            "\"hostname\":\"%s\","
            "\"pid\":%d,"
            "\"tid\":%lu,"
            "\"message\":\"%s\"}\n",
            ts_iso, utilities_log_level_cloudwatch(level),
            utilities_log_level_str(level), UTILITIES_APP_NAME,
            UTILITIES_VERSION, hostname, (int)getpid(),
            (unsigned long)pthread_self(), escaped_msg);
    fflush(stdout);
  } else {
    char ts_display[64];
    current_timestamp_display(ts_display, sizeof(ts_display));

    fprintf(stderr, "%s[%s] [%s%s%s] %s%s\n", s_ansi_dim, ts_display,
            level_color(level), utilities_log_level_str(level), s_ansi_reset,
            message, s_ansi_reset);
  }

  if (s_log_file) {
    char ts_iso[64];
    current_timestamp_iso8601(ts_iso, sizeof(ts_iso));

    fprintf(s_log_file, "[%s] [%s] %s\n", ts_iso,
            utilities_log_level_cloudwatch(level), message);
    fflush(s_log_file);
  }

  pthread_mutex_unlock(&s_log_mutex);

  if (level == UTILITIES_ERROR && s_error_callback) {
    s_error_callback(message);
  }
}

void utilities_logf(const char *component, const char *operation,
                    UtilitiesLogLevel level, const char *status,
                    long long elapsed_ms, const char *caller,
                    const char *details[]) {
  char buf[UTILITIES_LOG_BUFFER_SIZE];
  int offset = 0;

  offset +=
      snprintf(buf + offset, sizeof(buf) - (size_t)offset,
               "[%s::%s] %s (%lld毫秒)", component ? component : "?",
               operation ? operation : "?", status ? status : "", elapsed_ms);

  if (caller && caller[0] != '\0') {
    offset +=
        snprintf(buf + offset, sizeof(buf) - (size_t)offset, " @%s", caller);
  }

  if (details) {
    for (size_t i = 0; details[i] != NULL; ++i) {
      offset += snprintf(buf + offset, sizeof(buf) - (size_t)offset, " | %s",
                         details[i]);
      if ((size_t)offset >= sizeof(buf) - 1)
        break;
    }
  }

  utilities_log(level, "%s", buf);
}

void utilities_log_progress(const char *component, const char *operation,
                            const char *msg, const char *details[]) {
  char buf[UTILITIES_LOG_BUFFER_SIZE];
  int offset = 0;

  offset += snprintf(buf + offset, sizeof(buf) - (size_t)offset, "[%s::%s] %s",
                     component ? component : "?", operation ? operation : "?",
                     msg ? msg : "");

  if (details) {
    for (size_t i = 0; details[i] != NULL; ++i) {
      offset += snprintf(buf + offset, sizeof(buf) - (size_t)offset, " | %s",
                         details[i]);
      if ((size_t)offset >= sizeof(buf) - 1)
        break;
    }
  }

  utilities_log(UTILITIES_INFO, "%s", buf);
}

void utilities_log_start(const char *component, const char *operation) {
  utilities_log(UTILITIES_INFO, "[%s::%s] 开始", component ? component : "?",
                operation ? operation : "?");
}

void utilities_log_success(const char *component, const char *operation,
                           long long elapsed_ms, const char *details[]) {
  utilities_logf(component, operation, UTILITIES_INFO, "成功", elapsed_ms, "",
                 details);
}

void utilities_log_error(const char *component, const char *operation,
                         const char *error_msg, long long elapsed_ms,
                         const char *details[]) {
  char status_buf[1024];
  snprintf(status_buf, sizeof(status_buf), "失败: %s",
           error_msg ? error_msg : "未知");

  utilities_logf(component, operation, UTILITIES_ERROR, status_buf, elapsed_ms,
                 "", details);
}

void utilities_log_warn(const char *component, const char *operation,
                        const char *warn_msg, long long elapsed_ms,
                        const char *details[]) {
  char status_buf[1024];
  snprintf(status_buf, sizeof(status_buf), "警告: %s",
           warn_msg ? warn_msg : "未知");

  utilities_logf(component, operation, UTILITIES_WARN, status_buf, elapsed_ms,
                 "", details);
}

const char *utilities_mask(const char *sensitive) {
  static __thread char masked[256];

  if (!sensitive)
    return "[已脱敏]";

  size_t len = strlen(sensitive);
  if (len <= UTILITIES_MASK_PREFIX_LEN) {
    return "[已脱敏]";
  }

  snprintf(masked, sizeof(masked), "%.*s[已脱敏]", UTILITIES_MASK_PREFIX_LEN,
           sensitive);
  return masked;
}

bool utilities_retry_with_backoff(const char *name, int max_attempts,
                                  long long backoff_ms,
                                  bool (*fn)(void *userdata), void *userdata) {
  if (!fn || max_attempts <= 0)
    return false;

  for (int i = 0; i < max_attempts; ++i) {
    if (fn(userdata)) {
      return true;
    }

    if (i + 1 < max_attempts) {
      utilities_log(UTILITIES_WARN, "%s 第 %d/%d 次尝试失败 - %lld毫秒后重试",
                    name ? name : "?", i + 1, max_attempts, backoff_ms);

      struct timespec ts;
      ts.tv_sec = backoff_ms / 1000;
      ts.tv_nsec = (backoff_ms % 1000) * 1000000L;
      nanosleep(&ts, NULL);
    }
  }

  utilities_log(UTILITIES_ERROR, "%s: 已耗尽 %d 次重试", name ? name : "?",
                max_attempts);
  return false;
}
