#include "../../include/audit.h"
#include "../../include/logger.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __APPLE__
#include <stdlib.h>
#define getrandom(buf, len, flags) \
  (arc4random_buf(buf, len), (len))
#define GRND_RANDOM 0
#else
#include <sys/random.h>
#endif

audit_trail_t g_audit;

static const char *audit_event_type_str(audit_event_type type) {
  switch (type) {
  case AUDIT_EVENT_CONNECTION:
    return "连接建立";
  case AUDIT_EVENT_DISCONNECTION:
    return "连接断开";
  case AUDIT_EVENT_AUTH_ATTEMPT:
    return "认证尝试";
  case AUDIT_EVENT_AUTH_SUCCESS:
    return "认证成功";
  case AUDIT_EVENT_AUTH_FAILURE:
    return "认证失败";
  case AUDIT_EVENT_COMMAND:
    return "命令执行";
  case AUDIT_EVENT_FILE_ACCESS:
    return "文件访问";
  case AUDIT_EVENT_FILE_MODIFY:
    return "文件修改";
  case AUDIT_EVENT_DATA_EXFIL:
    return "数据外泄";
  case AUDIT_EVENT_SCAN_PROBE:
    return "扫描探测";
  case AUDIT_EVENT_EXPLOIT_ATTEMPT:
    return "漏洞利用";
  case AUDIT_EVENT_PROTOCOL_ERROR:
    return "协议错误";
  default:
    return "未知事件";
  }
}

static const char *audit_severity_str(audit_severity sev) {
  switch (sev) {
  case AUDIT_SEVERITY_LOW:
    return "低";
  case AUDIT_SEVERITY_MEDIUM:
    return "中";
  case AUDIT_SEVERITY_HIGH:
    return "高";
  case AUDIT_SEVERITY_CRITICAL:
    return "严重";
  default:
    return "未知";
  }
}

static const char *protocol_name(int proto) {
  switch (proto) {
  case 1:
    return "HTTP";
  case 2:
    return "HTTPS";
  case 3:
    return "FTP";
  case 4:
    return "FTPS";
  case 5:
    return "SSH";
  case 6:
    return "TELNET";
  case 7:
    return "SMTP";
  case 8:
    return "POP3";
  case 9:
    return "IMAP";
  case 10:
    return "DNS";
  case 11:
    return "MYSQL";
  case 12:
    return "POSTGRESQL";
  case 13:
    return "REDIS";
  case 14:
    return "QUESTDB";
  default:
    return "UNKNOWN";
  }
}

static int ensure_audit_dir(void) {
  struct stat st;
  if (stat(AUDIT_LOG_DIR, &st) == 0 && S_ISDIR(st.st_mode)) {
    return 0;
  }
  if (mkdir(AUDIT_LOG_DIR, 0700) != 0) {
    UTILITIES_LOG_ERROR("[审计] 无法创建审计日志目录: %s", strerror(errno));
    return -1;
  }
  return 0;
}

static int rotate_log_file(audit_trail_t *trail) {
  time_t now = time(NULL);
  struct tm tm_info;
  localtime_r(&now, &tm_info);

  char new_path[512];
  snprintf(new_path, sizeof(new_path), "%s/audit_%04d%02d%02d_%02d%02d%02d.log",
           AUDIT_LOG_DIR, tm_info.tm_year + 1900, tm_info.tm_mon + 1,
           tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);

  if (trail->current_log_file &&
      strcmp(trail->current_log_path, new_path) == 0) {
    return 0;
  }

  if (trail->current_log_file) {
    fclose(trail->current_log_file);
    trail->current_log_file = NULL;
  }

  int fd = open(new_path, O_CREAT | O_WRONLY | O_APPEND, 0600);
  if (fd < 0) {
    UTILITIES_LOG_ERROR("[审计] 无法创建审计日志文件: %s (%s)", new_path,
                        strerror(errno));
    return -1;
  }

  trail->current_log_file = fdopen(fd, "a");
  if (!trail->current_log_file) {
    close(fd);
    UTILITIES_LOG_ERROR("[审计] 无法打开审计日志文件流: %s (%s)", new_path,
                        strerror(errno));
    return -1;
  }

  strncpy(trail->current_log_path, new_path, sizeof(trail->current_log_path) - 1);
  UTILITIES_LOG_INFO("[审计] 审计日志文件已打开: %s (权限=0600)", new_path);
  return 0;
}

static void write_record(audit_trail_t *trail, const audit_record_t *rec) {
  if (!trail->current_log_file) {
    if (rotate_log_file(trail) != 0)
      return;
  }

  char time_buf[64];
  struct tm tm_info;
  localtime_r(&rec->timestamp, &tm_info);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

  fprintf(trail->current_log_file,
          "[%s] SEQ=%llu 严重性=%s 协议=%s 事件=%s "
          "来源=%s:%d 会话=%s 用户=%s 详情=%s\n",
          time_buf, (unsigned long long)rec->sequence_number,
          audit_severity_str(rec->severity), protocol_name(rec->protocol),
          audit_event_type_str(rec->event_type), rec->source_ip,
          rec->source_port, rec->session_id,
          rec->username[0] ? rec->username : "-", rec->details);

  fflush(trail->current_log_file);
}

static void *flush_thread_func(void *arg) {
  audit_trail_t *trail = (audit_trail_t *)arg;

  while (trail->running) {
    pthread_mutex_lock(&trail->mutex);

    while (trail->count == 0 && trail->running) {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += 1;
      pthread_cond_timedwait(&trail->flush_cond, &trail->mutex, &ts);
    }

    while (trail->count > 0) {
      size_t idx = (trail->head - trail->count) % trail->capacity;
      audit_record_t *rec = &trail->ring_buffer[idx];
      write_record(trail, rec);
      trail->count--;
    }

    pthread_mutex_unlock(&trail->mutex);
  }

  pthread_mutex_lock(&trail->mutex);
  while (trail->count > 0) {
    size_t idx = (trail->head - trail->count) % trail->capacity;
    audit_record_t *rec = &trail->ring_buffer[idx];
    write_record(trail, rec);
    trail->count--;
  }
  pthread_mutex_unlock(&trail->mutex);

  return NULL;
}

int audit_init(audit_trail_t *trail) {
  memset(trail, 0, sizeof(*trail));

  if (ensure_audit_dir() != 0)
    return -1;

  trail->capacity = AUDIT_RING_BUFFER_SIZE;
  trail->ring_buffer = calloc(trail->capacity, sizeof(audit_record_t));
  if (!trail->ring_buffer) {
    UTILITIES_LOG_ERROR("[审计] 内存分配失败");
    return -1;
  }

  trail->head = 0;
  trail->count = 0;
  trail->next_sequence = 1;
  trail->running = 1;
  trail->total_records = 0;
  trail->dropped_records = 0;
  trail->current_log_file = NULL;
  trail->current_log_path[0] = '\0';

  pthread_mutex_init(&trail->mutex, NULL);
  pthread_cond_init(&trail->flush_cond, NULL);

  if (rotate_log_file(trail) != 0) {
    free(trail->ring_buffer);
    return -1;
  }

  if (pthread_create(&trail->flush_thread, NULL, flush_thread_func, trail) !=
      0) {
    UTILITIES_LOG_ERROR("[审计] 无法创建刷写线程");
    fclose(trail->current_log_file);
    free(trail->ring_buffer);
    return -1;
  }

  UTILITIES_LOG_INFO("[审计] 审计追踪系统已启动 (缓冲区=%zu 条记录)",
                     trail->capacity);
  return 0;
}

void audit_shutdown(audit_trail_t *trail) {
  pthread_mutex_lock(&trail->mutex);
  trail->running = 0;
  pthread_cond_signal(&trail->flush_cond);
  pthread_mutex_unlock(&trail->mutex);

  pthread_join(trail->flush_thread, NULL);

  if (trail->current_log_file) {
    fclose(trail->current_log_file);
    trail->current_log_file = NULL;
  }

  UTILITIES_LOG_INFO("[审计] 审计追踪系统已关闭 (总记录=%zu, 丢弃=%zu)",
                     trail->total_records, trail->dropped_records);

  free(trail->ring_buffer);
  pthread_mutex_destroy(&trail->mutex);
  pthread_cond_destroy(&trail->flush_cond);
}

void audit_record_event(audit_trail_t *trail, audit_event_type type,
                        audit_severity severity, int protocol,
                        const char *source_ip, int source_port,
                        const char *session_id, const char *username,
                        const char *details_fmt, ...) {
  pthread_mutex_lock(&trail->mutex);

  if (trail->count >= trail->capacity) {
    trail->dropped_records++;
    pthread_mutex_unlock(&trail->mutex);
    return;
  }

  audit_record_t *rec = &trail->ring_buffer[trail->head];
  rec->timestamp = time(NULL);
  rec->sequence_number = trail->next_sequence++;
  rec->event_type = type;
  rec->severity = severity;
  rec->protocol = protocol;
  rec->source_port = source_port;

  strncpy(rec->source_ip, source_ip ? source_ip : "unknown",
          AUDIT_MAX_IP_LEN - 1);
  strncpy(rec->session_id, session_id ? session_id : "-",
          AUDIT_MAX_SESSION_ID_LEN - 1);
  strncpy(rec->username, username ? username : "",
          AUDIT_MAX_USER_LEN - 1);

  va_list args;
  va_start(args, details_fmt);
  vsnprintf(rec->details, AUDIT_MAX_DETAIL_LEN, details_fmt, args);
  va_end(args);

  trail->head = (trail->head + 1) % trail->capacity;
  trail->count++;
  trail->total_records++;

  pthread_cond_signal(&trail->flush_cond);
  pthread_mutex_unlock(&trail->mutex);
}

void audit_record_connection(audit_trail_t *trail, int protocol,
                             const char *ip, int port,
                             const char *session_id) {
  audit_record_event(trail, AUDIT_EVENT_CONNECTION, AUDIT_SEVERITY_LOW,
                     protocol, ip, port, session_id, NULL,
                     "新连接建立");
}

void audit_record_auth(audit_trail_t *trail, int protocol, const char *ip,
                       int port, const char *session_id, const char *username,
                       const char *password, int success) {
  audit_event_type type =
      success ? AUDIT_EVENT_AUTH_SUCCESS : AUDIT_EVENT_AUTH_FAILURE;
  audit_severity sev = success ? AUDIT_SEVERITY_HIGH : AUDIT_SEVERITY_MEDIUM;

  audit_record_event(trail, type, sev, protocol, ip, port, session_id,
                     username, "密码=\"%s\"", password ? password : "(空)");
}

void audit_record_command(audit_trail_t *trail, int protocol, const char *ip,
                          int port, const char *session_id,
                          const char *command) {
  audit_record_event(trail, AUDIT_EVENT_COMMAND, AUDIT_SEVERITY_HIGH, protocol,
                     ip, port, session_id, NULL, "命令=\"%s\"", command);
}

void audit_record_disconnect(audit_trail_t *trail, int protocol,
                             const char *ip, int port,
                             const char *session_id) {
  audit_record_event(trail, AUDIT_EVENT_DISCONNECTION, AUDIT_SEVERITY_LOW,
                     protocol, ip, port, session_id, NULL, "连接断开");
}

void audit_generate_session_id(char *buf, size_t buf_len) {
  if (!buf || buf_len < 37) {
    return;
  }

  unsigned char uuid[16];
  if (getrandom(uuid, sizeof(uuid), GRND_RANDOM) != sizeof(uuid)) {
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    for (size_t i = 0; i < sizeof(uuid); i++) {
      uuid[i] = (unsigned char)((seed * 1103515245 + 12345) >> 16);
      seed = (unsigned int)(uuid[i] ^ (time(NULL) + i));
    }
  }

  uuid[6] = (uuid[6] & 0x0F) | 0x40;
  uuid[8] = (uuid[8] & 0x3F) | 0x80;

  const char *hex = "0123456789abcdef";
  size_t pos = 0;

  for (size_t i = 0; i < 4 && pos < buf_len - 1; i++) {
    buf[pos++] = hex[(uuid[i] >> 4) & 0x0F];
    buf[pos++] = hex[uuid[i] & 0x0F];
  }
  if (pos < buf_len - 1) buf[pos++] = '-';

  for (size_t i = 4; i < 6 && pos < buf_len - 1; i++) {
    buf[pos++] = hex[(uuid[i] >> 4) & 0x0F];
    buf[pos++] = hex[uuid[i] & 0x0F];
  }
  if (pos < buf_len - 1) buf[pos++] = '-';

  for (size_t i = 6; i < 8 && pos < buf_len - 1; i++) {
    buf[pos++] = hex[(uuid[i] >> 4) & 0x0F];
    buf[pos++] = hex[uuid[i] & 0x0F];
  }
  if (pos < buf_len - 1) buf[pos++] = '-';

  for (size_t i = 8; i < 10 && pos < buf_len - 1; i++) {
    buf[pos++] = hex[(uuid[i] >> 4) & 0x0F];
    buf[pos++] = hex[uuid[i] & 0x0F];
  }
  if (pos < buf_len - 1) buf[pos++] = '-';

  for (size_t i = 10; i < 16 && pos < buf_len - 1; i++) {
    buf[pos++] = hex[(uuid[i] >> 4) & 0x0F];
    buf[pos++] = hex[uuid[i] & 0x0F];
  }

  buf[pos] = '\0';
}
