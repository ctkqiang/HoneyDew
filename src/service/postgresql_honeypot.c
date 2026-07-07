/**
 * Copyright (c) 2026 钟智强
 * All rights reserved.
 *
 * PostgreSQL 14.10 蜜罐服务
 * 模拟 PostgreSQL 线协议，使用 MD5 密码认证捕获凭据。
 */

#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PG_RECV_BUFFER_SIZE 4096
#define PG_PROTOCOL_VERSION_3 196608
#define PG_AUTH_MD5 5
#define PG_SALT_LEN 4

static void pg_generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "pg_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static int pg_parse_startup_username(const unsigned char *buf, ssize_t n,
                                     char *username, size_t usize) {
  if (n <= 8)
    return -1;

  const char *params = (const char *)(buf + 8);
  size_t remaining = (size_t)n - 8;

  while (remaining > 1) {
    size_t key_len = strnlen(params, remaining);
    if (key_len == 0 || key_len >= remaining)
      break;

    const char *key = params;
    params += key_len + 1;
    remaining -= key_len + 1;

    if (remaining == 0)
      break;

    size_t val_len = strnlen(params, remaining);
    const char *val = params;
    params += val_len + 1;
    remaining -= (val_len < remaining) ? val_len + 1 : remaining;

    if (strcmp(key, "user") == 0) {
      strncpy(username, val, usize - 1);
      username[usize - 1] = '\0';
      return 0;
    }
  }

  return -1;
}

static void pg_send_auth_md5(int fd, const unsigned char salt[PG_SALT_LEN]) {
  unsigned char pkt[13];
  pkt[0] = 'R';
  uint32_t body_len = htonl(12);
  memcpy(pkt + 1, &body_len, 4);
  uint32_t method = htonl(PG_AUTH_MD5);
  memcpy(pkt + 5, &method, 4);
  memcpy(pkt + 9, salt, PG_SALT_LEN);
  send(fd, pkt, sizeof(pkt), 0);
}

static void pg_send_error_response(int fd, const char *severity,
                                   const char *code, const char *message) {
  unsigned char pkt[512];
  size_t pos = 0;

  pkt[pos++] = 'E';

  size_t len_offset = pos;
  pos += 4;

  pkt[pos++] = 'S';
  size_t slen = strlen(severity);
  memcpy(pkt + pos, severity, slen + 1);
  pos += slen + 1;

  pkt[pos++] = 'V';
  memcpy(pkt + pos, severity, slen + 1);
  pos += slen + 1;

  pkt[pos++] = 'C';
  size_t clen = strlen(code);
  memcpy(pkt + pos, code, clen + 1);
  pos += clen + 1;

  pkt[pos++] = 'M';
  size_t mlen = strlen(message);
  memcpy(pkt + pos, message, mlen + 1);
  pos += mlen + 1;

  pkt[pos++] = '\0';

  uint32_t body = htonl((uint32_t)(pos - 1));
  memcpy(pkt + len_offset, &body, 4);

  send(fd, pkt, pos, 0);
}

void run_postgresql_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  pg_generate_session_id(session_id, sizeof(session_id),
                         conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 新连接建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, POSTGRESQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  unsigned char buf[PG_RECV_BUFFER_SIZE];
  ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n <= 0) {
    UTILITIES_LOG_WARN("[PostgreSQL蜜罐] 未收到启动消息: %s:%d",
                       conn->remote_ip, conn->remote_port);
    goto pg_cleanup;
  }

  if (n < 8) {
    UTILITIES_LOG_WARN("[PostgreSQL蜜罐] 启动消息过短 (%zd 字节): %s:%d", n,
                       conn->remote_ip, conn->remote_port);
    goto pg_cleanup;
  }

  uint32_t msg_len = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                     ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
  uint32_t proto_ver = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                       ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];

  UTILITIES_LOG_DEBUG(
      "[PostgreSQL蜜罐] 启动消息: 长度=%u 协议版本=%u 来自 %s:%d", msg_len,
      proto_ver, conn->remote_ip, conn->remote_port);

  if (proto_ver == 80877103) {
    UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 收到 SSLRequest，拒绝 SSL: %s:%d",
                       conn->remote_ip, conn->remote_port);
    const char ssl_deny = 'N';
    send(conn->socket_file_descriptor, &ssl_deny, 1, 0);

    n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);
    if (n <= 8) {
      UTILITIES_LOG_WARN("[PostgreSQL蜜罐] SSL 拒绝后未收到启动消息: %s:%d",
                         conn->remote_ip, conn->remote_port);
      goto pg_cleanup;
    }

    proto_ver = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
  }

  if (proto_ver != PG_PROTOCOL_VERSION_3) {
    UTILITIES_LOG_WARN("[PostgreSQL蜜罐] 不支持的协议版本 %u: %s:%d", proto_ver,
                       conn->remote_ip, conn->remote_port);
    pg_send_error_response(conn->socket_file_descriptor, "FATAL", "08004",
                           "unsupported protocol version");
    goto pg_cleanup;
  }

  char username[256] = {0};
  pg_parse_startup_username(buf, n, username, sizeof(username));

  UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 启动参数: 用户=\"%s\" 来自 %s:%d",
                     username, conn->remote_ip, conn->remote_port);

  unsigned char salt[PG_SALT_LEN];
  srand((unsigned int)time(NULL) ^ (unsigned int)conn->socket_file_descriptor);
  for (int i = 0; i < PG_SALT_LEN; i++)
    salt[i] = (unsigned char)(rand() % 256);

  pg_send_auth_md5(conn->socket_file_descriptor, salt);

  memset(buf, 0, sizeof(buf));
  n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n > 5 && buf[0] == 'p') {
    char password_hash[256] = {0};
    size_t pw_len = strnlen((const char *)(buf + 5), (size_t)n - 5);
    if (pw_len >= sizeof(password_hash))
      pw_len = sizeof(password_hash) - 1;
    memcpy(password_hash, buf + 5, pw_len);
    password_hash[pw_len] = '\0';

    UTILITIES_LOG_WARN(
        "[PostgreSQL蜜罐] 捕获认证凭据: 用户=\"%s\" MD5哈希=\"%s\" 来自 %s:%d",
        username, password_hash, conn->remote_ip, conn->remote_port);

    audit_record_auth(&g_audit, POSTGRESQL_PROTOCOL, conn->remote_ip,
                      conn->remote_port, session_id, username, password_hash,
                      0);

    char err_msg[512];
    snprintf(err_msg, sizeof(err_msg),
             "password authentication failed for user \"%s\"", username);
    pg_send_error_response(conn->socket_file_descriptor, "FATAL", "28P01",
                           err_msg);
  } else {
    UTILITIES_LOG_WARN("[PostgreSQL蜜罐] 未收到密码响应: %s:%d",
                       conn->remote_ip, conn->remote_port);
  }

pg_cleanup:
  UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, POSTGRESQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
