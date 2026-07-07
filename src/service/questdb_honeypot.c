/**
 * Copyright (c) 2025 zhongjyuan
 * All rights reserved.
 *
 * QuestDB 7.3.10 蜜罐服务
 * QuestDB 使用 PostgreSQL 线协议 (端口 8812)。
 * 模拟认证流程并捕获 SQL 查询。
 */

#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#define QDB_RECV_BUFFER_SIZE    4096
#define QDB_PROTOCOL_VERSION_3  196608
#define QDB_AUTH_MD5            5
#define QDB_SALT_LEN            4
#define QDB_SERVER_VERSION      "QuestDB 7.3.10"

static void qdb_generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "qdb_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static int qdb_parse_startup_username(const unsigned char *buf, ssize_t n,
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

static void qdb_send_auth_md5(int fd, const unsigned char salt[QDB_SALT_LEN]) {
  unsigned char pkt[13];
  pkt[0] = 'R';
  uint32_t body_len = htonl(12);
  memcpy(pkt + 1, &body_len, 4);
  uint32_t method = htonl(QDB_AUTH_MD5);
  memcpy(pkt + 5, &method, 4);
  memcpy(pkt + 9, salt, QDB_SALT_LEN);
  send(fd, pkt, sizeof(pkt), 0);
}

static void qdb_send_auth_ok(int fd) {
  unsigned char pkt[9];
  pkt[0] = 'R';
  uint32_t body_len = htonl(8);
  memcpy(pkt + 1, &body_len, 4);
  uint32_t method = htonl(0);
  memcpy(pkt + 5, &method, 4);
  send(fd, pkt, sizeof(pkt), 0);
}

static void qdb_send_parameter_status(int fd, const char *name,
                                      const char *value) {
  size_t nlen = strlen(name) + 1;
  size_t vlen = strlen(value) + 1;
  uint32_t body = htonl((uint32_t)(4 + nlen + vlen));

  unsigned char pkt[256];
  size_t pos = 0;
  pkt[pos++] = 'S';
  memcpy(pkt + pos, &body, 4);
  pos += 4;
  memcpy(pkt + pos, name, nlen);
  pos += nlen;
  memcpy(pkt + pos, value, vlen);
  pos += vlen;
  send(fd, pkt, pos, 0);
}

static void qdb_send_ready_for_query(int fd) {
  unsigned char pkt[6];
  pkt[0] = 'Z';
  uint32_t body = htonl(5);
  memcpy(pkt + 1, &body, 4);
  pkt[5] = 'I';
  send(fd, pkt, sizeof(pkt), 0);
}

static void qdb_send_error_response(int fd, const char *severity,
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

static void qdb_send_empty_query_result(int fd, const char *tag) {
  unsigned char row_desc[7];
  row_desc[0] = 'T';
  uint32_t rd_body = htonl(6);
  memcpy(row_desc + 1, &rd_body, 4);
  row_desc[5] = 0x00;
  row_desc[6] = 0x00;
  send(fd, row_desc, sizeof(row_desc), 0);

  unsigned char cmd_complete[256];
  size_t pos = 0;
  cmd_complete[pos++] = 'C';
  size_t tag_len = strlen(tag) + 1;
  uint32_t cc_body = htonl((uint32_t)(4 + tag_len));
  memcpy(cmd_complete + pos, &cc_body, 4);
  pos += 4;
  memcpy(cmd_complete + pos, tag, tag_len);
  pos += tag_len;
  send(fd, cmd_complete, pos, 0);
}

static void qdb_strip_crlf(char *str) {
  size_t n = strlen(str);
  while (n > 0 && (str[n - 1] == '\r' || str[n - 1] == '\n'))
    str[--n] = '\0';
}

void run_questdb_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  qdb_generate_session_id(session_id, sizeof(session_id),
                          conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[QuestDB蜜罐] 新连接建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  unsigned char buf[QDB_RECV_BUFFER_SIZE];
  ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n <= 0) {
    UTILITIES_LOG_WARN("[QuestDB蜜罐] 未收到启动消息: %s:%d",
                       conn->remote_ip, conn->remote_port);
    goto qdb_cleanup;
  }

  if (n < 8) {
    UTILITIES_LOG_WARN("[QuestDB蜜罐] 启动消息过短 (%zd 字节): %s:%d",
                       n, conn->remote_ip, conn->remote_port);
    goto qdb_cleanup;
  }

  uint32_t proto_ver = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                       ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];

  if (proto_ver == 80877103) {
    UTILITIES_LOG_INFO("[QuestDB蜜罐] 收到 SSLRequest，拒绝 SSL: %s:%d",
                       conn->remote_ip, conn->remote_port);
    const char ssl_deny = 'N';
    send(conn->socket_file_descriptor, &ssl_deny, 1, 0);

    n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);
    if (n <= 8) {
      UTILITIES_LOG_WARN("[QuestDB蜜罐] SSL 拒绝后未收到启动消息: %s:%d",
                         conn->remote_ip, conn->remote_port);
      goto qdb_cleanup;
    }

    proto_ver = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
  }

  if (proto_ver != QDB_PROTOCOL_VERSION_3) {
    UTILITIES_LOG_WARN("[QuestDB蜜罐] 不支持的协议版本 %u: %s:%d",
                       proto_ver, conn->remote_ip, conn->remote_port);
    qdb_send_error_response(conn->socket_file_descriptor, "FATAL", "08004",
                            "unsupported protocol version");
    goto qdb_cleanup;
  }

  char username[256] = {0};
  qdb_parse_startup_username(buf, n, username, sizeof(username));

  UTILITIES_LOG_INFO("[QuestDB蜜罐] 启动参数: 用户=\"%s\" 来自 %s:%d",
                     username, conn->remote_ip, conn->remote_port);

  unsigned char salt[QDB_SALT_LEN];
  srand((unsigned int)time(NULL) ^ (unsigned int)conn->socket_file_descriptor);
  for (int i = 0; i < QDB_SALT_LEN; i++)
    salt[i] = (unsigned char)(rand() % 256);

  qdb_send_auth_md5(conn->socket_file_descriptor, salt);

  memset(buf, 0, sizeof(buf));
  n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n <= 5 || buf[0] != 'p') {
    UTILITIES_LOG_WARN("[QuestDB蜜罐] 未收到密码响应: %s:%d",
                       conn->remote_ip, conn->remote_port);
    goto qdb_cleanup;
  }

  char password_hash[256] = {0};
  size_t pw_len = strnlen((const char *)(buf + 5), (size_t)n - 5);
  if (pw_len >= sizeof(password_hash))
    pw_len = sizeof(password_hash) - 1;
  memcpy(password_hash, buf + 5, pw_len);
  password_hash[pw_len] = '\0';

  UTILITIES_LOG_WARN(
      "[QuestDB蜜罐] 捕获认证凭据: 用户=\"%s\" MD5哈希=\"%s\" 来自 %s:%d",
      username, password_hash, conn->remote_ip, conn->remote_port);

  audit_record_auth(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                    conn->remote_port, session_id, username,
                    password_hash, 0);

  qdb_send_auth_ok(conn->socket_file_descriptor);

  qdb_send_parameter_status(conn->socket_file_descriptor,
                            "server_version", QDB_SERVER_VERSION);
  qdb_send_parameter_status(conn->socket_file_descriptor,
                            "server_encoding", "UTF8");
  qdb_send_parameter_status(conn->socket_file_descriptor,
                            "client_encoding", "UTF8");
  qdb_send_parameter_status(conn->socket_file_descriptor,
                            "DateStyle", "ISO, MDY");

  qdb_send_ready_for_query(conn->socket_file_descriptor);

  while (1) {
    memset(buf, 0, sizeof(buf));
    n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);
    if (n <= 0)
      break;

    char msg_type = (char)buf[0];

    if (msg_type == 'Q') {
      char sql[QDB_RECV_BUFFER_SIZE] = {0};
      if (n > 5) {
        size_t sql_len = strnlen((const char *)(buf + 5), (size_t)n - 5);
        if (sql_len >= sizeof(sql))
          sql_len = sizeof(sql) - 1;
        memcpy(sql, buf + 5, sql_len);
        sql[sql_len] = '\0';
        qdb_strip_crlf(sql);
      }

      UTILITIES_LOG_WARN("[QuestDB蜜罐] SQL 查询: \"%s\" 来自 %s:%d",
                         sql, conn->remote_ip, conn->remote_port);

      audit_record_command(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                           conn->remote_port, session_id, sql);

      if (strncasecmp(sql, "SELECT", 6) == 0) {
        qdb_send_empty_query_result(conn->socket_file_descriptor, "SELECT 0");
      } else if (strncasecmp(sql, "INSERT", 6) == 0) {
        qdb_send_empty_query_result(conn->socket_file_descriptor,
                                    "INSERT 0 1");
      } else if (strncasecmp(sql, "CREATE", 6) == 0) {
        qdb_send_empty_query_result(conn->socket_file_descriptor,
                                    "CREATE TABLE");
      } else if (strncasecmp(sql, "SHOW", 4) == 0) {
        qdb_send_empty_query_result(conn->socket_file_descriptor, "SHOW");
      } else if (strncasecmp(sql, "DROP", 4) == 0) {
        UTILITIES_LOG_WARN(
            "[QuestDB蜜罐] 检测到 DROP 操作: \"%s\" 来自 %s:%d",
            sql, conn->remote_ip, conn->remote_port);
        qdb_send_error_response(conn->socket_file_descriptor, "ERROR",
                                "42501", "permission denied");
        qdb_send_ready_for_query(conn->socket_file_descriptor);
        continue;
      } else {
        qdb_send_error_response(conn->socket_file_descriptor, "ERROR",
                                "42601", "syntax error");
        qdb_send_ready_for_query(conn->socket_file_descriptor);
        continue;
      }

      qdb_send_ready_for_query(conn->socket_file_descriptor);

    } else if (msg_type == 'X') {
      UTILITIES_LOG_INFO("[QuestDB蜜罐] 收到终止消息: %s:%d",
                         conn->remote_ip, conn->remote_port);
      break;

    } else if (msg_type == 'P') {
      UTILITIES_LOG_INFO("[QuestDB蜜罐] 收到 Parse 消息: %s:%d",
                         conn->remote_ip, conn->remote_port);

      unsigned char parse_complete[5];
      parse_complete[0] = '1';
      uint32_t pc_body = htonl(4);
      memcpy(parse_complete + 1, &pc_body, 4);
      send(conn->socket_file_descriptor, parse_complete, 5, 0);

    } else {
      UTILITIES_LOG_DEBUG("[QuestDB蜜罐] 未知消息类型 '%c' (0x%02x): %s:%d",
                          msg_type, (unsigned char)msg_type,
                          conn->remote_ip, conn->remote_port);
    }
  }

qdb_cleanup:
  UTILITIES_LOG_INFO("[QuestDB蜜罐] 会话结束: %s:%d",
                     conn->remote_ip, conn->remote_port);

  audit_record_disconnect(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
