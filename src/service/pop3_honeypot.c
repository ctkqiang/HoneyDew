/**
 * 版权所有 (c) 2026 钟智强
 * 保留所有权利。
 *
 * POP3 蜜罐服务 (Dovecot)
 * 模拟 Dovecot POP3 服务器，捕获用户名和密码。
 */

#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define POP3_RECV_BUFFER_SIZE 4096

static void pop3_generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "pop3_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static void pop3_strip_crlf(char *str) {
  size_t n = strlen(str);
  while (n > 0 && (str[n - 1] == '\r' || str[n - 1] == '\n'))
    str[--n] = '\0';
}

void run_pop3_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  pop3_generate_session_id(session_id, sizeof(session_id),
                           conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[POP3蜜罐] 新连接建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner = "+OK Dovecot ready.\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[POP3_RECV_BUFFER_SIZE];
  char username[256] = {0};
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    pop3_strip_crlf(buf);

    UTILITIES_LOG_INFO("[POP3蜜罐] 收到命令: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    if (strncasecmp(buf, "USER ", 5) == 0) {
      strncpy(username, buf + 5, sizeof(username) - 1);
      username[sizeof(username) - 1] = '\0';

      UTILITIES_LOG_INFO("[POP3蜜罐] 用户名: \"%s\" 来自 %s:%d", username,
                         conn->remote_ip, conn->remote_port);

      const char *resp = "+OK\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "PASS ", 5) == 0) {
      const char *password = buf + 5;

      UTILITIES_LOG_WARN(
          "[POP3蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d", username,
          password, conn->remote_ip, conn->remote_port);

      audit_record_auth(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                        conn->remote_port, session_id, username, password, 0);

      const char *resp = "-ERR Authentication failed.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      memset(username, 0, sizeof(username));

    } else if (strncasecmp(buf, "CAPA", 4) == 0) {
      const char *resp = "+OK Capability list follows\r\n"
                         "USER\r\n"
                         "UIDL\r\n"
                         "TOP\r\n"
                         "RESP-CODES\r\n"
                         "AUTH-RESP-CODE\r\n"
                         "PIPELINING\r\n"
                         "STLS\r\n"
                         ".\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "QUIT", 4) == 0) {
      const char *resp = "+OK Bye.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strncasecmp(buf, "NOOP", 4) == 0) {
      const char *resp = "+OK\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "STAT", 4) == 0) {
      const char *resp = "-ERR Not authenticated\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "LIST", 4) == 0) {
      const char *resp = "-ERR Not authenticated\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "RETR", 4) == 0) {
      const char *resp = "-ERR Not authenticated\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "STLS", 4) == 0) {
      const char *resp = "-ERR TLS not available\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "AUTH", 4) == 0) {
      const char *resp = "-ERR Unknown authentication mechanism\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else {
      const char *resp = "-ERR Unknown command\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
    }
  }

  UTILITIES_LOG_INFO("[POP3蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
