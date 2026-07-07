/**
 * 版权所有 (c) 2026 钟智强
 * 保留所有权利。
 *
 * IMAP 蜜罐服务 (Dovecot)
 * 模拟 Dovecot IMAP4rev1 服务器，捕获 LOGIN 凭据。
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

#define IMAP_RECV_BUFFER_SIZE 4096

static void imap_generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "imap_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static void imap_strip_crlf(char *str) {
  size_t n = strlen(str);
  while (n > 0 && (str[n - 1] == '\r' || str[n - 1] == '\n'))
    str[--n] = '\0';
}

static void imap_parse_login_args(const char *args, char *username,
                                  size_t usize, char *password, size_t psize) {
  const char *p = args;
  char *pw_start = NULL;

  if (*p == '"') {
    const char *end = strchr(p + 1, '"');
    if (end) {
      size_t ulen = (size_t)(end - p - 1);
      if (ulen >= usize)
        ulen = usize - 1;
      memcpy(username, p + 1, ulen);
      username[ulen] = '\0';
      pw_start = (char *)(end + 1);
      while (*pw_start == ' ')
        pw_start++;
    }
  } else {
    const char *sp = strchr(p, ' ');
    if (sp) {
      size_t ulen = (size_t)(sp - p);
      if (ulen >= usize)
        ulen = usize - 1;
      memcpy(username, p, ulen);
      username[ulen] = '\0';
      pw_start = (char *)(sp + 1);
    }
  }

  if (!pw_start)
    return;

  if (*pw_start == '"') {
    const char *end = strchr(pw_start + 1, '"');
    if (end) {
      size_t plen = (size_t)(end - pw_start - 1);
      if (plen >= psize)
        plen = psize - 1;
      memcpy(password, pw_start + 1, plen);
      password[plen] = '\0';
    }
  } else {
    strncpy(password, pw_start, psize - 1);
    password[psize - 1] = '\0';
  }
}

void run_imap_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  imap_generate_session_id(session_id, sizeof(session_id),
                           conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[IMAP蜜罐] 新连接建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, IMAP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner =
      "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS "
      "AUTH=PLAIN] Dovecot ready.\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[IMAP_RECV_BUFFER_SIZE];
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    imap_strip_crlf(buf);

    UTILITIES_LOG_INFO("[IMAP蜜罐] 收到命令: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, IMAP_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    char tag[64] = {0};
    char *space = strchr(buf, ' ');
    if (space) {
      size_t tag_len = (size_t)(space - buf);
      if (tag_len >= sizeof(tag))
        tag_len = sizeof(tag) - 1;
      memcpy(tag, buf, tag_len);
      tag[tag_len] = '\0';
    } else {
      strncpy(tag, "*", sizeof(tag) - 1);
    }

    char *cmd = space ? space + 1 : buf;

    if (strncasecmp(cmd, "LOGIN ", 6) == 0) {
      char username[256] = {0};
      char password[256] = {0};

      imap_parse_login_args(cmd + 6, username, sizeof(username), password,
                            sizeof(password));

      UTILITIES_LOG_WARN(
          "[IMAP蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d", username,
          password, conn->remote_ip, conn->remote_port);

      audit_record_auth(&g_audit, IMAP_PROTOCOL, conn->remote_ip,
                        conn->remote_port, session_id, username, password, 0);

      char resp[512];
      snprintf(resp, sizeof(resp),
               "%s NO [AUTHENTICATIONFAILED] Authentication failed.\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "CAPABILITY", 10) == 0) {
      char resp[512];
      snprintf(resp, sizeof(resp),
               "* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS "
               "ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN STARTTLS\r\n"
               "%s OK CAPABILITY completed\r\n",
               tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "LOGOUT", 6) == 0) {
      char resp[256];
      snprintf(resp, sizeof(resp),
               "* BYE Dovecot closing connection\r\n"
               "%s OK LOGOUT completed\r\n",
               tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strncasecmp(cmd, "NOOP", 4) == 0) {
      char resp[128];
      snprintf(resp, sizeof(resp), "%s OK NOOP completed\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "STARTTLS", 8) == 0) {
      char resp[256];
      snprintf(resp, sizeof(resp), "%s BAD TLS not available\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "AUTHENTICATE", 12) == 0) {
      UTILITIES_LOG_WARN("[IMAP蜜罐] AUTHENTICATE 尝试: \"%s\" 来自 %s:%d", cmd,
                         conn->remote_ip, conn->remote_port);
      char resp[256];
      snprintf(resp, sizeof(resp),
               "%s NO [AUTHENTICATIONFAILED] Authentication failed.\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "SELECT", 6) == 0 ||
               strncasecmp(cmd, "EXAMINE", 7) == 0 ||
               strncasecmp(cmd, "LIST", 4) == 0 ||
               strncasecmp(cmd, "FETCH", 5) == 0 ||
               strncasecmp(cmd, "STORE", 5) == 0 ||
               strncasecmp(cmd, "SEARCH", 6) == 0) {
      char resp[256];
      snprintf(resp, sizeof(resp), "%s BAD Not authenticated\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else {
      char resp[256];
      snprintf(resp, sizeof(resp), "%s BAD Command not recognized\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
    }
  }

  UTILITIES_LOG_INFO("[IMAP蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, IMAP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
