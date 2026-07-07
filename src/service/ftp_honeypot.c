/**
 * Copyright (c) 2026 钟智强
 * 保留所有权利。
 *
 * FTP 蜜罐服务 - 模拟 Ubuntu 上的 vsftpd 3.0.3
 *
 * 捕获攻击者的凭据、命令及文件访问尝试。
 * 呈现一个逼真的 FTP 环境，并放置诱饵文件，
 * 以最大程度地从未授权访问尝试中收集情报。
 */

#include "../../include/audit.h"
#include "../../include/connection.h"
#include "../../include/dispatcher.h"
#include "../../include/logger.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FTP_RECV_BUFFER_SIZE 4096
#define FTP_MAX_AUTH_ATTEMPTS 6
#define FTP_MAX_CMD_LEN 512
#define FTP_SUCCEED_ON_ATTEMPT 2

#define FTP_BANNER "220 (vsFTPd 3.0.3)\r\n"
#define FTP_RESP_USER_OK "331 Please specify the password.\r\n"
#define FTP_RESP_LOGIN_OK "230 Login successful.\r\n"
#define FTP_RESP_LOGIN_FAIL "530 Login incorrect.\r\n"
#define FTP_RESP_NOT_LOGGED_IN "530 Please login with USER and PASS.\r\n"
#define FTP_RESP_PWD "257 \"/var/www/html\" is the current directory\r\n"
#define FTP_RESP_CWD_OK "250 Directory successfully changed.\r\n"
#define FTP_RESP_TYPE_OK "200 Switching to Binary mode.\r\n"
#define FTP_RESP_PASV "227 Entering Passive Mode (10,0,2,15,39,45).\r\n"
#define FTP_RESP_RETR_FAIL "550 Failed to open file.\r\n"
#define FTP_RESP_STOR_OK "226 Transfer complete.\r\n"
#define FTP_RESP_SYST "215 UNIX Type: L8\r\n"
#define FTP_RESP_GOODBYE "221 Goodbye.\r\n"
#define FTP_RESP_UNKNOWN "500 Unknown command.\r\n"
#define FTP_RESP_FEAT                                                          \
  "211-Features:\r\n"                                                          \
  " EPRT\r\n"                                                                  \
  " EPSV\r\n"                                                                  \
  " MDTM\r\n"                                                                  \
  " PASV\r\n"                                                                  \
  " REST STREAM\r\n"                                                           \
  " SIZE\r\n"                                                                  \
  " TVFS\r\n"                                                                  \
  " UTF8\r\n"                                                                  \
  "211 End\r\n"
#define FTP_RESP_SIZE_FAIL "550 Could not get file size.\r\n"
#define FTP_RESP_DELE_FAIL "550 Permission denied.\r\n"
#define FTP_RESP_MKD_FAIL "550 Permission denied.\r\n"
#define FTP_RESP_RMD_FAIL "550 Permission denied.\r\n"
#define FTP_RESP_NOOP "200 NOOP ok.\r\n"
#define FTP_RESP_PORT_OK "200 PORT command successful.\r\n"
#define FTP_RESP_EPSV "229 Entering Extended Passive Mode (|||10029|).\r\n"

#define FTP_FAKE_LIST_HEADER "150 Here comes the directory listing.\r\n"

#define FTP_FAKE_LIST_DATA                                                     \
  "drwxr-xr-x    2 www-data www-data     4096 Jul 05 08:12 .\r\n"              \
  "drwxr-xr-x    3 root     root         4096 Jun 28 14:30 ..\r\n"             \
  "-rw-r--r--    1 www-data www-data  2048576 Jul 04 22:15 backup.sql\r\n"     \
  "-rw-------    1 root     root          487 Jun 15 09:44 .htpasswd\r\n"      \
  "-rw-r--r--    1 www-data www-data     3214 Jul 01 16:33 wp-config.php\r\n"  \
  "-rw-r--r--    1 www-data www-data 15728640 Jul 03 03:00 "                   \
  "database_dump.tar.gz\r\n"                                                   \
  "-rw-r--r--    1 www-data www-data      741 Jun 20 11:22 .env\r\n"           \
  "-rwxr-xr-x    1 www-data www-data     1024 Jun 18 07:55 deploy.sh\r\n"      \
  "drwxr-xr-x    5 www-data www-data     4096 Jul 02 19:40 uploads\r\n"

#define FTP_FAKE_LIST_FOOTER "226 Directory send OK.\r\n"

typedef struct {
  int authenticated;
  int auth_attempts;
  char username[256];
  char password[256];
  char cwd[512];
} ftp_session_t;

static void ftp_generate_session_id(char *buf, size_t len) {
  audit_generate_session_id(buf, len);
}

static void ftp_strip_crlf(char *str) {
  size_t n = strlen(str);
  while (n > 0 && (str[n - 1] == '\r' || str[n - 1] == '\n'))
    str[--n] = '\0';
}

static void ftp_send(int fd, const char *data) {
  send(fd, data, strlen(data), 0);
}

static const char *ftp_extract_argument(const char *line, size_t cmd_len) {
  if (strlen(line) <= cmd_len)
    return "";
  const char *arg = line + cmd_len;
  while (*arg == ' ')
    arg++;
  return arg;
}

static void ftp_handle_user(ftp_session_t *sess, int sockfd, const char *line,
                            const char *remote_ip, uint16_t remote_port,
                            const char *session_id) {
  const char *user = ftp_extract_argument(line, 4);
  strncpy(sess->username, user, sizeof(sess->username) - 1);
  sess->username[sizeof(sess->username) - 1] = '\0';

  UTILITIES_LOG_WARN("[FTP蜜罐] 收到用户名: \"%s\" 来自 %s:%d", sess->username,
                     remote_ip, remote_port);

  audit_record_command(&g_audit, FTP_PROTOCOL, remote_ip, remote_port,
                       session_id, line);

  sess->authenticated = 0;
  memset(sess->password, 0, sizeof(sess->password));

  ftp_send(sockfd, FTP_RESP_USER_OK);
}

static int ftp_handle_pass(ftp_session_t *sess, int sockfd, const char *line,
                           const char *remote_ip, uint16_t remote_port,
                           const char *session_id) {
  const char *pass = ftp_extract_argument(line, 4);
  strncpy(sess->password, pass, sizeof(sess->password) - 1);
  sess->password[sizeof(sess->password) - 1] = '\0';

  sess->auth_attempts++;

  UTILITIES_LOG_WARN(
      "[FTP蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d (第%d次尝试)",
      sess->username, sess->password, remote_ip, remote_port,
      sess->auth_attempts);

  int success = (sess->auth_attempts >= FTP_SUCCEED_ON_ATTEMPT) ? 1 : 0;

  audit_record_auth(&g_audit, FTP_PROTOCOL, remote_ip, remote_port, session_id,
                    sess->username, sess->password, success);

  if (success) {
    sess->authenticated = 1;
    strncpy(sess->cwd, "/var/www/html", sizeof(sess->cwd) - 1);

    UTILITIES_LOG_WARN("[FTP蜜罐] 攻击者已\"登录\": 用户=\"%s\" 来自 %s:%d",
                       sess->username, remote_ip, remote_port);

    ftp_send(sockfd, FTP_RESP_LOGIN_OK);
  } else {
    ftp_send(sockfd, FTP_RESP_LOGIN_FAIL);
  }

  return success;
}

static void ftp_handle_list(int sockfd, const char *line, const char *remote_ip,
                            uint16_t remote_port, const char *session_id) {
  const char *arg = ftp_extract_argument(line, 4);

  UTILITIES_LOG_WARN("[FTP蜜罐] 目录列表请求: \"%s\" 来自 %s:%d",
                     (strlen(arg) > 0) ? arg : ".", remote_ip, remote_port);

  audit_record_command(&g_audit, FTP_PROTOCOL, remote_ip, remote_port,
                       session_id, line);

  ftp_send(sockfd, FTP_FAKE_LIST_HEADER);
  ftp_send(sockfd, FTP_FAKE_LIST_DATA);
  ftp_send(sockfd, FTP_FAKE_LIST_FOOTER);
}

static void ftp_handle_retr(int sockfd, const char *line, const char *remote_ip,
                            uint16_t remote_port, const char *session_id) {
  const char *filename = ftp_extract_argument(line, 4);

  UTILITIES_LOG_WARN("[FTP蜜罐] 文件下载尝试: \"%s\" 来自 %s:%d", filename,
                     remote_ip, remote_port);

  audit_record_event(&g_audit, AUDIT_EVENT_FILE_ACCESS, AUDIT_SEVERITY_HIGH,
                     FTP_PROTOCOL, remote_ip, remote_port, session_id, "",
                     "RETR %s", filename);

  ftp_send(sockfd, FTP_RESP_RETR_FAIL);
}

static void ftp_handle_stor(int sockfd, const char *line, const char *remote_ip,
                            uint16_t remote_port, const char *session_id) {
  const char *filename = ftp_extract_argument(line, 4);

  UTILITIES_LOG_WARN("[FTP蜜罐] 文件上传尝试: \"%s\" 来自 %s:%d", filename,
                     remote_ip, remote_port);

  audit_record_event(&g_audit, AUDIT_EVENT_FILE_MODIFY, AUDIT_SEVERITY_HIGH,
                     FTP_PROTOCOL, remote_ip, remote_port, session_id, "",
                     "STOR %s", filename);

  ftp_send(sockfd, FTP_RESP_STOR_OK);
}

static void ftp_handle_cwd(ftp_session_t *sess, int sockfd, const char *line,
                           const char *remote_ip, uint16_t remote_port,
                           const char *session_id) {
  const char *dir = ftp_extract_argument(line, 3);

  UTILITIES_LOG_WARN("[FTP蜜罐] 目录切换: \"%s\" 来自 %s:%d", dir, remote_ip,
                     remote_port);

  audit_record_command(&g_audit, FTP_PROTOCOL, remote_ip, remote_port,
                       session_id, line);

  if (dir[0] == '/') {
    strncpy(sess->cwd, dir, sizeof(sess->cwd) - 1);
    sess->cwd[sizeof(sess->cwd) - 1] = '\0';
  } else {
    size_t cur_len = strlen(sess->cwd);
    if (cur_len > 0 && sess->cwd[cur_len - 1] != '/')
      strncat(sess->cwd, "/", sizeof(sess->cwd) - cur_len - 1);
    strncat(sess->cwd, dir, sizeof(sess->cwd) - strlen(sess->cwd) - 1);
  }

  ftp_send(sockfd, FTP_RESP_CWD_OK);
}

static void ftp_handle_dele(int sockfd, const char *line, const char *remote_ip,
                            uint16_t remote_port, const char *session_id) {
  const char *filename = ftp_extract_argument(line, 4);

  UTILITIES_LOG_WARN("[FTP蜜罐] 文件删除尝试: \"%s\" 来自 %s:%d", filename,
                     remote_ip, remote_port);

  audit_record_event(&g_audit, AUDIT_EVENT_FILE_MODIFY, AUDIT_SEVERITY_HIGH,
                     FTP_PROTOCOL, remote_ip, remote_port, session_id, "",
                     "DELE %s", filename);

  ftp_send(sockfd, FTP_RESP_DELE_FAIL);
}

void run_ftp_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  ftp_generate_session_id(session_id, sizeof(session_id));

  UTILITIES_LOG_INFO("[FTP蜜罐] 新连接建立: %s:%d (套接字=%d)", conn->remote_ip,
                     conn->remote_port, conn->socket_file_descriptor);

  audit_record_connection(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  ftp_session_t sess;
  memset(&sess, 0, sizeof(sess));
  strncpy(sess.cwd, "/", sizeof(sess.cwd) - 1);

  int sockfd = conn->socket_file_descriptor;
  ftp_send(sockfd, FTP_BANNER);

  char recv_buf[FTP_RECV_BUFFER_SIZE];
  char line_buf[FTP_RECV_BUFFER_SIZE];
  size_t line_len = 0;
  int running = 1;

  while (running) {
    ssize_t n = recv(sockfd, recv_buf, sizeof(recv_buf) - 1, 0);
    if (n <= 0)
      break;

    recv_buf[n] = '\0';

    for (ssize_t i = 0; i < n; i++) {
      char c = recv_buf[i];

      if (c == '\n') {
        line_buf[line_len] = '\0';
        ftp_strip_crlf(line_buf);

        if (line_len == 0) {
          line_len = 0;
          continue;
        }

        UTILITIES_LOG_WARN("[FTP蜜罐] 收到命令: \"%s\" 来自 %s:%d", line_buf,
                           conn->remote_ip, conn->remote_port);

        if (strncasecmp(line_buf, "USER ", 5) == 0) {
          ftp_handle_user(&sess, sockfd, line_buf, conn->remote_ip,
                          conn->remote_port, session_id);

        } else if (strncasecmp(line_buf, "PASS ", 5) == 0) {
          ftp_handle_pass(&sess, sockfd, line_buf, conn->remote_ip,
                          conn->remote_port, session_id);

          if (sess.auth_attempts >= FTP_MAX_AUTH_ATTEMPTS &&
              !sess.authenticated) {
            UTILITIES_LOG_WARN("[FTP蜜罐] 认证尝试次数超限: %s:%d (共%d次)",
                               conn->remote_ip, conn->remote_port,
                               sess.auth_attempts);
            ftp_send(sockfd, FTP_RESP_GOODBYE);
            running = 0;
          }

        } else if (strncasecmp(line_buf, "QUIT", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_GOODBYE);
          running = 0;

        } else if (!sess.authenticated) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_NOT_LOGGED_IN);

        } else if (strncasecmp(line_buf, "PWD", 3) == 0 ||
                   strncasecmp(line_buf, "XPWD", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          char pwd_resp[600];
          snprintf(pwd_resp, sizeof(pwd_resp),
                   "257 \"%s\" is the current directory\r\n", sess.cwd);
          ftp_send(sockfd, pwd_resp);

        } else if (strncasecmp(line_buf, "LIST", 4) == 0 ||
                   strncasecmp(line_buf, "NLST", 4) == 0 ||
                   strcasecmp(line_buf, "ls") == 0 ||
                   strncasecmp(line_buf, "ls ", 3) == 0) {
          ftp_handle_list(sockfd, line_buf, conn->remote_ip, conn->remote_port,
                          session_id);

        } else if (strncasecmp(line_buf, "CWD ", 4) == 0 ||
                   strncasecmp(line_buf, "XCWD ", 5) == 0) {
          ftp_handle_cwd(&sess, sockfd, line_buf, conn->remote_ip,
                         conn->remote_port, session_id);

        } else if (strncasecmp(line_buf, "CDUP", 4) == 0 ||
                   strncasecmp(line_buf, "XCUP", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          strncpy(sess.cwd, "/var/www", sizeof(sess.cwd) - 1);
          ftp_send(sockfd, FTP_RESP_CWD_OK);

        } else if (strncasecmp(line_buf, "TYPE ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_TYPE_OK);

        } else if (strncasecmp(line_buf, "PASV", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_PASV);

        } else if (strncasecmp(line_buf, "EPSV", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_EPSV);

        } else if (strncasecmp(line_buf, "PORT ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          UTILITIES_LOG_WARN("[FTP蜜罐] PORT命令: \"%s\" 来自 %s:%d",
                             line_buf + 5, conn->remote_ip, conn->remote_port);
          ftp_send(sockfd, FTP_RESP_PORT_OK);

        } else if (strncasecmp(line_buf, "RETR ", 5) == 0) {
          ftp_handle_retr(sockfd, line_buf, conn->remote_ip, conn->remote_port,
                          session_id);

        } else if (strncasecmp(line_buf, "STOR ", 5) == 0) {
          ftp_handle_stor(sockfd, line_buf, conn->remote_ip, conn->remote_port,
                          session_id);

        } else if (strncasecmp(line_buf, "DELE ", 5) == 0) {
          ftp_handle_dele(sockfd, line_buf, conn->remote_ip, conn->remote_port,
                          session_id);

        } else if (strncasecmp(line_buf, "MKD ", 4) == 0 ||
                   strncasecmp(line_buf, "XMKD ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          UTILITIES_LOG_WARN("[FTP蜜罐] 创建目录尝试: \"%s\" 来自 %s:%d",
                             ftp_extract_argument(line_buf, 3), conn->remote_ip,
                             conn->remote_port);
          ftp_send(sockfd, FTP_RESP_MKD_FAIL);

        } else if (strncasecmp(line_buf, "RMD ", 4) == 0 ||
                   strncasecmp(line_buf, "XRMD ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          UTILITIES_LOG_WARN("[FTP蜜罐] 删除目录尝试: \"%s\" 来自 %s:%d",
                             ftp_extract_argument(line_buf, 3), conn->remote_ip,
                             conn->remote_port);
          ftp_send(sockfd, FTP_RESP_RMD_FAIL);

        } else if (strncasecmp(line_buf, "SYST", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_SYST);

        } else if (strncasecmp(line_buf, "FEAT", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_FEAT);

        } else if (strncasecmp(line_buf, "SIZE ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          UTILITIES_LOG_WARN("[FTP蜜罐] 文件大小查询: \"%s\" 来自 %s:%d",
                             line_buf + 5, conn->remote_ip, conn->remote_port);
          ftp_send(sockfd, FTP_RESP_SIZE_FAIL);

        } else if (strncasecmp(line_buf, "NOOP", 4) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_NOOP);

        } else if (strncasecmp(line_buf, "SITE ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          UTILITIES_LOG_WARN("[FTP蜜罐] SITE命令: \"%s\" 来自 %s:%d",
                             line_buf + 5, conn->remote_ip, conn->remote_port);
          ftp_send(sockfd, FTP_RESP_UNKNOWN);

        } else if (strncasecmp(line_buf, "MDTM ", 5) == 0) {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          ftp_send(sockfd, FTP_RESP_SIZE_FAIL);

        } else {
          audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                               conn->remote_port, session_id, line_buf);
          UTILITIES_LOG_WARN("[FTP蜜罐] 未知命令: \"%s\" 来自 %s:%d", line_buf,
                             conn->remote_ip, conn->remote_port);
          ftp_send(sockfd, FTP_RESP_UNKNOWN);
        }

        line_len = 0;
      } else if (line_len < sizeof(line_buf) - 1) {
        line_buf[line_len++] = c;
      }
    }
  }

  UTILITIES_LOG_INFO("[FTP蜜罐] 会话结束: %s:%d (用户=\"%s\", 认证尝试=%d)",
                     conn->remote_ip, conn->remote_port, sess.username,
                     sess.auth_attempts);

  audit_record_disconnect(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
