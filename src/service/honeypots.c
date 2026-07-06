#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/dispatcher.h"
#include "../../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#define HONEYPOT_RECV_BUFFER_SIZE 4096

static void generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "sess_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static void strip_crlf(char *str) {
  size_t n = strlen(str);
  while (n > 0 && (str[n - 1] == '\r' || str[n - 1] == '\n'))
    str[--n] = '\0';
}

/* ========================================================================== */
/* FTP Honeypot - vsftpd 3.0.3                                                */
/* ========================================================================== */

void run_ftp_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[FTP蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner = "220 (vsFTPd 3.0.3)\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  char username[256] = {0};
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    strip_crlf(buf);

    UTILITIES_LOG_INFO("[FTP蜜罐] 收到命令: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    if (strncasecmp(buf, "USER ", 5) == 0) {
      strncpy(username, buf + 5, sizeof(username) - 1);
      username[sizeof(username) - 1] = '\0';
      const char *resp = "331 Please specify the password.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "PASS ", 5) == 0) {
      const char *password = buf + 5;

      UTILITIES_LOG_WARN("[FTP蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d",
                         username, password, conn->remote_ip,
                         conn->remote_port);

      audit_record_auth(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                        conn->remote_port, session_id, username, password, 0);

      const char *resp = "530 Login incorrect.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      memset(username, 0, sizeof(username));

    } else if (strncasecmp(buf, "LIST", 4) == 0) {
      const char *resp =
          "150 Here comes the directory listing.\r\n"
          "226 Directory send OK.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "PWD", 3) == 0) {
      const char *resp = "257 \"/\" is the current directory\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "SYST", 4) == 0) {
      const char *resp = "215 UNIX Type: L8\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "QUIT", 4) == 0) {
      const char *resp = "221 Goodbye.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else {
      const char *resp = "500 Unknown command.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
    }
  }

  UTILITIES_LOG_INFO("[FTP蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, FTP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* Telnet Honeypot                                                            */
/* ========================================================================== */

static const char *telnet_fake_response(const char *cmd) {
  if (strstr(cmd, "whoami"))
    return "root\r\n";
  if (strstr(cmd, "id"))
    return "uid=0(root) gid=0(root) groups=0(root)\r\n";
  if (strstr(cmd, "uname"))
    return "Linux gateway 4.15.0-213-generic #224-Ubuntu SMP x86_64\r\n";
  if (strstr(cmd, "pwd"))
    return "/root\r\n";
  if (strstr(cmd, "ls"))
    return "bin  etc  home  lib  proc  root  sbin  tmp  usr  var\r\n";
  if (strstr(cmd, "cat /etc/passwd"))
    return "root:x:0:0:root:/root:/bin/bash\r\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n";
  if (strstr(cmd, "ps"))
    return "  PID TTY      TIME CMD\r\n"
           "    1 ?    00:00:02 init\r\n"
           "  234 ?    00:00:00 telnetd\r\n"
           "  567 pts/0 00:00:00 bash\r\n";
  if (strstr(cmd, "exit") || strstr(cmd, "logout"))
    return NULL;
  return "sh: command not found\r\n";
}

void run_telnet_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[Telnet蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  int auth_attempts = 0;
  int authenticated = 0;

  while (!authenticated && auth_attempts < 3) {
    const char *login_prompt = "\r\nlogin: ";
    send(conn->socket_file_descriptor, login_prompt, strlen(login_prompt), 0);

    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      goto telnet_end;
    buf[n] = '\0';
    strip_crlf(buf);

    char username[256];
    strncpy(username, buf, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';

    const char *pass_prompt = "Password: ";
    send(conn->socket_file_descriptor, pass_prompt, strlen(pass_prompt), 0);

    memset(buf, 0, sizeof(buf));
    n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      goto telnet_end;
    buf[n] = '\0';
    strip_crlf(buf);

    char password[256];
    strncpy(password, buf, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    UTILITIES_LOG_WARN("[Telnet蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d",
                       username, password, conn->remote_ip, conn->remote_port);

    audit_record_auth(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                      conn->remote_port, session_id, username, password, 0);

    auth_attempts++;

    if (auth_attempts >= 3) {
      const char *msg = "\r\n";
      send(conn->socket_file_descriptor, msg, strlen(msg), 0);
      authenticated = 1;
    } else {
      const char *fail = "\r\nLogin incorrect\r\n";
      send(conn->socket_file_descriptor, fail, strlen(fail), 0);
    }
  }

  if (!authenticated)
    goto telnet_end;

  UTILITIES_LOG_WARN("[Telnet蜜罐] 攻击者已\"登录\": %s:%d", conn->remote_ip,
                     conn->remote_port);

  const char *motd =
      "\r\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic "
      "x86_64)\r\n\r\n";
  send(conn->socket_file_descriptor, motd, strlen(motd), 0);

  const char *shell_prompt = "root@gateway:~# ";

  while (1) {
    send(conn->socket_file_descriptor, shell_prompt, strlen(shell_prompt), 0);

    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;
    buf[n] = '\0';
    strip_crlf(buf);

    if (strlen(buf) == 0)
      continue;

    UTILITIES_LOG_WARN("[Telnet蜜罐] 执行命令: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    const char *response = telnet_fake_response(buf);
    if (!response)
      break;

    send(conn->socket_file_descriptor, response, strlen(response), 0);
  }

telnet_end:
  UTILITIES_LOG_INFO("[Telnet蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* SMTP Honeypot - Postfix                                                    */
/* ========================================================================== */

void run_smtp_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[SMTP蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, SMTP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner = "220 mail.example.com ESMTP Postfix\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  int in_data = 0;
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    strip_crlf(buf);

    UTILITIES_LOG_INFO("[SMTP蜜罐] 收到: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, SMTP_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    if (in_data) {
      if (strcmp(buf, ".") == 0) {
        in_data = 0;
        const char *resp = "250 2.0.0 Ok: queued as 4A1B2C3D4E\r\n";
        send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      }
      continue;
    }

    if (strncasecmp(buf, "EHLO", 4) == 0 || strncasecmp(buf, "HELO", 4) == 0) {
      const char *resp =
          "250-mail.example.com\r\n"
          "250-PIPELINING\r\n"
          "250-SIZE 10240000\r\n"
          "250-VRFY\r\n"
          "250-ETRN\r\n"
          "250-STARTTLS\r\n"
          "250-AUTH PLAIN LOGIN\r\n"
          "250 8BITMIME\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "MAIL FROM:", 10) == 0) {
      const char *resp = "250 2.1.0 Ok\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "RCPT TO:", 8) == 0) {
      const char *resp = "250 2.1.5 Ok\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "DATA", 4) == 0) {
      const char *resp = "354 End data with <CR><LF>.<CR><LF>\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      in_data = 1;

    } else if (strncasecmp(buf, "QUIT", 4) == 0) {
      const char *resp = "221 2.0.0 Bye\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strncasecmp(buf, "RSET", 4) == 0) {
      const char *resp = "250 2.0.0 Ok\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "NOOP", 4) == 0) {
      const char *resp = "250 2.0.0 Ok\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "AUTH", 4) == 0) {
      const char *resp = "535 5.7.8 Error: authentication failed\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else {
      const char *resp = "502 5.5.2 Error: command not recognized\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
    }
  }

  UTILITIES_LOG_INFO("[SMTP蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, SMTP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* POP3 Honeypot                                                              */
/* ========================================================================== */

void run_pop3_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[POP3蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner = "+OK POP3 server ready\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  char username[256] = {0};
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    strip_crlf(buf);

    UTILITIES_LOG_INFO("[POP3蜜罐] 收到命令: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    if (strncasecmp(buf, "USER ", 5) == 0) {
      strncpy(username, buf + 5, sizeof(username) - 1);
      username[sizeof(username) - 1] = '\0';
      const char *resp = "+OK\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "PASS ", 5) == 0) {
      const char *password = buf + 5;

      UTILITIES_LOG_WARN(
          "[POP3蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d", username,
          password, conn->remote_ip, conn->remote_port);

      audit_record_auth(&g_audit, POP3_PROTOCOL, conn->remote_ip,
                        conn->remote_port, session_id, username, password, 0);

      const char *resp = "-ERR [AUTH] Authentication failed.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      memset(username, 0, sizeof(username));

    } else if (strncasecmp(buf, "QUIT", 4) == 0) {
      const char *resp = "+OK Bye\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strncasecmp(buf, "CAPA", 4) == 0) {
      const char *resp =
          "+OK Capability list follows\r\n"
          "USER\r\n"
          "UIDL\r\n"
          "TOP\r\n"
          ".\r\n";
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

/* ========================================================================== */
/* IMAP Honeypot                                                              */
/* ========================================================================== */

void run_imap_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[IMAP蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, IMAP_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner = "* OK IMAP4rev1 Service Ready\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    strip_crlf(buf);

    UTILITIES_LOG_INFO("[IMAP蜜罐] 收到: \"%s\" 来自 %s:%d", buf,
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
      char *args = cmd + 6;
      char username[256] = {0};
      char password[256] = {0};

      char *pw_start = NULL;
      if (args[0] == '"') {
        char *end_quote = strchr(args + 1, '"');
        if (end_quote) {
          size_t ulen = (size_t)(end_quote - args - 1);
          if (ulen >= sizeof(username))
            ulen = sizeof(username) - 1;
          memcpy(username, args + 1, ulen);
          pw_start = end_quote + 2;
        }
      } else {
        char *sp = strchr(args, ' ');
        if (sp) {
          size_t ulen = (size_t)(sp - args);
          if (ulen >= sizeof(username))
            ulen = sizeof(username) - 1;
          memcpy(username, args, ulen);
          pw_start = sp + 1;
        }
      }

      if (pw_start) {
        if (pw_start[0] == '"') {
          char *end_quote = strchr(pw_start + 1, '"');
          if (end_quote) {
            size_t plen = (size_t)(end_quote - pw_start - 1);
            if (plen >= sizeof(password))
              plen = sizeof(password) - 1;
            memcpy(password, pw_start + 1, plen);
          }
        } else {
          strncpy(password, pw_start, sizeof(password) - 1);
        }
      }

      UTILITIES_LOG_WARN(
          "[IMAP蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d", username,
          password, conn->remote_ip, conn->remote_port);

      audit_record_auth(&g_audit, IMAP_PROTOCOL, conn->remote_ip,
                        conn->remote_port, session_id, username, password, 0);

      char resp[256];
      snprintf(resp, sizeof(resp),
               "%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "CAPABILITY", 10) == 0) {
      char resp[512];
      snprintf(resp, sizeof(resp),
               "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN STARTTLS\r\n"
               "%s OK CAPABILITY completed\r\n",
               tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(cmd, "LOGOUT", 6) == 0) {
      char resp[256];
      snprintf(resp, sizeof(resp),
               "* BYE IMAP4rev1 Server logging out\r\n"
               "%s OK LOGOUT completed\r\n",
               tag);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strncasecmp(cmd, "NOOP", 4) == 0) {
      char resp[128];
      snprintf(resp, sizeof(resp), "%s OK NOOP completed\r\n", tag);
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

/* ========================================================================== */
/* DNS Honeypot                                                               */
/* ========================================================================== */

void run_dns_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[DNS蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, DNS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  unsigned char buf[HONEYPOT_RECV_BUFFER_SIZE];
  ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n > 0) {
    char hex_dump[HONEYPOT_RECV_BUFFER_SIZE * 3 + 1];
    size_t hex_len = 0;
    for (ssize_t i = 0; i < n && hex_len < sizeof(hex_dump) - 4; i++) {
      hex_len += (size_t)snprintf(hex_dump + hex_len,
                                  sizeof(hex_dump) - hex_len, "%02x ", buf[i]);
    }
    hex_dump[hex_len] = '\0';

    UTILITIES_LOG_INFO("[DNS蜜罐] 收到查询数据 (%zd 字节): %s", n, hex_dump);

    audit_record_command(&g_audit, DNS_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, hex_dump);

    if (n >= 12) {
      unsigned char nxdomain_response[HONEYPOT_RECV_BUFFER_SIZE];
      memcpy(nxdomain_response, buf, (size_t)n);

      nxdomain_response[2] = 0x81;
      nxdomain_response[3] = 0x83;

      nxdomain_response[6] = 0x00;
      nxdomain_response[7] = 0x00;
      nxdomain_response[8] = 0x00;
      nxdomain_response[9] = 0x00;
      nxdomain_response[10] = 0x00;
      nxdomain_response[11] = 0x00;

      send(conn->socket_file_descriptor, nxdomain_response, (size_t)n, 0);

      UTILITIES_LOG_INFO("[DNS蜜罐] 已发送 NXDOMAIN 响应至 %s:%d",
                         conn->remote_ip, conn->remote_port);
    }
  }

  UTILITIES_LOG_INFO("[DNS蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, DNS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* MySQL Honeypot - 5.7.42-log                                                */
/* ========================================================================== */

void run_mysql_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[MySQL蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, MYSQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *server_version = "5.7.42-log";
  unsigned char greeting[128];
  size_t pos = 0;

  size_t version_len = strlen(server_version);
  size_t payload_len = 1 + version_len + 1 + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 +
                       10 + 13;

  greeting[pos++] = (unsigned char)(payload_len & 0xFF);
  greeting[pos++] = (unsigned char)((payload_len >> 8) & 0xFF);
  greeting[pos++] = (unsigned char)((payload_len >> 16) & 0xFF);
  greeting[pos++] = 0x00;

  greeting[pos++] = 0x0A;

  memcpy(greeting + pos, server_version, version_len);
  pos += version_len;
  greeting[pos++] = 0x00;

  greeting[pos++] = 0x01;
  greeting[pos++] = 0x00;
  greeting[pos++] = 0x00;
  greeting[pos++] = 0x00;

  const unsigned char salt_part1[] = {0x3a, 0x23, 0x4e, 0x5a,
                                      0x6b, 0x7c, 0x2d, 0x1e};
  memcpy(greeting + pos, salt_part1, 8);
  pos += 8;

  greeting[pos++] = 0x00;

  greeting[pos++] = 0xFF;
  greeting[pos++] = 0xF7;

  greeting[pos++] = 0x21;

  greeting[pos++] = 0x02;
  greeting[pos++] = 0x00;

  greeting[pos++] = 0xFF;
  greeting[pos++] = 0x81;

  greeting[pos++] = 0x15;

  memset(greeting + pos, 0, 10);
  pos += 10;

  const unsigned char salt_part2[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                                      0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C};
  memcpy(greeting + pos, salt_part2, 12);
  pos += 12;
  greeting[pos++] = 0x00;

  send(conn->socket_file_descriptor, greeting, pos, 0);

  unsigned char buf[HONEYPOT_RECV_BUFFER_SIZE];
  ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n > 4) {
    char username[256] = {0};
    size_t offset = 4 + 4 + 4 + 1 + 23;

    if (offset < (size_t)n) {
      size_t ulen = strnlen((const char *)(buf + offset), (size_t)n - offset);
      if (ulen >= sizeof(username))
        ulen = sizeof(username) - 1;
      memcpy(username, buf + offset, ulen);
      username[ulen] = '\0';
    }

    UTILITIES_LOG_WARN("[MySQL蜜罐] 捕获认证: 用户=\"%s\" 来自 %s:%d", username,
                       conn->remote_ip, conn->remote_port);

    audit_record_auth(&g_audit, MYSQL_PROTOCOL, conn->remote_ip,
                      conn->remote_port, session_id, username, "(hashed)", 0);

    const char *error_msg = "Access denied for user";
    size_t err_msg_len = strlen(error_msg);
    unsigned char err_packet[256];
    size_t epos = 0;

    size_t err_payload = 1 + 2 + 1 + 5 + err_msg_len;
    err_packet[epos++] = (unsigned char)(err_payload & 0xFF);
    err_packet[epos++] = (unsigned char)((err_payload >> 8) & 0xFF);
    err_packet[epos++] = (unsigned char)((err_payload >> 16) & 0xFF);
    err_packet[epos++] = 0x02;

    err_packet[epos++] = 0xFF;

    err_packet[epos++] = 0x15;
    err_packet[epos++] = 0x04;

    err_packet[epos++] = '#';
    memcpy(err_packet + epos, "28000", 5);
    epos += 5;

    memcpy(err_packet + epos, error_msg, err_msg_len);
    epos += err_msg_len;

    send(conn->socket_file_descriptor, err_packet, epos, 0);
  }

  UTILITIES_LOG_INFO("[MySQL蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, MYSQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* PostgreSQL Honeypot                                                        */
/* ========================================================================== */

void run_postgresql_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, POSTGRESQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  unsigned char buf[HONEYPOT_RECV_BUFFER_SIZE];
  ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n <= 0) {
    UTILITIES_LOG_WARN("[PostgreSQL蜜罐] 未收到启动消息: %s:%d",
                       conn->remote_ip, conn->remote_port);
    goto pg_end;
  }

  char username[256] = {0};
  if (n > 8) {
    const char *params = (const char *)(buf + 8);
    size_t remaining = (size_t)n - 8;

    while (remaining > 1) {
      size_t key_len = strnlen(params, remaining);
      if (key_len == 0 || key_len >= remaining)
        break;

      const char *key = params;
      params += key_len + 1;
      remaining -= key_len + 1;

      size_t val_len = strnlen(params, remaining);
      const char *val = params;
      params += val_len + 1;
      remaining -= val_len + 1;

      if (strcmp(key, "user") == 0) {
        strncpy(username, val, sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0';
      }
    }
  }

  UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 启动消息: 用户=\"%s\" 来自 %s:%d",
                     username, conn->remote_ip, conn->remote_port);

  unsigned char auth_request[] = {'R', 0x00, 0x00, 0x00, 0x08,
                                  0x00, 0x00, 0x00, 0x03};
  send(conn->socket_file_descriptor, auth_request, sizeof(auth_request), 0);

  memset(buf, 0, sizeof(buf));
  n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);

  if (n > 5 && buf[0] == 'p') {
    uint32_t msg_len = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) |
                       ((uint32_t)buf[3] << 8) | (uint32_t)buf[4];
    (void)msg_len;

    char password[256] = {0};
    size_t pw_len = strnlen((const char *)(buf + 5), (size_t)n - 5);
    if (pw_len >= sizeof(password))
      pw_len = sizeof(password) - 1;
    memcpy(password, buf + 5, pw_len);
    password[pw_len] = '\0';

    UTILITIES_LOG_WARN(
        "[PostgreSQL蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d",
        username, password, conn->remote_ip, conn->remote_port);

    audit_record_auth(&g_audit, POSTGRESQL_PROTOCOL, conn->remote_ip,
                      conn->remote_port, session_id, username, password, 0);

    unsigned char auth_ok[] = {'R', 0x00, 0x00, 0x00, 0x08,
                               0x00, 0x00, 0x00, 0x00};
    send(conn->socket_file_descriptor, auth_ok, sizeof(auth_ok), 0);

    const char *fatal_msg = "SFATAL\0VFATAL\0C3D000\0"
                            "Mdatabase \"production\" does not exist\0\0";
    size_t fatal_detail_len = 0;
    const char *p = fatal_msg;
    while (1) {
      if (*p == '\0') {
        fatal_detail_len++;
        if (*(p + 1) == '\0') {
          fatal_detail_len++;
          break;
        }
      }
      fatal_detail_len++;
      p++;
    }

    unsigned char error_packet[512];
    size_t epos = 0;
    error_packet[epos++] = 'E';
    uint32_t elen = (uint32_t)(4 + fatal_detail_len);
    error_packet[epos++] = (unsigned char)((elen >> 24) & 0xFF);
    error_packet[epos++] = (unsigned char)((elen >> 16) & 0xFF);
    error_packet[epos++] = (unsigned char)((elen >> 8) & 0xFF);
    error_packet[epos++] = (unsigned char)(elen & 0xFF);
    memcpy(error_packet + epos, fatal_msg, fatal_detail_len);
    epos += fatal_detail_len;

    send(conn->socket_file_descriptor, error_packet, epos, 0);
  }

pg_end:
  UTILITIES_LOG_INFO("[PostgreSQL蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, POSTGRESQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* Redis Honeypot                                                             */
/* ========================================================================== */

void run_redis_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[Redis蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, REDIS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';

    char *line = buf;
    char command[256] = {0};
    char arg1[256] = {0};

    if (buf[0] == '*') {
      int argc = atoi(buf + 1);
      (void)argc;

      line = strchr(line, '\n');
      if (!line)
        continue;
      line++;

      if (line[0] == '$') {
        line = strchr(line, '\n');
        if (!line)
          continue;
        line++;
        char *end = strchr(line, '\r');
        if (end) {
          size_t clen = (size_t)(end - line);
          if (clen >= sizeof(command))
            clen = sizeof(command) - 1;
          memcpy(command, line, clen);
          command[clen] = '\0';
          line = end + 2;
        }

        if (line[0] == '$') {
          line = strchr(line, '\n');
          if (line) {
            line++;
            char *aend = strchr(line, '\r');
            if (aend) {
              size_t alen = (size_t)(aend - line);
              if (alen >= sizeof(arg1))
                alen = sizeof(arg1) - 1;
              memcpy(arg1, line, alen);
              arg1[alen] = '\0';
            }
          }
        }
      }
    } else {
      strip_crlf(buf);
      char *sp = strchr(buf, ' ');
      if (sp) {
        size_t clen = (size_t)(sp - buf);
        if (clen >= sizeof(command))
          clen = sizeof(command) - 1;
        memcpy(command, buf, clen);
        command[clen] = '\0';
        strncpy(arg1, sp + 1, sizeof(arg1) - 1);
      } else {
        strncpy(command, buf, sizeof(command) - 1);
      }
    }

    if (strlen(command) == 0)
      continue;

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf), "%s %s", command, arg1);

    UTILITIES_LOG_INFO("[Redis蜜罐] 收到命令: \"%s\" 来自 %s:%d", log_buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, REDIS_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, log_buf);

    if (strcasecmp(command, "PING") == 0) {
      const char *resp = "+PONG\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strcasecmp(command, "AUTH") == 0) {
      UTILITIES_LOG_WARN("[Redis蜜罐] 认证尝试: 密码=\"%s\" 来自 %s:%d", arg1,
                         conn->remote_ip, conn->remote_port);

      audit_record_auth(&g_audit, REDIS_PROTOCOL, conn->remote_ip,
                        conn->remote_port, session_id, "", arg1, 0);

      const char *resp = "-ERR invalid password\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strcasecmp(command, "INFO") == 0) {
      const char *info_data =
          "# Server\r\n"
          "redis_version:6.2.14\r\n"
          "redis_mode:standalone\r\n"
          "os:Linux 5.15.0-91-generic x86_64\r\n"
          "tcp_port:6379\r\n"
          "uptime_in_seconds:1234567\r\n"
          "uptime_in_days:14\r\n"
          "connected_clients:3\r\n"
          "used_memory:1048576\r\n"
          "used_memory_human:1.00M\r\n";
      char resp[1024];
      snprintf(resp, sizeof(resp), "$%zu\r\n%s\r\n", strlen(info_data),
               info_data);
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strcasecmp(command, "QUIT") == 0) {
      const char *resp = "+OK\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strcasecmp(command, "CONFIG") == 0) {
      const char *resp = "-ERR unknown command 'CONFIG'\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strcasecmp(command, "SET") == 0 ||
               strcasecmp(command, "GET") == 0 ||
               strcasecmp(command, "DEL") == 0) {
      const char *resp = "-NOAUTH Authentication required.\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else {
      const char *resp = "-ERR unknown command\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
    }
  }

  UTILITIES_LOG_INFO("[Redis蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, REDIS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}

/* ========================================================================== */
/* QuestDB Honeypot                                                           */
/* ========================================================================== */

void run_questdb_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  generate_session_id(session_id, sizeof(session_id),
                      conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[QuestDB蜜罐] 新连接: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_connection(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  const char *banner = "QuestDB 7.3.1 (compatible)\r\n";
  send(conn->socket_file_descriptor, banner, strlen(banner), 0);

  char buf[HONEYPOT_RECV_BUFFER_SIZE];
  int running = 1;

  while (running) {
    memset(buf, 0, sizeof(buf));
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
      break;

    buf[n] = '\0';
    strip_crlf(buf);

    if (strlen(buf) == 0)
      continue;

    UTILITIES_LOG_INFO("[QuestDB蜜罐] 收到命令: \"%s\" 来自 %s:%d", buf,
                       conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, buf);

    if (strncasecmp(buf, "SELECT", 6) == 0) {
      const char *resp =
          "+--------+\r\n"
          "| result |\r\n"
          "+--------+\r\n"
          "| 0 rows |\r\n"
          "+--------+\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "INSERT", 6) == 0 ||
               strncasecmp(buf, "CREATE", 6) == 0) {
      const char *resp = "OK\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "SHOW", 4) == 0) {
      const char *resp =
          "+----------------+\r\n"
          "| table          |\r\n"
          "+----------------+\r\n"
          "| trades         |\r\n"
          "| sensors        |\r\n"
          "| weather        |\r\n"
          "+----------------+\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else if (strncasecmp(buf, "\\q", 2) == 0 ||
               strncasecmp(buf, "QUIT", 4) == 0 ||
               strncasecmp(buf, "EXIT", 4) == 0) {
      const char *resp = "Bye\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
      running = 0;

    } else if (strncasecmp(buf, "DROP", 4) == 0) {
      const char *resp = "ERROR: permission denied\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);

    } else {
      const char *resp = "ERROR: unexpected SQL statement\r\n";
      send(conn->socket_file_descriptor, resp, strlen(resp), 0);
    }
  }

  UTILITIES_LOG_INFO("[QuestDB蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, QUESTDB_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
