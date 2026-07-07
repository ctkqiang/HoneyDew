#include "../../include/connection.h"
#include "../../include/logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define SMTP_BANNER "220 mail.honeydew.local ESMTP Postfix (Ubuntu)\r\n"
#define SMTP_BUF_SIZE 4096
#define SMTP_DATA_MAX 65536

static const char *SMTP_EHLO_RESPONSE =
    "250-mail.honeydew.local\r\n"
    "250-SIZE 10240000\r\n"
    "250-AUTH PLAIN LOGIN\r\n"
    "250 OK\r\n";

static const char *SMTP_AUTH_USERNAME_CHALLENGE = "334 VXNlcm5hbWU6\r\n";
static const char *SMTP_AUTH_PASSWORD_CHALLENGE = "334 UGFzc3dvcmQ6\r\n";
static const char *SMTP_AUTH_FAILED = "535 5.7.8 Authentication failed\r\n";
static const char *SMTP_MAIL_OK = "250 2.1.0 Ok\r\n";
static const char *SMTP_RCPT_OK = "250 2.1.5 Ok\r\n";
static const char *SMTP_DATA_START = "354 End data with <CR><LF>.<CR><LF>\r\n";
static const char *SMTP_DATA_QUEUED = "250 2.0.0 Ok: queued\r\n";
static const char *SMTP_VRFY_OK = "252 2.0.0 user\r\n";
static const char *SMTP_RSET_OK = "250 2.0.0 Ok\r\n";
static const char *SMTP_QUIT_OK = "221 2.0.0 Bye\r\n";
static const char *SMTP_UNKNOWN_CMD = "502 5.5.2 Error: command not recognized\r\n";

static int base64_decode(const char *input, char *output, size_t out_size) {
  static const int decode_table[256] = {
      ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
      ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
      ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
      ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
      ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
      ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
      ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
      ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
      ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
      ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
      ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
  };

  size_t input_len = strlen(input);
  size_t out_idx = 0;

  for (size_t i = 0; i < input_len && out_idx < out_size - 1;) {
    unsigned int sextet[4] = {0, 0, 0, 0};
    int valid = 0;

    for (int j = 0; j < 4 && i < input_len; j++) {
      char c = input[i++];
      if (c == '=') {
        sextet[j] = 0;
      } else if (c == '\r' || c == '\n' || c == ' ') {
        j--;
        continue;
      } else {
        sextet[j] = (unsigned int)decode_table[(unsigned char)c];
      }
      valid++;
    }

    if (valid < 2)
      break;

    unsigned int triple =
        (sextet[0] << 18) | (sextet[1] << 12) | (sextet[2] << 6) | sextet[3];

    if (out_idx < out_size - 1)
      output[out_idx++] = (char)((triple >> 16) & 0xFF);
    if (valid > 2 && out_idx < out_size - 1)
      output[out_idx++] = (char)((triple >> 8) & 0xFF);
    if (valid > 3 && out_idx < out_size - 1)
      output[out_idx++] = (char)(triple & 0xFF);
  }

  output[out_idx] = '\0';
  return (int)out_idx;
}

static int smtp_send(int fd, const char *data) {
  size_t len = strlen(data);
  ssize_t sent = send(fd, data, len, 0);
  return (sent == (ssize_t)len) ? 0 : -1;
}

static int smtp_recv_line(int fd, char *buf, size_t buf_size) {
  size_t pos = 0;
  memset(buf, 0, buf_size);

  while (pos < buf_size - 1) {
    char c;
    ssize_t n = recv(fd, &c, 1, 0);
    if (n <= 0)
      return -1;

    buf[pos++] = c;

    if (pos >= 2 && buf[pos - 2] == '\r' && buf[pos - 1] == '\n') {
      buf[pos - 2] = '\0';
      return (int)(pos - 2);
    }
  }

  buf[pos] = '\0';
  return (int)pos;
}

static void smtp_strip_crlf(char *line) {
  size_t len = strlen(line);
  while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n'))
    line[--len] = '\0';
}

static void smtp_handle_auth_login(int fd, connection_t *conn) {
  char line[SMTP_BUF_SIZE];

  if (smtp_send(fd, SMTP_AUTH_USERNAME_CHALLENGE) < 0)
    return;

  if (smtp_recv_line(fd, line, sizeof(line)) < 0)
    return;

  smtp_strip_crlf(line);
  UTILITIES_LOG_WARN("[SMTP蜜罐] AUTH LOGIN 用户名(base64): \"%s\" 来自 %s:%d",
                     line, conn->remote_ip, conn->remote_port);

  char username[SMTP_BUF_SIZE];
  base64_decode(line, username, sizeof(username));

  if (smtp_send(fd, SMTP_AUTH_PASSWORD_CHALLENGE) < 0)
    return;

  if (smtp_recv_line(fd, line, sizeof(line)) < 0)
    return;

  smtp_strip_crlf(line);
  UTILITIES_LOG_WARN("[SMTP蜜罐] AUTH LOGIN 密码(base64): \"%s\" 来自 %s:%d",
                     line, conn->remote_ip, conn->remote_port);

  char password[SMTP_BUF_SIZE];
  base64_decode(line, password, sizeof(password));

  UTILITIES_LOG_WARN(
      "[SMTP蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d", username,
      password, conn->remote_ip, conn->remote_port);

  smtp_send(fd, SMTP_AUTH_FAILED);
}

static void smtp_handle_auth_plain(int fd, const char *arg,
                                   connection_t *conn) {
  char decoded[SMTP_BUF_SIZE];
  char auth_data[SMTP_BUF_SIZE];

  if (arg && strlen(arg) > 0) {
    strncpy(auth_data, arg, sizeof(auth_data) - 1);
    auth_data[sizeof(auth_data) - 1] = '\0';
  } else {
    if (smtp_send(fd, "334\r\n") < 0)
      return;

    char line[SMTP_BUF_SIZE];
    if (smtp_recv_line(fd, line, sizeof(line)) < 0)
      return;
    smtp_strip_crlf(line);
    strncpy(auth_data, line, sizeof(auth_data) - 1);
    auth_data[sizeof(auth_data) - 1] = '\0';
  }

  UTILITIES_LOG_WARN("[SMTP蜜罐] AUTH PLAIN (base64): \"%s\" 来自 %s:%d",
                     auth_data, conn->remote_ip, conn->remote_port);

  int decoded_len = base64_decode(auth_data, decoded, sizeof(decoded));

  const char *authzid = decoded;
  const char *username = "";
  const char *password = "";

  if (decoded_len > 0) {
    const char *p = decoded;
    const char *end = decoded + decoded_len;

    p = memchr(p, '\0', (size_t)(end - p));
    if (p && p < end) {
      username = p + 1;
      p = memchr(username, '\0', (size_t)(end - username));
      if (p && p < end)
        password = p + 1;
    }
  }

  UTILITIES_LOG_WARN(
      "[SMTP蜜罐] 捕获凭据(PLAIN): 用户=\"%s\" 密码=\"%s\" 来自 %s:%d",
      username, password, conn->remote_ip, conn->remote_port);

  (void)authzid;
  smtp_send(fd, SMTP_AUTH_FAILED);
}

static void smtp_handle_data(int fd, connection_t *conn) {
  if (smtp_send(fd, SMTP_DATA_START) < 0)
    return;

  char data_buf[SMTP_DATA_MAX];
  size_t data_len = 0;
  char line[SMTP_BUF_SIZE];

  while (data_len < sizeof(data_buf) - 1) {
    if (smtp_recv_line(fd, line, sizeof(line)) < 0)
      return;

    if (strcmp(line, ".") == 0)
      break;

    size_t line_len = strlen(line);
    if (data_len + line_len + 2 < sizeof(data_buf)) {
      memcpy(data_buf + data_len, line, line_len);
      data_len += line_len;
      data_buf[data_len++] = '\n';
    }
  }

  data_buf[data_len] = '\0';

  char summary[512];
  size_t summary_len = (data_len > 400) ? 400 : data_len;
  memcpy(summary, data_buf, summary_len);
  summary[summary_len] = '\0';

  for (size_t i = 0; i < summary_len; i++) {
    if (summary[i] == '\r' || summary[i] == '\n')
      summary[i] = ' ';
  }

  UTILITIES_LOG_WARN(
      "[SMTP蜜罐] 邮件内容 (%zu 字节) 来自 %s:%d: \"%.400s\"", data_len,
      conn->remote_ip, conn->remote_port, summary);

  smtp_send(fd, SMTP_DATA_QUEUED);
}

void run_smtp_service(connection_t *conn) {
  int fd = conn->socket_file_descriptor;

  UTILITIES_LOG_INFO("[SMTP蜜罐] 新会话建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port, fd);

  if (smtp_send(fd, SMTP_BANNER) < 0) {
    UTILITIES_LOG_ERROR("[SMTP蜜罐] 发送横幅失败: %s:%d", conn->remote_ip,
                        conn->remote_port);
    close(fd);
    return;
  }

  char line[SMTP_BUF_SIZE];

  while (smtp_recv_line(fd, line, sizeof(line)) >= 0) {
    smtp_strip_crlf(line);

    if (strlen(line) == 0)
      continue;

    UTILITIES_LOG_WARN("[SMTP蜜罐] 收到命令: \"%s\" 来自 %s:%d", line,
                       conn->remote_ip, conn->remote_port);

    if (strncasecmp(line, "EHLO", 4) == 0 ||
        strncasecmp(line, "HELO", 4) == 0) {
      char *domain = line + 4;
      while (*domain == ' ')
        domain++;
      UTILITIES_LOG_WARN("[SMTP蜜罐] 客户端标识: \"%s\" 来自 %s:%d", domain,
                         conn->remote_ip, conn->remote_port);
      smtp_send(fd, SMTP_EHLO_RESPONSE);

    } else if (strncasecmp(line, "AUTH LOGIN", 10) == 0) {
      smtp_handle_auth_login(fd, conn);

    } else if (strncasecmp(line, "AUTH PLAIN", 10) == 0) {
      char *arg = line + 10;
      while (*arg == ' ')
        arg++;
      smtp_handle_auth_plain(fd, (*arg != '\0') ? arg : NULL, conn);

    } else if (strncasecmp(line, "MAIL FROM:", 10) == 0) {
      char *sender = line + 10;
      while (*sender == ' ')
        sender++;
      UTILITIES_LOG_WARN("[SMTP蜜罐] 发件人: \"%s\" 来自 %s:%d", sender,
                         conn->remote_ip, conn->remote_port);
      smtp_send(fd, SMTP_MAIL_OK);

    } else if (strncasecmp(line, "RCPT TO:", 8) == 0) {
      char *recipient = line + 8;
      while (*recipient == ' ')
        recipient++;
      UTILITIES_LOG_WARN("[SMTP蜜罐] 收件人: \"%s\" 来自 %s:%d", recipient,
                         conn->remote_ip, conn->remote_port);
      smtp_send(fd, SMTP_RCPT_OK);

    } else if (strncasecmp(line, "DATA", 4) == 0) {
      smtp_handle_data(fd, conn);

    } else if (strncasecmp(line, "VRFY", 4) == 0) {
      char *user = line + 4;
      while (*user == ' ')
        user++;
      UTILITIES_LOG_WARN("[SMTP蜜罐] 验证用户: \"%s\" 来自 %s:%d", user,
                         conn->remote_ip, conn->remote_port);
      smtp_send(fd, SMTP_VRFY_OK);

    } else if (strncasecmp(line, "RSET", 4) == 0) {
      UTILITIES_LOG_WARN("[SMTP蜜罐] 会话重置 来自 %s:%d", conn->remote_ip,
                         conn->remote_port);
      smtp_send(fd, SMTP_RSET_OK);

    } else if (strncasecmp(line, "QUIT", 4) == 0) {
      UTILITIES_LOG_WARN("[SMTP蜜罐] 客户端退出: %s:%d", conn->remote_ip,
                         conn->remote_port);
      smtp_send(fd, SMTP_QUIT_OK);
      break;

    } else {
      UTILITIES_LOG_WARN("[SMTP蜜罐] 未知命令: \"%s\" 来自 %s:%d", line,
                         conn->remote_ip, conn->remote_port);
      smtp_send(fd, SMTP_UNKNOWN_CMD);
    }
  }

  close(fd);
  UTILITIES_LOG_INFO("[SMTP蜜罐] 会话已关闭: %s:%d", conn->remote_ip,
                     conn->remote_port);
}
