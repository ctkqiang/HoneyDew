#include "../../include/finite_state.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *handle_http(connection_t *conn, const unsigned char *input,
                           size_t input_len, size_t *out_len) {
  (void)input;
  (void)input_len;

  pthread_mutex_lock(&conn->mutex);

  state_condition current_state = conn->state;

  switch (current_state) {

  case HTTP_STATE_BANNER: {
    conn->state = (state_condition)HTTP_STATE_WAIT_CMD;
    pthread_mutex_unlock(&conn->mutex);
    *out_len = 0;
    return NULL;
  }

  case HTTP_STATE_WAIT_CMD: {
    const char *resp_str =
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.29 (Ubuntu)\r\n"
        "X-Powered-By: PHP/7.2.10\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>Admin Panel</title></head>\n"
        "<body>\n"
        "<h1>Welcome to Admin Dashboard</h1>\n"
        "<p>Server: Apache/2.4.29</p>\n"
        "<p>PHP Version: 7.2.10</p>\n"
        "<!-- TODO: remove debug info before production -->\n"
        "<!-- DB: mysql://root:root@localhost:3306/admin -->\n"
        "<form action=\"/login\" method=\"POST\">\n"
        "  <input name=\"username\" placeholder=\"admin\">\n"
        "  <input name=\"password\" type=\"password\">\n"
        "  <button>Login</button>\n"
        "</form>\n"
        "</body>\n"
        "</html>\r\n";
    *out_len = strlen(resp_str);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, resp_str, *out_len);

    conn->state = (state_condition)HTTP_STATE_CLOSE;

    pthread_mutex_unlock(&conn->mutex);
    return resp;
  }

  default:
    pthread_mutex_unlock(&conn->mutex);
    *out_len = 0;
    return NULL;
  }
}

static char *extract_ssh_banner(const unsigned char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] == '\n') {
      size_t line_len = (i > 0 && data[i - 1] == '\r') ? i - 1 : i;
      char *banner = malloc(line_len + 1);
      if (!banner)
        return NULL;
      memcpy(banner, data, line_len);
      banner[line_len] = '\0';
      return banner;
    }
  }
  return NULL;
}

unsigned char *handle_ssh(connection_t *conn, const unsigned char *input,
                          size_t input_len, size_t *out_len) {
  pthread_mutex_lock(&conn->mutex);

  state_condition current_state = conn->state;

  switch (current_state) {

  case SSH_STATE_BANNER: {
    const char *banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
    *out_len = strlen(banner);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, banner, *out_len);

    conn->state = (state_condition)SSH_STATE_WAIT_AUTH;
    pthread_mutex_unlock(&conn->mutex);

    return resp;
  }

  case SSH_STATE_WAIT_AUTH: {
    UTILITIES_LOG_WARN("[SSH蜜罐] 认证尝试来自 %s:%d (套接字=%d)",
                       conn->remote_ip, conn->remote_port,
                       conn->socket_file_descriptor);

    if (input && input_len > 0) {
      char *client_banner = extract_ssh_banner(input, input_len);
      if (client_banner) {
        UTILITIES_LOG_WARN("[SSH蜜罐] 客户端标识: \"%s\" 来自 %s:%d",
                           client_banner, conn->remote_ip, conn->remote_port);
        free(client_banner);
      }

      UTILITIES_LOG_INFO("[SSH蜜罐] 捕获原始数据 %zu 字节 来自 %s:%d",
                         input_len, conn->remote_ip, conn->remote_port);
    }

    const char *proto_error = "Protocol mismatch.\r\n";
    *out_len = strlen(proto_error);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, proto_error, *out_len);

    conn->state = (state_condition)SSH_STATE_CLOSE;
    pthread_mutex_unlock(&conn->mutex);

    return resp;
  }

  case SSH_STATE_AUTH_FAIL: {
    UTILITIES_LOG_WARN("[SSH蜜罐] 重复认证尝试来自 %s:%d", conn->remote_ip,
                       conn->remote_port);

    if (input && input_len > 0) {
      UTILITIES_LOG_INFO("[SSH蜜罐] 捕获额外数据 %zu 字节", input_len);
    }

    conn->state = (state_condition)SSH_STATE_CLOSE;
    pthread_mutex_unlock(&conn->mutex);

    *out_len = 0;
    return NULL;
  }

  default:
    pthread_mutex_unlock(&conn->mutex);
    *out_len = 0;
    return NULL;
  }
}
