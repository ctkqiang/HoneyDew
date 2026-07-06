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
    const char *banner = "200 蜜罐HTTP服务器已就绪\r\n";
    *out_len = strlen(banner);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, banner, *out_len);

    conn->state = (state_condition)HTTP_STATE_WAIT_CMD;
    pthread_mutex_unlock(&conn->mutex);

    return resp;
  }

  case HTTP_STATE_WAIT_CMD: {
    const char *resp_str = "HTTP/1.0 200 OK\r\nContent-Type: text/html; "
                           "charset=utf-8\r\n\r\n"
                           "<html><body>蜜罐陷阱</body></html>\r\n";
    *out_len = strlen(resp_str);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, resp_str, *out_len);

    conn->state = (state_condition)HTTP_STATE_PROCESS;

    pthread_mutex_unlock(&conn->mutex);
    return resp;
  }

  case HTTP_STATE_PROCESS: {
    const char *close_msg = "连接正在关闭。\r\n";
    *out_len = strlen(close_msg);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, close_msg, *out_len);

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
    (void)input;
    (void)input_len;

    UTILITIES_LOG_WARN("[SSH蜜罐] 认证尝试来自 %s:%d (套接字=%d)",
                       conn->remote_ip, conn->remote_port,
                       conn->socket_file_descriptor);

    if (input && input_len > 0) {
      char safe_input[256];
      size_t copy_len = input_len < 255 ? input_len : 255;
      memcpy(safe_input, input, copy_len);
      safe_input[copy_len] = '\0';
      UTILITIES_LOG_WARN("[SSH蜜罐] 捕获凭据: \"%s\"", safe_input);
    }

    const char *auth_fail = "\r\n权限拒绝, 请重试。\r\n"
                            "Permission denied (publickey,password).\r\n";
    *out_len = strlen(auth_fail);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, auth_fail, *out_len);

    conn->state = (state_condition)SSH_STATE_AUTH_FAIL;
    pthread_mutex_unlock(&conn->mutex);

    return resp;
  }

  case SSH_STATE_AUTH_FAIL: {
    (void)input;
    (void)input_len;

    UTILITIES_LOG_WARN("[SSH蜜罐] 重复认证尝试来自 %s:%d", conn->remote_ip,
                       conn->remote_port);

    if (input && input_len > 0) {
      char safe_input[256];
      size_t copy_len = input_len < 255 ? input_len : 255;
      memcpy(safe_input, input, copy_len);
      safe_input[copy_len] = '\0';
      UTILITIES_LOG_WARN("[SSH蜜罐] 捕获凭据: \"%s\"", safe_input);
    }

    const char *disconnect = "认证失败次数过多。\r\n"
                             "Connection closed by remote host.\r\n";
    *out_len = strlen(disconnect);

    unsigned char *resp = malloc(*out_len + 1);
    memcpy(resp, disconnect, *out_len);

    conn->state = (state_condition)SSH_STATE_CLOSE;
    pthread_mutex_unlock(&conn->mutex);

    return resp;
  }

  default:
    pthread_mutex_unlock(&conn->mutex);
    *out_len = 0;
    return NULL;
  }
}
