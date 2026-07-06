#include "../../include/finite_state.h"
#include "../../include/connection.h"

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
