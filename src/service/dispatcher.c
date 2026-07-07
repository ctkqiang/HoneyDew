#include "../../include/dispatcher.h"
#include "../../include/connection.h"
#include "../../include/finite_state.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#define close closesocket
#else
#include <sys/socket.h>
#endif

service_binding_t service_map[] = {
    {9090, HTTP_PROTOCOL, run_http_service},
    {2222, SSH_PROTOCOL, run_ssh_service},
    {2121, FTP_PROTOCOL, run_ftp_service},
    {2323, TELNET_PROTOCOL, run_telnet_service},
    {2525, SMTP_PROTOCOL, run_smtp_service},
    {3306, MYSQL_PROTOCOL, run_mysql_service},
    {6379, REDIS_PROTOCOL, run_redis_service},
    {5432, POSTGRESQL_PROTOCOL, run_postgresql_service},
    {1100, POP3_PROTOCOL, run_pop3_service},
    {1430, IMAP_PROTOCOL, run_imap_service},
    {5353, DNS_PROTOCOL, run_dns_service},
    {8812, QUESTDB_PROTOCOL, run_questdb_service},
    {0, UNKNOWN_PROTOCOL, NULL},
};

static char *extract_line(connection_t *conn) {
  pthread_mutex_lock(&conn->mutex);

  if (conn->buffer_length == 0) {
    pthread_mutex_unlock(&conn->mutex);
    return NULL;
  }

  unsigned char *start = conn->tcp_reassembly_buffer;
  size_t len = conn->buffer_length;
  size_t i;

  for (i = 0; i < len; i++) {
    if (start[i] == '\n') {
      size_t line_len = (i > 0 && start[i - 1] == '\r') ? i - 1 : i;
      char *line = malloc(line_len + 1);

      if (!line) {
        pthread_mutex_unlock(&conn->mutex);
        return NULL;
      }

      memcpy(line, start, line_len);
      line[line_len] = '\0';
      size_t consume = i + 1;

      if (consume > conn->buffer_length)
        consume = conn->buffer_length;

      memmove(start, start + consume, conn->buffer_length - consume);
      conn->buffer_length -= consume;

      pthread_mutex_unlock(&conn->mutex);
      return line;
    }
  }
  pthread_mutex_unlock(&conn->mutex);
  return NULL;
}

void run_http_service(connection_t *conn) {
  UTILITIES_LOG_INFO("[HTTP蜜罐] 新会话建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  size_t out_len;
  unsigned char *resp = handle_http(conn, NULL, 0, &out_len);

  if (resp) {
    send(conn->socket_file_descriptor, resp, out_len, 0);
    free(resp);
  }

  unsigned char buf[1024];

  while (1) {
    ssize_t n = recv(conn->socket_file_descriptor, buf, sizeof(buf), 0);
    if (n <= 0) {
      if (n == 0) {
        UTILITIES_LOG_INFO("[HTTP蜜罐] 客户端断开连接 (套接字=%d)",
                           conn->socket_file_descriptor);
      } else {
        UTILITIES_LOG_WARN("[HTTP蜜罐] 接收数据失败 (套接字=%d)",
                           conn->socket_file_descriptor);
      }
      break;
    }
    connection_append_data(conn, buf, (size_t)n);

    char *line;
    while ((line = extract_line(conn)) != NULL) {
      UTILITIES_LOG_DEBUG("[HTTP蜜罐] 收到指令: \"%s\" (套接字=%d)", line,
                          conn->socket_file_descriptor);

      unsigned char *response =
          handle_http(conn, (unsigned char *)line, strlen(line), &out_len);

      if (response) {
        send(conn->socket_file_descriptor, response, out_len, 0);
        free(response);
      }
      free(line);

      if (conn->state == (state_condition)HTTP_STATE_CLOSE)
        goto http_done;
    }
  }

http_done:
  close(conn->socket_file_descriptor);
  UTILITIES_LOG_INFO("[HTTP蜜罐] 会话已关闭 (套接字=%d)",
                     conn->socket_file_descriptor);
}
