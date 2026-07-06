#include "include/config.h"
#include "include/connection.h"
#include "include/dispatcher.h"
#include "include/finite_state.h"
#include "include/logger.h"
#include "include/session.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  int count;
  int max;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
} conn_semaphore_t;

static void conn_semaphore_init(conn_semaphore_t *s, int max) {
  s->count = 0;
  s->max = max;
  pthread_mutex_init(&s->mutex, NULL);
  pthread_cond_init(&s->cond, NULL);
}

static void conn_semaphore_acquire(conn_semaphore_t *s) {
  pthread_mutex_lock(&s->mutex);
  while (s->count >= s->max) {
    pthread_cond_wait(&s->cond, &s->mutex);
  }
  s->count++;
  pthread_mutex_unlock(&s->mutex);
}

static void conn_semaphore_release(conn_semaphore_t *s) {
  pthread_mutex_lock(&s->mutex);
  s->count--;
  pthread_cond_signal(&s->cond);
  pthread_mutex_unlock(&s->mutex);
}

typedef struct {
  int client_fd;
  struct sockaddr_in client_addr;
  session_table_t *sessions;
  conn_semaphore_t *sem;
} thread_args_t;

static void *connection_handler(void *arg) {
  thread_args_t *a = (thread_args_t *)arg;
  int fd = a->client_fd;
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &a->client_addr.sin_addr, ip, sizeof(ip));
  uint16_t port = ntohs(a->client_addr.sin_port);

  connection_t *conn =
      connection_create(fd, ip, port, HTTP_PROTOCOL, HTTP_STATE_BANNER);
  session_table_add(a->sessions, conn);

  for (int i = 0; service_map[i].port != 0; i++) {
    if (service_map[i].port == get_default_config().listen_port) {
      service_map[i].handler(conn);
      break;
    }
  }

  session_table_remove(a->sessions, fd);
  conn_semaphore_release(a->sem);
  free(a);
  return NULL;
}

int main(void) {
  config_t cfg = get_default_config();

  utilities_set_log_level("信息");
  UTILITIES_LOG_INFO("[蜜罐] 正在启动 %s v%s", UTILITIES_APP_NAME,
                     UTILITIES_VERSION);

  session_table_t *sessions = session_table_create();

  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 创建套接字失败");
    return 1;
  }

  int opt = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(cfg.listen_port);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 绑定端口 %d 失败", cfg.listen_port);
    close(listen_fd);
    return 1;
  }

  if (listen(listen_fd, SOMAXCONN) < 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 监听失败");
    close(listen_fd);
    return 1;
  }

  UTILITIES_LOG_INFO("[蜜罐] 正在监听端口 %d，最大连接数 %d", cfg.listen_port,
                     cfg.max_connections);

  conn_semaphore_t conn_sem;
  conn_semaphore_init(&conn_sem, cfg.max_connections);

  signal(SIGPIPE, SIG_IGN);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd =
        accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
      UTILITIES_LOG_WARN("[蜜罐] 接受连接失败");
      continue;
    }

    conn_semaphore_acquire(&conn_sem);

    thread_args_t *args = malloc(sizeof(*args));
    if (!args) {
      UTILITIES_LOG_ERROR("[蜜罐] 内存分配失败");
      close(client_fd);
      conn_semaphore_release(&conn_sem);
      continue;
    }
    args->client_fd = client_fd;
    args->client_addr = client_addr;
    args->sessions = sessions;
    args->sem = &conn_sem;

    pthread_t tid;
    if (pthread_create(&tid, NULL, connection_handler, args) != 0) {
      UTILITIES_LOG_ERROR("[蜜罐] 创建线程失败");
      close(client_fd);
      conn_semaphore_release(&conn_sem);
      free(args);
      continue;
    }
    pthread_detach(tid);
  }

  close(listen_fd);
  session_table_destroy(sessions);
  return 0;
}
