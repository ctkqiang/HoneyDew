#include "include/config.h"
#include "include/connection.h"
#include "include/dispatcher.h"
#include "include/finite_state.h"
#include "include/logger.h"
#include "include/session.h"

#include <arpa/inet.h>
#include <errno.h>
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
  service_binding_t *binding;
} thread_args_t;

typedef struct {
  service_binding_t *binding;
  session_table_t *sessions;
  conn_semaphore_t *sem;
} listener_args_t;

static void *connection_handler(void *arg) {
  thread_args_t *a = (thread_args_t *)arg;
  int fd = a->client_fd;
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &a->client_addr.sin_addr, ip, sizeof(ip));
  uint16_t port = ntohs(a->client_addr.sin_port);

  connection_t *conn =
      connection_create(fd, ip, port, a->binding->proto, SSH_STATE_BANNER);
  session_table_add(a->sessions, conn);

  a->binding->handler(conn);

  session_table_remove(a->sessions, fd);
  conn_semaphore_release(a->sem);
  free(a);
  return NULL;
}

static void *listener_thread(void *arg) {
  listener_args_t *la = (listener_args_t *)arg;
  service_binding_t *binding = la->binding;

  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 创建套接字失败 (端口 %d): %s", binding->port,
                        strerror(errno));
    free(la);
    return NULL;
  }

  int opt = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(binding->port);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 绑定端口 %d 失败: %s", binding->port,
                        strerror(errno));
    close(listen_fd);
    free(la);
    return NULL;
  }

  if (listen(listen_fd, SOMAXCONN) < 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 监听端口 %d 失败: %s", binding->port,
                        strerror(errno));
    close(listen_fd);
    free(la);
    return NULL;
  }

  UTILITIES_LOG_INFO("[蜜罐] 端口 %d 已启动监听", binding->port);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd =
        accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
      UTILITIES_LOG_WARN("[蜜罐] 接受连接失败 (端口 %d)", binding->port);
      continue;
    }

    conn_semaphore_acquire(la->sem);

    thread_args_t *args = malloc(sizeof(*args));
    if (!args) {
      UTILITIES_LOG_ERROR("[蜜罐] 内存分配失败");
      close(client_fd);
      conn_semaphore_release(la->sem);
      continue;
    }
    args->client_fd = client_fd;
    args->client_addr = client_addr;
    args->sessions = la->sessions;
    args->sem = la->sem;
    args->binding = binding;

    pthread_t tid;
    if (pthread_create(&tid, NULL, connection_handler, args) != 0) {
      UTILITIES_LOG_ERROR("[蜜罐] 创建线程失败");
      close(client_fd);
      conn_semaphore_release(la->sem);
      free(args);
      continue;
    }
    pthread_detach(tid);
  }

  close(listen_fd);
  free(la);
  return NULL;
}

int main(void) {
  config_t cfg = get_default_config();

  utilities_set_log_level("调试");
  UTILITIES_LOG_INFO("[蜜罐] 正在启动 %s v%s", UTILITIES_APP_NAME,
                     UTILITIES_VERSION);

  signal(SIGPIPE, SIG_IGN);

  session_table_t *sessions = session_table_create();

  conn_semaphore_t conn_sem;
  conn_semaphore_init(&conn_sem, cfg.max_connections);

  int service_count = 0;
  for (int i = 0; service_map[i].handler != NULL; i++) {
    service_count++;
  }

  UTILITIES_LOG_INFO("[蜜罐] 共 %d 个服务待启动，最大连接数 %d", service_count,
                     cfg.max_connections);

  pthread_t *listeners = malloc(sizeof(pthread_t) * (size_t)service_count);

  for (int i = 0; i < service_count; i++) {
    listener_args_t *la = malloc(sizeof(*la));
    la->binding = &service_map[i];
    la->sessions = sessions;
    la->sem = &conn_sem;

    if (pthread_create(&listeners[i], NULL, listener_thread, la) != 0) {
      UTILITIES_LOG_ERROR("[蜜罐] 启动监听线程失败 (端口 %d)",
                          service_map[i].port);
      free(la);
    }
  }

  for (int i = 0; i < service_count; i++) {
    pthread_join(listeners[i], NULL);
  }

  free(listeners);
  session_table_destroy(sessions);

  return 0;
}
