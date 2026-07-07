#include "include/audit.h"
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
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;

static int ensure_key_directory(void) {
  struct stat st;
  if (stat(SSH_KEY_DIR, &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      UTILITIES_LOG_ERROR("[蜜罐] %s 存在但不是目录", SSH_KEY_DIR);
      return -1;
    }
    return 0;
  }

  if (mkdir(SSH_KEY_DIR, 0700) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 无法创建密钥目录 %s: %s", SSH_KEY_DIR,
                        strerror(errno));
    return -1;
  }

  UTILITIES_LOG_INFO("[蜜罐] 已创建密钥目录: %s (权限=0700)", SSH_KEY_DIR);
  return 0;
}

static int validate_key_file(const char *path, mode_t expected_mode) {
  struct stat st;
  if (stat(path, &st) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 密钥文件不存在: %s", path);
    return -1;
  }

  if (st.st_size == 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 密钥文件为空: %s", path);
    return -1;
  }

  if ((st.st_mode & 0777) != expected_mode) {
    UTILITIES_LOG_WARN("[蜜罐] 密钥文件权限不正确: %s (当前=%04o, 期望=%04o)",
                       path, st.st_mode & 0777, expected_mode);
    if (chmod(path, expected_mode) != 0) {
      UTILITIES_LOG_ERROR("[蜜罐] 无法修正密钥文件权限: %s", strerror(errno));
      return -1;
    }
    UTILITIES_LOG_INFO("[蜜罐] 已修正密钥文件权限: %s -> %04o", path,
                       expected_mode);
  }

  FILE *fp = fopen(path, "r");
  if (!fp) {
    UTILITIES_LOG_ERROR("[蜜罐] 无法读取密钥文件: %s", path);
    return -1;
  }

  char header[64];
  if (fgets(header, sizeof(header), fp) == NULL) {
    fclose(fp);
    UTILITIES_LOG_ERROR("[蜜罐] 密钥文件格式无效: %s", path);
    return -1;
  }
  fclose(fp);

  if (expected_mode == 0600) {
    if (strstr(header, "-----BEGIN") == NULL) {
      UTILITIES_LOG_ERROR("[蜜罐] 私钥文件格式无效 (缺少 PEM 头): %s", path);
      return -1;
    }
  }

  return 0;
}

static int ensure_ssh_host_key(const char *key_path) {
  if (ensure_key_directory() != 0) {
    return -1;
  }

  struct stat st;
  if (stat(key_path, &st) == 0 && st.st_size > 0) {
    UTILITIES_LOG_INFO("[蜜罐] SSH 主机密钥已存在: %s", key_path);
    if (validate_key_file(key_path, 0600) != 0) {
      return -1;
    }
    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "%s.pub", key_path);
    if (validate_key_file(pub_path, 0644) != 0) {
      UTILITIES_LOG_WARN("[蜜罐] 公钥文件缺失或无效，正在重新生成");
    } else {
      UTILITIES_LOG_INFO("[蜜罐] SSH 密钥对验证通过");
      return 0;
    }
  }

  UTILITIES_LOG_INFO("[蜜罐] 正在生成 SSH 主机密钥: %s", key_path);

  unlink(key_path);
  char pub_path[512];
  snprintf(pub_path, sizeof(pub_path), "%s.pub", key_path);
  unlink(pub_path);

  char cmd[512];
  snprintf(
      cmd, sizeof(cmd),
      "ssh-keygen -t rsa -b 2048 -f \"%s\" -N \"\" -q -C \"honeydew@蜜罐\"",
      key_path);

  int ret = system(cmd);
  if (ret != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] SSH 主机密钥生成失败 (返回码=%d)", ret);
    return -1;
  }

  if (chmod(key_path, 0600) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 无法设置私钥权限: %s", strerror(errno));
    return -1;
  }
  if (chmod(pub_path, 0644) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 无法设置公钥权限: %s", strerror(errno));
    return -1;
  }

  UTILITIES_LOG_INFO("[蜜罐] SSH 主机密钥生成成功: %s (私钥=0600, 公钥=0644)",
                     key_path);

  if (validate_key_file(key_path, 0600) != 0 ||
      validate_key_file(pub_path, 0644) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 生成的密钥验证失败");
    return -1;
  }

  UTILITIES_LOG_INFO("[蜜罐] SSH 密钥对验证通过");
  return 0;
}

static void signal_handler(int sig) {
  (void)sig;
  g_running = 0;
  UTILITIES_LOG_INFO("[蜜罐] 收到停止信号，正在优雅关闭...");
}

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
  char ip[INET6_ADDRSTRLEN];

  if (a->client_addr.sin_family == AF_INET6) {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&a->client_addr;
    inet_ntop(AF_INET6, &addr6->sin6_addr, ip, sizeof(ip));
  } else {
    inet_ntop(AF_INET, &a->client_addr.sin_addr, ip, sizeof(ip));
  }
  uint16_t port = ntohs(a->client_addr.sin_port);

  connection_t *conn = connection_create(fd, ip, port, a->binding->proto, 0);
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

  int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
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

  int ipv6_only = 0;
  setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only));

  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  addr.sin6_port = htons(binding->port);

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

  UTILITIES_LOG_INFO("[蜜罐] 端口 %d 已启动监听 (IPv4/IPv6)", binding->port);

  while (g_running) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in6);
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

  if (ensure_ssh_host_key(cfg.ssh_host_key_path) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 无法生成 SSH 主机密钥，SSH 蜜罐将无法正常工作");
    return 1;
  }

  if (audit_init(&g_audit) != 0) {
    UTILITIES_LOG_ERROR("[蜜罐] 审计系统初始化失败");
    return 1;
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

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
  audit_shutdown(&g_audit);

  UTILITIES_LOG_INFO("[蜜罐] %s v%s 已优雅关闭", UTILITIES_APP_NAME,
                     UTILITIES_VERSION);

  return 0;
}
