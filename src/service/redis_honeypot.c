/**
 * Copyright (c) 2025 zhongtianqiang
 *
 * Redis 蜜罐服务 - 模拟 Redis 6.2.6 无认证实例
 *
 * 模拟常见的 Redis 错误配置场景：未设置密码保护。
 * 支持 RESP 协议数组格式和内联命令两种解析方式。
 * 记录所有攻击者命令，重点监控 CONFIG SET、SLAVEOF、EVAL 等高危操作。
 */

#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REDIS_RECV_BUFFER_SIZE 4096
#define REDIS_MAX_ARGS 32
#define REDIS_MAX_ARG_LEN 1024
#define REDIS_RESP_BUFFER_SIZE 8192

/* ========================================================================== */
/* 辅助函数 */
/* ========================================================================== */

static void redis_generate_session_id(char *buf, size_t len) {
  audit_generate_session_id(buf, len);
}

static void redis_str_toupper(char *dst, const char *src, size_t max_len) {
  size_t i;
  for (i = 0; i < max_len - 1 && src[i] != '\0'; i++)
    dst[i] = (char)toupper((unsigned char)src[i]);
  dst[i] = '\0';
}

static ssize_t redis_send(int fd, const char *data, size_t len) {
  return send(fd, data, len, 0);
}

static ssize_t redis_send_str(int fd, const char *str) {
  return redis_send(fd, str, strlen(str));
}

static ssize_t redis_send_bulk_string(int fd, const char *str) {
  char header[64];
  size_t len = strlen(str);
  snprintf(header, sizeof(header), "$%zu\r\n", len);
  redis_send_str(fd, header);
  redis_send(fd, str, len);
  return redis_send_str(fd, "\r\n");
}

/* ========================================================================== */
/* RESP 协议解析器 */
/* ========================================================================== */

typedef struct {
  int argc;
  char argv[REDIS_MAX_ARGS][REDIS_MAX_ARG_LEN];
} redis_command_t;

/**
 * 解析 RESP 数组格式: *N\r\n$len\r\n...\r\n
 * 返回消耗的字节数，失败返回 0
 */
static size_t redis_parse_resp_array(const char *buf, size_t buf_len,
                                     redis_command_t *cmd) {
  cmd->argc = 0;

  if (buf_len < 4 || buf[0] != '*')
    return 0;

  const char *p = buf + 1;
  const char *end = buf + buf_len;
  const char *crlf = strstr(p, "\r\n");
  if (!crlf || crlf >= end)
    return 0;

  int argc = atoi(p);
  if (argc <= 0 || argc > REDIS_MAX_ARGS)
    return 0;

  p = crlf + 2;

  for (int i = 0; i < argc; i++) {
    if (p >= end || *p != '$')
      return 0;

    crlf = strstr(p + 1, "\r\n");
    if (!crlf || crlf >= end)
      return 0;

    int arg_len = atoi(p + 1);
    if (arg_len < 0)
      return 0;

    p = crlf + 2;
    if (p + arg_len + 2 > end)
      return 0;

    size_t copy_len = (size_t)arg_len < REDIS_MAX_ARG_LEN - 1
                          ? (size_t)arg_len
                          : REDIS_MAX_ARG_LEN - 1;
    memcpy(cmd->argv[i], p, copy_len);
    cmd->argv[i][copy_len] = '\0';

    p += arg_len;
    if (p + 2 > end || p[0] != '\r' || p[1] != '\n')
      return 0;
    p += 2;
  }

  cmd->argc = argc;
  return (size_t)(p - buf);
}

/**
 * 解析内联命令格式: COMMAND arg1 arg2...\r\n
 * 返回消耗的字节数，失败返回 0
 */
static size_t redis_parse_inline(const char *buf, size_t buf_len,
                                 redis_command_t *cmd) {
  cmd->argc = 0;

  const char *crlf = strstr(buf, "\r\n");
  if (!crlf)
    crlf = strstr(buf, "\n");
  if (!crlf) {
    if (buf_len > 0 && buf[buf_len - 1] != '\0')
      crlf = buf + buf_len;
    else
      return 0;
  }

  size_t line_len = (size_t)(crlf - buf);
  if (line_len == 0)
    return (size_t)(crlf - buf) + (crlf[0] == '\r' ? 2 : 1);

  char line[REDIS_RECV_BUFFER_SIZE];
  if (line_len >= sizeof(line))
    line_len = sizeof(line) - 1;
  memcpy(line, buf, line_len);
  line[line_len] = '\0';

  char *saveptr = NULL;
  char *token = strtok_r(line, " \t", &saveptr);
  while (token && cmd->argc < REDIS_MAX_ARGS) {
    size_t tlen = strlen(token);
    if (tlen >= REDIS_MAX_ARG_LEN)
      tlen = REDIS_MAX_ARG_LEN - 1;
    memcpy(cmd->argv[cmd->argc], token, tlen);
    cmd->argv[cmd->argc][tlen] = '\0';
    cmd->argc++;
    token = strtok_r(NULL, " \t", &saveptr);
  }

  size_t consumed = (size_t)(crlf - buf);
  if (crlf < buf + buf_len) {
    consumed += (crlf[0] == '\r' && crlf + 1 < buf + buf_len && crlf[1] == '\n')
                    ? 2
                    : 1;
  }
  return consumed;
}

/* ========================================================================== */
/* Redis 命令响应 */
/* ========================================================================== */

static const char *REDIS_FAKE_INFO =
    "# Server\r\n"
    "redis_version:6.2.6\r\n"
    "redis_git_sha1:00000000\r\n"
    "redis_git_dirty:0\r\n"
    "redis_build_id:a3fdef44459b3ad6\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 5.15.0-91-generic x86_64\r\n"
    "arch_bits:64\r\n"
    "multiplexing_api:epoll\r\n"
    "gcc_version:11.4.0\r\n"
    "process_id:1\r\n"
    "tcp_port:6379\r\n"
    "uptime_in_seconds:864213\r\n"
    "uptime_in_days:10\r\n"
    "hz:10\r\n"
    "configured_hz:10\r\n"
    "lru_clock:14523871\r\n"
    "executable:/usr/local/bin/redis-server\r\n"
    "config_file:/etc/redis/redis.conf\r\n"
    "\r\n"
    "# Clients\r\n"
    "connected_clients:3\r\n"
    "cluster_connections:0\r\n"
    "maxclients:10000\r\n"
    "blocked_clients:0\r\n"
    "\r\n"
    "# Memory\r\n"
    "used_memory:2097152\r\n"
    "used_memory_human:2.00M\r\n"
    "used_memory_rss:4194304\r\n"
    "used_memory_rss_human:4.00M\r\n"
    "used_memory_peak:3145728\r\n"
    "used_memory_peak_human:3.00M\r\n"
    "total_system_memory:8589934592\r\n"
    "total_system_memory_human:8.00G\r\n"
    "maxmemory:0\r\n"
    "maxmemory_human:0B\r\n"
    "maxmemory_policy:noeviction\r\n"
    "\r\n"
    "# Keyspace\r\n"
    "db0:keys=47,expires=12,avg_ttl=86400000\r\n";

static const char *REDIS_FAKE_CONFIG =
    "*20\r\n"
    "$10\r\nbind\r\n$7\r\n0.0.0.0\r\n"
    "$4\r\nport\r\n$4\r\n6379\r\n"
    "$9\r\ntimeout\r\n$1\r\n0\r\n"
    "$3\r\ndir\r\n$8\r\n/var/lib\r\n"
    "$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n"
    "$12\r\nrequirepass\r\n$0\r\n\r\n"
    "$10\r\nmaxclients\r\n$5\r\n10000\r\n"
    "$9\r\nmaxmemory\r\n$1\r\n0\r\n"
    "$16\r\nmaxmemory-policy\r\n$10\r\nnoeviction\r\n"
    "$9\r\nloglevel\r\n$6\r\nnotice\r\n";

static const char *REDIS_FAKE_KEYS = "*4\r\n"
                                     "$14\r\nsession:abc123\r\n"
                                     "$11\r\nusers:admin\r\n"
                                     "$18\r\ntokens:refresh_key\r\n"
                                     "$20\r\napi_keys:production\r\n";

static void redis_handle_info(int fd) {
  char resp[REDIS_RESP_BUFFER_SIZE];
  size_t info_len = strlen(REDIS_FAKE_INFO);
  snprintf(resp, sizeof(resp), "$%zu\r\n%s\r\n", info_len, REDIS_FAKE_INFO);
  redis_send_str(fd, resp);
}

static void redis_handle_config_get(int fd, const redis_command_t *cmd,
                                    const char *remote_ip, int remote_port) {
  if (cmd->argc >= 3) {
    UTILITIES_LOG_WARN("[Redis蜜罐] CONFIG GET 请求: 模式=\"%s\" 来自 %s:%d",
                       cmd->argv[2], remote_ip, remote_port);
  }
  redis_send_str(fd, REDIS_FAKE_CONFIG);
}

static void redis_handle_config_set(int fd, const redis_command_t *cmd,
                                    const char *remote_ip, int remote_port) {
  if (cmd->argc >= 4) {
    UTILITIES_LOG_WARN(
        "[Redis蜜罐] CONFIG SET 攻击检测: 键=\"%s\" 值=\"%s\" 来自 %s:%d",
        cmd->argv[2], cmd->argv[3], remote_ip, remote_port);
  } else if (cmd->argc >= 3) {
    UTILITIES_LOG_WARN("[Redis蜜罐] CONFIG SET 攻击检测: 键=\"%s\" 来自 %s:%d",
                       cmd->argv[2], remote_ip, remote_port);
  }
  redis_send_str(fd, "+OK\r\n");
}

/* ========================================================================== */
/* 主命令分发 */
/* ========================================================================== */

/**
 * 处理单条 Redis 命令，返回 0 表示继续，返回 1 表示关闭连接
 */
static int redis_dispatch_command(int fd, const redis_command_t *cmd,
                                  const char *remote_ip, int remote_port,
                                  const char *session_id) {
  if (cmd->argc <= 0)
    return 0;

  char upper_cmd[REDIS_MAX_ARG_LEN];
  redis_str_toupper(upper_cmd, cmd->argv[0], sizeof(upper_cmd));

  /* 构建完整命令字符串用于日志和审计 */
  char full_cmd[REDIS_RECV_BUFFER_SIZE];
  size_t offset = 0;
  for (int i = 0; i < cmd->argc && offset < sizeof(full_cmd) - 1; i++) {
    if (i > 0)
      full_cmd[offset++] = ' ';
    size_t remaining = sizeof(full_cmd) - 1 - offset;
    size_t arg_len = strlen(cmd->argv[i]);
    size_t copy = arg_len < remaining ? arg_len : remaining;
    memcpy(full_cmd + offset, cmd->argv[i], copy);
    offset += copy;
  }
  full_cmd[offset] = '\0';

  UTILITIES_LOG_WARN("[Redis蜜罐] 收到命令: \"%s\" 来自 %s:%d", full_cmd,
                     remote_ip, remote_port);

  audit_record_command(&g_audit, REDIS_PROTOCOL, remote_ip, remote_port,
                       session_id, full_cmd);

  /* PING */
  if (strcmp(upper_cmd, "PING") == 0) {
    if (cmd->argc >= 2)
      redis_send_bulk_string(fd, cmd->argv[1]);
    else
      redis_send_str(fd, "+PONG\r\n");
    return 0;
  }

  /* INFO */
  if (strcmp(upper_cmd, "INFO") == 0) {
    redis_handle_info(fd);
    return 0;
  }

  /* CONFIG */
  if (strcmp(upper_cmd, "CONFIG") == 0) {
    if (cmd->argc >= 2) {
      char sub[REDIS_MAX_ARG_LEN];
      redis_str_toupper(sub, cmd->argv[1], sizeof(sub));

      if (strcmp(sub, "GET") == 0) {
        redis_handle_config_get(fd, cmd, remote_ip, remote_port);
      } else if (strcmp(sub, "SET") == 0) {
        redis_handle_config_set(fd, cmd, remote_ip, remote_port);
      } else if (strcmp(sub, "RESETSTAT") == 0) {
        redis_send_str(fd, "+OK\r\n");
      } else if (strcmp(sub, "REWRITE") == 0) {
        redis_send_str(fd, "+OK\r\n");
      } else {
        redis_send_str(
            fd, "-ERR Unknown subcommand or wrong number of arguments\r\n");
      }
    } else {
      redis_send_str(fd,
                     "-ERR wrong number of arguments for 'config' command\r\n");
    }
    return 0;
  }

  /* SET */
  if (strcmp(upper_cmd, "SET") == 0) {
    if (cmd->argc >= 3) {
      UTILITIES_LOG_WARN("[Redis蜜罐] SET 操作: 键=\"%s\" 值=\"%s\" 来自 %s:%d",
                         cmd->argv[1], cmd->argv[2], remote_ip, remote_port);
    } else if (cmd->argc >= 2) {
      UTILITIES_LOG_WARN("[Redis蜜罐] SET 操作: 键=\"%s\" 来自 %s:%d",
                         cmd->argv[1], remote_ip, remote_port);
    }
    redis_send_str(fd, "+OK\r\n");
    return 0;
  }

  /* GET */
  if (strcmp(upper_cmd, "GET") == 0) {
    redis_send_str(fd, "$-1\r\n");
    return 0;
  }

  /* KEYS */
  if (strcmp(upper_cmd, "KEYS") == 0) {
    if (cmd->argc >= 2) {
      UTILITIES_LOG_WARN("[Redis蜜罐] KEYS 扫描: 模式=\"%s\" 来自 %s:%d",
                         cmd->argv[1], remote_ip, remote_port);
    }
    redis_send_str(fd, REDIS_FAKE_KEYS);
    return 0;
  }

  /* AUTH */
  if (strcmp(upper_cmd, "AUTH") == 0) {
    if (cmd->argc >= 2) {
      UTILITIES_LOG_WARN("[Redis蜜罐] AUTH 尝试: 密码=\"%s\" 来自 %s:%d",
                         cmd->argv[1], remote_ip, remote_port);
      audit_record_auth(&g_audit, REDIS_PROTOCOL, remote_ip, remote_port,
                        session_id, "", cmd->argv[1], 0);
    }
    redis_send_str(fd, "-ERR Client sent AUTH, but no password is set. "
                       "Did you mean ACL SETUSER with >password?\r\n");
    return 0;
  }

  /* SLAVEOF / REPLICAOF */
  if (strcmp(upper_cmd, "SLAVEOF") == 0 ||
      strcmp(upper_cmd, "REPLICAOF") == 0) {
    if (cmd->argc >= 3) {
      UTILITIES_LOG_WARN("[Redis蜜罐] 主从复制攻击检测: %s %s %s 来自 %s:%d",
                         upper_cmd, cmd->argv[1], cmd->argv[2], remote_ip,
                         remote_port);
    } else {
      UTILITIES_LOG_WARN("[Redis蜜罐] 主从复制攻击检测: %s 来自 %s:%d",
                         upper_cmd, remote_ip, remote_port);
    }
    redis_send_str(fd, "+OK\r\n");
    return 0;
  }

  /* EVAL (Lua 脚本执行) */
  if (strcmp(upper_cmd, "EVAL") == 0 || strcmp(upper_cmd, "EVALSHA") == 0) {
    if (cmd->argc >= 2) {
      UTILITIES_LOG_WARN(
          "[Redis蜜罐] Lua 脚本执行尝试: 脚本=\"%.256s\" 来自 %s:%d",
          cmd->argv[1], remote_ip, remote_port);
    }
    redis_send_str(fd, "-NOSCRIPT No matching script. "
                       "Please use EVAL.\r\n");
    return 0;
  }

  /* FLUSHALL / FLUSHDB */
  if (strcmp(upper_cmd, "FLUSHALL") == 0 || strcmp(upper_cmd, "FLUSHDB") == 0) {
    UTILITIES_LOG_WARN("[Redis蜜罐] 破坏性命令: %s 来自 %s:%d", upper_cmd,
                       remote_ip, remote_port);
    redis_send_str(fd, "+OK\r\n");
    return 0;
  }

  /* DEL / UNLINK */
  if (strcmp(upper_cmd, "DEL") == 0 || strcmp(upper_cmd, "UNLINK") == 0) {
    if (cmd->argc >= 2) {
      UTILITIES_LOG_WARN("[Redis蜜罐] 删除键: \"%s\" 来自 %s:%d", cmd->argv[1],
                         remote_ip, remote_port);
    }
    redis_send_str(fd, ":0\r\n");
    return 0;
  }

  /* EXISTS */
  if (strcmp(upper_cmd, "EXISTS") == 0) {
    redis_send_str(fd, ":0\r\n");
    return 0;
  }

  /* TTL / PTTL */
  if (strcmp(upper_cmd, "TTL") == 0 || strcmp(upper_cmd, "PTTL") == 0) {
    redis_send_str(fd, ":-2\r\n");
    return 0;
  }

  /* TYPE */
  if (strcmp(upper_cmd, "TYPE") == 0) {
    redis_send_str(fd, "+none\r\n");
    return 0;
  }

  /* DBSIZE */
  if (strcmp(upper_cmd, "DBSIZE") == 0) {
    redis_send_str(fd, ":47\r\n");
    return 0;
  }

  /* SELECT */
  if (strcmp(upper_cmd, "SELECT") == 0) {
    redis_send_str(fd, "+OK\r\n");
    return 0;
  }

  /* COMMAND */
  if (strcmp(upper_cmd, "COMMAND") == 0) {
    redis_send_str(fd, "*0\r\n");
    return 0;
  }

  /* CLIENT */
  if (strcmp(upper_cmd, "CLIENT") == 0) {
    if (cmd->argc >= 2) {
      char sub[REDIS_MAX_ARG_LEN];
      redis_str_toupper(sub, cmd->argv[1], sizeof(sub));
      if (strcmp(sub, "SETNAME") == 0) {
        redis_send_str(fd, "+OK\r\n");
        return 0;
      }
      if (strcmp(sub, "GETNAME") == 0) {
        redis_send_str(fd, "$-1\r\n");
        return 0;
      }
      if (strcmp(sub, "LIST") == 0) {
        const char *client_info = "id=3 addr=127.0.0.1:6379 fd=8 name= db=0 "
                                  "cmd=client\r\n";
        redis_send_bulk_string(fd, client_info);
        return 0;
      }
    }
    redis_send_str(fd, "+OK\r\n");
    return 0;
  }

  /* ECHO */
  if (strcmp(upper_cmd, "ECHO") == 0) {
    if (cmd->argc >= 2)
      redis_send_bulk_string(fd, cmd->argv[1]);
    else
      redis_send_str(fd,
                     "-ERR wrong number of arguments for 'echo' command\r\n");
    return 0;
  }

  /* SAVE / BGSAVE / BGREWRITEAOF */
  if (strcmp(upper_cmd, "SAVE") == 0 || strcmp(upper_cmd, "BGSAVE") == 0 ||
      strcmp(upper_cmd, "BGREWRITEAOF") == 0) {
    UTILITIES_LOG_WARN("[Redis蜜罐] 持久化命令: %s 来自 %s:%d", upper_cmd,
                       remote_ip, remote_port);
    redis_send_str(fd, "+OK\r\n");
    return 0;
  }

  /* SHUTDOWN */
  if (strcmp(upper_cmd, "SHUTDOWN") == 0) {
    UTILITIES_LOG_WARN("[Redis蜜罐] 关闭服务器尝试: SHUTDOWN 来自 %s:%d",
                       remote_ip, remote_port);
    redis_send_str(fd, "+OK\r\n");
    return 1;
  }

  /* MODULE LOAD */
  if (strcmp(upper_cmd, "MODULE") == 0) {
    if (cmd->argc >= 3) {
      UTILITIES_LOG_WARN(
          "[Redis蜜罐] 模块加载攻击检测: MODULE %s %s 来自 %s:%d", cmd->argv[1],
          cmd->argv[2], remote_ip, remote_port);
    }
    redis_send_str(
        fd, "-ERR Error loading shared library: No such file or directory\r\n");
    return 0;
  }

  /* DEBUG */
  if (strcmp(upper_cmd, "DEBUG") == 0) {
    UTILITIES_LOG_WARN("[Redis蜜罐] DEBUG 命令尝试 来自 %s:%d", remote_ip,
                       remote_port);
    redis_send_str(fd, "-ERR DEBUG command not allowed\r\n");
    return 0;
  }

  /* QUIT */
  if (strcmp(upper_cmd, "QUIT") == 0) {
    redis_send_str(fd, "+OK\r\n");
    return 1;
  }

  /* 未知命令 */
  char err_resp[512];
  snprintf(
      err_resp, sizeof(err_resp),
      "-ERR unknown command '%s', with args beginning with: ", cmd->argv[0]);

  for (int i = 1; i < cmd->argc && i <= 3; i++) {
    size_t cur_len = strlen(err_resp);
    snprintf(err_resp + cur_len, sizeof(err_resp) - cur_len, "'%s' ",
             cmd->argv[i]);
  }

  size_t resp_len = strlen(err_resp);
  if (resp_len + 2 < sizeof(err_resp)) {
    err_resp[resp_len] = '\r';
    err_resp[resp_len + 1] = '\n';
    err_resp[resp_len + 2] = '\0';
  }

  redis_send_str(fd, err_resp);
  return 0;
}

/* ========================================================================== */
/* Redis 蜜罐主入口 */
/* ========================================================================== */

void run_redis_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  redis_generate_session_id(session_id, sizeof(session_id));

  UTILITIES_LOG_INFO("[Redis蜜罐] 新连接建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, REDIS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  int fd = conn->socket_file_descriptor;
  char recv_buf[REDIS_RECV_BUFFER_SIZE];
  size_t buf_used = 0;
  int running = 1;

  while (running) {
    if (buf_used >= sizeof(recv_buf) - 1) {
      UTILITIES_LOG_WARN("[Redis蜜罐] 接收缓冲区溢出，重置: %s:%d",
                         conn->remote_ip, conn->remote_port);
      buf_used = 0;
    }

    ssize_t n =
        recv(fd, recv_buf + buf_used, sizeof(recv_buf) - 1 - buf_used, 0);
    if (n <= 0) {
      if (n < 0) {
        UTILITIES_LOG_DEBUG("[Redis蜜罐] 接收数据失败: %s:%d", conn->remote_ip,
                            conn->remote_port);
      }
      break;
    }

    buf_used += (size_t)n;
    recv_buf[buf_used] = '\0';

    /* 循环解析缓冲区中的所有完整命令 */
    while (buf_used > 0 && running) {
      redis_command_t cmd;
      memset(&cmd, 0, sizeof(cmd));
      size_t consumed = 0;

      if (recv_buf[0] == '*') {
        consumed = redis_parse_resp_array(recv_buf, buf_used, &cmd);
      }

      if (consumed == 0) {
        consumed = redis_parse_inline(recv_buf, buf_used, &cmd);
      }

      if (consumed == 0)
        break;

      if (cmd.argc > 0) {
        if (redis_dispatch_command(fd, &cmd, conn->remote_ip, conn->remote_port,
                                   session_id)) {
          running = 0;
        }
      }

      /* 移除已消耗的数据 */
      if (consumed < buf_used) {
        memmove(recv_buf, recv_buf + consumed, buf_used - consumed);
        buf_used -= consumed;
      } else {
        buf_used = 0;
      }
    }
  }

  UTILITIES_LOG_INFO("[Redis蜜罐] 会话已关闭: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, REDIS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
