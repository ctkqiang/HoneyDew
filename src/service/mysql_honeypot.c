#include "../../include/audit.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <stdlib.h>
#define getrandom(buf, len, flags) (arc4random_buf(buf, len), (len))
#define GRND_RANDOM 0
#endif

#define MYSQL_HONEYPOT_SERVER_VERSION "5.7.42-0ubuntu0.18.04.1"
#define MYSQL_HONEYPOT_AUTH_PLUGIN "mysql_native_password"
#define MYSQL_HONEYPOT_CHARSET_UTF8 0x21
#define MYSQL_HONEYPOT_PROTOCOL_VER 10
#define MYSQL_HONEYPOT_ERR_CODE 1045
#define MYSQL_HONEYPOT_RECV_BUF_SIZE 4096
#define MYSQL_HONEYPOT_GREETING_SIZE 512

static void mysql_generate_salt(unsigned char *buf, size_t len) {
  static const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "0123456789";

  unsigned char rand_bytes[32];
  if (getrandom(rand_bytes, sizeof(rand_bytes), GRND_RANDOM) ==
      sizeof(rand_bytes)) {
    for (size_t i = 0; i < len; i++) {
      buf[i] = (unsigned char)
          charset[rand_bytes[i % sizeof(rand_bytes)] % (sizeof(charset) - 1)];
    }
  } else {
    for (size_t i = 0; i < len; i++) {
      buf[i] = (unsigned char)charset[rand() % (sizeof(charset) - 1)];
    }
  }
}

static void mysql_write_le16(unsigned char *buf, uint16_t val) {
  buf[0] = (unsigned char)(val & 0xFF);
  buf[1] = (unsigned char)((val >> 8) & 0xFF);
}

static void mysql_write_le24(unsigned char *buf, uint32_t val) {
  buf[0] = (unsigned char)(val & 0xFF);
  buf[1] = (unsigned char)((val >> 8) & 0xFF);
  buf[2] = (unsigned char)((val >> 16) & 0xFF);
}

static void mysql_write_le32(unsigned char *buf, uint32_t val) {
  buf[0] = (unsigned char)(val & 0xFF);
  buf[1] = (unsigned char)((val >> 8) & 0xFF);
  buf[2] = (unsigned char)((val >> 16) & 0xFF);
  buf[3] = (unsigned char)((val >> 24) & 0xFF);
}

static size_t mysql_build_greeting_packet(unsigned char *buf, size_t buf_size,
                                          uint32_t conn_id) {
  unsigned char salt_part1[8];
  unsigned char salt_part2[12];
  mysql_generate_salt(salt_part1, sizeof(salt_part1));
  mysql_generate_salt(salt_part2, sizeof(salt_part2));

  const char *version = MYSQL_HONEYPOT_SERVER_VERSION;
  size_t version_len = strlen(version);
  const char *auth_plugin = MYSQL_HONEYPOT_AUTH_PLUGIN;
  size_t auth_plugin_len = strlen(auth_plugin);

  /* 能力标志位：CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS |
     CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 |
     CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH */
  uint32_t capabilities = 0x0000F7DF;
  uint16_t cap_lower = (uint16_t)(capabilities & 0xFFFF);
  uint16_t cap_upper = (uint16_t)((capabilities >> 16) & 0xFFFF);
  uint16_t status_flags = 0x0002; /* 服务器状态：自动提交 */
  uint8_t auth_data_len = 21;     /* 8 + 13（12 + 尾部 NUL） */

  unsigned char payload[MYSQL_HONEYPOT_GREETING_SIZE];
  size_t pos = 0;

  payload[pos++] = MYSQL_HONEYPOT_PROTOCOL_VER;

  memcpy(payload + pos, version, version_len);
  pos += version_len;
  payload[pos++] = 0x00;

  mysql_write_le32(payload + pos, conn_id);
  pos += 4;

  memcpy(payload + pos, salt_part1, 8);
  pos += 8;

  payload[pos++] = 0x00;

  mysql_write_le16(payload + pos, cap_lower);
  pos += 2;

  payload[pos++] = MYSQL_HONEYPOT_CHARSET_UTF8;

  mysql_write_le16(payload + pos, status_flags);
  pos += 2;

  mysql_write_le16(payload + pos, cap_upper);
  pos += 2;

  payload[pos++] = auth_data_len;

  memset(payload + pos, 0, 10);
  pos += 10;

  memcpy(payload + pos, salt_part2, 12);
  pos += 12;

  payload[pos++] = 0x00;

  memcpy(payload + pos, auth_plugin, auth_plugin_len);
  pos += auth_plugin_len;
  payload[pos++] = 0x00;

  if (pos + 4 > buf_size) {
    return 0;
  }

  mysql_write_le24(buf, (uint32_t)pos);
  buf[3] = 0x00; /* 序列号 = 0 */
  memcpy(buf + 4, payload, pos);

  return pos + 4;
}

static size_t mysql_build_error_packet(unsigned char *buf, size_t buf_size,
                                       uint8_t seq_id, const char *username,
                                       const char *remote_ip) {
  char message[256];
  snprintf(message, sizeof(message),
           "Access denied for user '%s'@'%s' (using password: YES)", username,
           remote_ip);
  size_t msg_len = strlen(message);

  /* 载荷：0xFF + 错误码(2) + '#' + SQL状态码(5) + 消息 */
  size_t payload_len = 1 + 2 + 1 + 5 + msg_len;

  if (payload_len + 4 > buf_size) {
    return 0;
  }

  mysql_write_le24(buf, (uint32_t)payload_len);
  buf[3] = seq_id;

  size_t pos = 4;
  buf[pos++] = 0xFF;

  mysql_write_le16(buf + pos, MYSQL_HONEYPOT_ERR_CODE);
  pos += 2;

  buf[pos++] = '#';

  memcpy(buf + pos, "28000", 5);
  pos += 5;

  memcpy(buf + pos, message, msg_len);
  pos += msg_len;

  return pos;
}

static const char *mysql_extract_username(const unsigned char *pkt,
                                          size_t pkt_len) {
  /*
   * MySQL HandshakeResponse41 载荷布局（4 字节头部之后）：
   *   4 字节  能力标志位
   *   4 字节  最大数据包大小
   *   1 字节  字符集
   *  23 字节  保留字段（全零）
   *   以 NUL 结尾的用户名字符串
   *
   * 用户名的最小偏移量 = 4 + 4 + 1 + 23 = 载荷中的第 32 字节。
   * 加上 4 字节数据包头部，即原始数据包中的偏移量为 36。
   */
  static const size_t USERNAME_OFFSET = 36;

  if (pkt_len <= USERNAME_OFFSET) {
    return NULL;
  }

  const char *start = (const char *)(pkt + USERNAME_OFFSET);
  size_t remaining = pkt_len - USERNAME_OFFSET;

  if (memchr(start, '\0', remaining) == NULL) {
    return NULL;
  }

  return start;
}

static void mysql_extract_and_log_query(const unsigned char *pkt,
                                        size_t pkt_len, const char *remote_ip,
                                        uint16_t remote_port,
                                        const char *session_id) {
  /*
   * MySQL COM_QUERY 数据包：
   *   3 字节  载荷长度
   *   1 字节  序列号
   *   1 字节  命令类型（0x03 = COM_QUERY）
   *   其余    查询字符串（非 NUL 结尾）
   */
  if (pkt_len < 5) {
    return;
  }

  uint8_t cmd = pkt[4];
  if (cmd == 0x03 && pkt_len > 5) {
    size_t query_len = pkt_len - 5;
    if (query_len > 1024) {
      query_len = 1024;
    }
    char query[1025];
    memcpy(query, pkt + 5, query_len);
    query[query_len] = '\0';

    UTILITIES_LOG_WARN("[MySQL蜜罐] 捕获SQL查询: \"%s\" 来自 %s:%d", query,
                       remote_ip, remote_port);

    audit_record_command(&g_audit, MYSQL_PROTOCOL, remote_ip, remote_port,
                         session_id, query);
  } else {
    UTILITIES_LOG_WARN("[MySQL蜜罐] 捕获命令类型: 0x%02X 来自 %s:%d", cmd,
                       remote_ip, remote_port);
  }
}

void run_mysql_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  audit_generate_session_id(session_id, sizeof(session_id));

  UTILITIES_LOG_INFO("[MySQL蜜罐] 新连接建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, MYSQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  srand((unsigned int)(time(NULL) ^ conn->socket_file_descriptor));

  static uint32_t connection_counter = 0;
  uint32_t conn_id;

  pthread_mutex_lock(&conn->mutex);
  conn_id = ++connection_counter;
  pthread_mutex_unlock(&conn->mutex);

  int fd = conn->socket_file_descriptor;

  /* 1. 发送 MySQL 握手问候包 */
  unsigned char greeting[MYSQL_HONEYPOT_GREETING_SIZE];
  size_t greeting_len =
      mysql_build_greeting_packet(greeting, sizeof(greeting), conn_id);
  if (greeting_len == 0) {
    UTILITIES_LOG_ERROR("[MySQL蜜罐] 构建握手包失败: %s:%d", conn->remote_ip,
                        conn->remote_port);
    close(fd);
    return;
  }

  ssize_t sent = send(fd, greeting, greeting_len, 0);
  if (sent <= 0) {
    UTILITIES_LOG_ERROR("[MySQL蜜罐] 发送握手包失败: %s:%d (errno=%d)",
                        conn->remote_ip, conn->remote_port, errno);
    close(fd);
    return;
  }

  UTILITIES_LOG_DEBUG("[MySQL蜜罐] 握手包已发送 (%zd 字节): %s:%d", sent,
                      conn->remote_ip, conn->remote_port);

  /* 2. 接收客户端认证响应 */
  unsigned char recv_buf[MYSQL_HONEYPOT_RECV_BUF_SIZE];
  ssize_t received = recv(fd, recv_buf, sizeof(recv_buf), 0);

  if (received <= 0) {
    UTILITIES_LOG_INFO("[MySQL蜜罐] 客户端未响应或断开: %s:%d", conn->remote_ip,
                       conn->remote_port);
    close(fd);
    return;
  }

  UTILITIES_LOG_DEBUG("[MySQL蜜罐] 收到认证数据 (%zd 字节): %s:%d", received,
                      conn->remote_ip, conn->remote_port);

  const char *username = mysql_extract_username(recv_buf, (size_t)received);
  if (!username || username[0] == '\0') {
    username = "(unknown)";
  }

  UTILITIES_LOG_WARN("[MySQL蜜罐] 捕获登录尝试: 用户=\"%s\" 来自 %s:%d",
                     username, conn->remote_ip, conn->remote_port);

  audit_record_auth(&g_audit, MYSQL_PROTOCOL, conn->remote_ip,
                    conn->remote_port, session_id, username, "", 0);

  /* 3. 回复 Access Denied 错误包 */
  unsigned char err_pkt[512];
  size_t err_len = mysql_build_error_packet(err_pkt, sizeof(err_pkt), 2,
                                            username, conn->remote_ip);
  if (err_len > 0) {
    send(fd, err_pkt, err_len, 0);
    UTILITIES_LOG_DEBUG("[MySQL蜜罐] 已发送拒绝访问响应: %s:%d",
                        conn->remote_ip, conn->remote_port);
  }

  /* 4. 继续监听后续数据, 捕获可能的SQL查询 */
  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  for (;;) {
    received = recv(fd, recv_buf, sizeof(recv_buf), 0);
    if (received <= 0) {
      break;
    }

    UTILITIES_LOG_WARN("[MySQL蜜罐] 错误响应后仍收到数据 (%zd 字节): %s:%d",
                       received, conn->remote_ip, conn->remote_port);

    mysql_extract_and_log_query(recv_buf, (size_t)received, conn->remote_ip,
                                conn->remote_port, session_id);

    /* 对后续请求也回复错误 */
    uint8_t seq = recv_buf[3];
    err_len =
        mysql_build_error_packet(err_pkt, sizeof(err_pkt), (uint8_t)(seq + 1),
                                 username, conn->remote_ip);
    if (err_len > 0) {
      send(fd, err_pkt, err_len, 0);
    }
  }

  close(fd);

  audit_record_disconnect(&g_audit, MYSQL_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  UTILITIES_LOG_INFO("[MySQL蜜罐] 会话已关闭: %s:%d", conn->remote_ip,
                     conn->remote_port);
}
