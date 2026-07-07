/**
 * telnet_honeypot.c
 *
 * Telnet honeypot service simulating a Linux BusyBox telnet login.
 * Captures attacker credentials and shell commands for audit logging.
 */

#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/dispatcher.h"
#include "../../include/logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TELNET_RECV_BUFFER_SIZE 4096
#define TELNET_CMD_BUFFER_SIZE 1024
#define TELNET_MAX_AUTH_ATTEMPTS 2
#define TELNET_SHELL_PROMPT "root@honeydew:~# "

#define TELNET_BANNER                                                          \
  "\r\nUbuntu 22.04.3 LTS\r\nhoneydew login: "

#define TELNET_MOTD                                                            \
  "\r\n"                                                                       \
  "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"    \
  "\r\n"                                                                       \
  "\r\n"                                                                       \
  "BusyBox v1.35.0 (Ubuntu 1:1.35.0-4ubuntu1) built-in shell (ash)\r\n"       \
  "Enter 'help' for a list of built-in commands.\r\n"                          \
  "\r\n"

/* Telnet IAC sequences for echo control */
static const unsigned char iac_will_echo[] = {0xFF, 0xFB, 0x01};
static const unsigned char iac_wont_echo[] = {0xFF, 0xFC, 0x01};

/* ========================================================================== */
/* Internal helpers                                                           */
/* ========================================================================== */

static void telnet_generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "telnet_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static void telnet_strip_crlf(char *str) {
  size_t n = strlen(str);
  while (n > 0 && (str[n - 1] == '\r' || str[n - 1] == '\n'))
    str[--n] = '\0';
}

/**
 * Strip telnet IAC negotiation bytes from raw input.
 * IAC commands are 3-byte sequences starting with 0xFF.
 * Sub-negotiation (0xFF 0xFA ... 0xFF 0xF0) is also stripped.
 * Returns the number of clean bytes written to dst.
 */
static size_t telnet_strip_iac(const unsigned char *src, size_t src_len,
                               char *dst, size_t dst_cap) {
  size_t di = 0;
  size_t si = 0;

  while (si < src_len && di < dst_cap - 1) {
    if (src[si] == 0xFF && si + 1 < src_len) {
      unsigned char cmd = src[si + 1];

      if (cmd == 0xFA) {
        /* Sub-negotiation: skip until IAC SE (0xFF 0xF0) */
        si += 2;
        while (si < src_len) {
          if (src[si] == 0xFF && si + 1 < src_len && src[si + 1] == 0xF0) {
            si += 2;
            break;
          }
          si++;
        }
        continue;
      }

      if (cmd >= 0xFB && cmd <= 0xFE) {
        /* WILL / WONT / DO / DONT: 3-byte command */
        si += 3;
        continue;
      }

      if (cmd == 0xFF) {
        /* Escaped 0xFF literal */
        dst[di++] = (char)0xFF;
        si += 2;
        continue;
      }

      /* Other 2-byte IAC commands (e.g., IAC NOP, IAC GA) */
      si += 2;
      continue;
    }

    dst[di++] = (char)src[si++];
  }

  dst[di] = '\0';
  return di;
}

static ssize_t telnet_send(int fd, const void *data, size_t len) {
  return send(fd, data, len, 0);
}

static ssize_t telnet_send_str(int fd, const char *str) {
  return send(fd, str, strlen(str), 0);
}

/**
 * Read a line from the telnet client, stripping IAC bytes.
 * Returns the length of the clean line, or -1 on disconnect/error.
 */
static ssize_t telnet_read_line(int fd, char *out, size_t out_cap) {
  unsigned char raw[TELNET_RECV_BUFFER_SIZE];

  memset(raw, 0, sizeof(raw));
  ssize_t n = recv(fd, raw, sizeof(raw) - 1, 0);
  if (n <= 0)
    return -1;

  telnet_strip_iac(raw, (size_t)n, out, out_cap);
  telnet_strip_crlf(out);
  return (ssize_t)strlen(out);
}

/* ========================================================================== */
/* Fake command responses                                                     */
/* ========================================================================== */

static const char *telnet_fake_response(const char *cmd, const char *remote_ip,
                                        uint16_t remote_port) {
  if (strstr(cmd, "whoami"))
    return "root\r\n";

  if (strstr(cmd, "id"))
    return "uid=0(root) gid=0(root) groups=0(root)\r\n";

  if (strstr(cmd, "uname"))
    return "Linux honeydew 5.15.0-91-generic "
           "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 "
           "x86_64 x86_64 GNU/Linux\r\n";

  if (strstr(cmd, "pwd"))
    return "/root\r\n";

  if (strstr(cmd, "cat /etc/passwd"))
    return "root:x:0:0:root:/root:/bin/bash\r\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
           "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
           "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
           "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
           "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\r\n";

  if (strstr(cmd, "cat /etc/shadow"))
    return "cat: /etc/shadow: Permission denied\r\n";

  if (strstr(cmd, "ls"))
    return "Desktop  Documents  Downloads  .bash_history  .ssh\r\n";

  if (strstr(cmd, "ps"))
    return "  PID TTY          TIME CMD\r\n"
           "    1 ?        00:00:01 systemd\r\n"
           "  234 ?        00:00:00 telnetd\r\n"
           "  512 ?        00:00:00 sshd\r\n"
           "  789 ?        00:00:00 cron\r\n"
           " 1024 pts/0    00:00:00 bash\r\n"
           " 1337 pts/0    00:00:00 ps\r\n";

  if (strstr(cmd, "ifconfig") || strstr(cmd, "ip addr"))
    return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
           "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n"
           "        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64  scopeid 0x20<link>\r\n"
           "        ether 08:00:27:8d:c0:4d  txqueuelen 1000  (Ethernet)\r\n"
           "\r\n"
           "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
           "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
           "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\r\n";

  if (strstr(cmd, "wget") || strstr(cmd, "curl")) {
    /* Extract URL for logging */
    const char *url_start = strstr(cmd, "http");
    if (url_start) {
      UTILITIES_LOG_WARN(
          "[Telnet蜜罐] 检测到下载尝试: URL=\"%s\" 来自 %s:%d",
          url_start, remote_ip, remote_port);
    }
    if (strstr(cmd, "wget"))
      return "Connecting to remote host... Connection refused\r\n";
    return "curl: (7) Failed to connect to remote host: Connection refused\r\n";
  }

  if (strstr(cmd, "help"))
    return "Built-in commands:\r\n"
           "  cat cd cp echo exit help id ifconfig kill ls mkdir\r\n"
           "  mv ping ps pwd rm rmdir sh uname wget whoami\r\n";

  if (strstr(cmd, "cd"))
    return "";

  if (strstr(cmd, "hostname"))
    return "honeydew\r\n";

  if (strstr(cmd, "uptime"))
    return " 14:23:01 up 42 days,  3:17,  1 user,  load average: 0.08, 0.03, 0.01\r\n";

  if (strstr(cmd, "exit") || strstr(cmd, "logout"))
    return NULL;

  return "sh: command not found\r\n";
}

/* ========================================================================== */
/* Telnet honeypot entry point                                                */
/* ========================================================================== */

void run_telnet_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  telnet_generate_session_id(session_id, sizeof(session_id),
                             conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[Telnet蜜罐] 新会话建立: %s:%d (套接字=%d)",
                     conn->remote_ip, conn->remote_port,
                     conn->socket_file_descriptor);

  audit_record_connection(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  int fd = conn->socket_file_descriptor;
  char line_buf[TELNET_CMD_BUFFER_SIZE];
  int auth_attempts = 0;
  int authenticated = 0;

  /* ---- Authentication phase ---- */
  while (!authenticated && auth_attempts < TELNET_MAX_AUTH_ATTEMPTS) {
    /* Send login banner / prompt */
    if (auth_attempts == 0) {
      telnet_send_str(fd, TELNET_BANNER);
    } else {
      telnet_send_str(fd, "\r\nLogin incorrect\r\n");
      telnet_send_str(fd, "honeydew login: ");
    }

    /* Read username */
    ssize_t ulen = telnet_read_line(fd, line_buf, sizeof(line_buf));
    if (ulen < 0)
      goto session_end;

    char username[256];
    strncpy(username, line_buf, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';

    /* Send IAC WILL ECHO to suppress client-side echo for password */
    telnet_send(fd, iac_will_echo, sizeof(iac_will_echo));
    telnet_send_str(fd, "Password: ");

    /* Read password */
    ssize_t plen = telnet_read_line(fd, line_buf, sizeof(line_buf));

    /* Send IAC WONT ECHO to re-enable client echo */
    telnet_send(fd, iac_wont_echo, sizeof(iac_wont_echo));
    telnet_send_str(fd, "\r\n");

    if (plen < 0)
      goto session_end;

    char password[256];
    strncpy(password, line_buf, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    UTILITIES_LOG_WARN(
        "[Telnet蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d",
        username, password, conn->remote_ip, conn->remote_port);

    audit_record_auth(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                      conn->remote_port, session_id, username, password, 0);

    auth_attempts++;

    if (auth_attempts >= TELNET_MAX_AUTH_ATTEMPTS) {
      authenticated = 1;
    }
  }

  if (!authenticated) {
    UTILITIES_LOG_INFO("[Telnet蜜罐] 认证阶段断开: %s:%d",
                       conn->remote_ip, conn->remote_port);
    goto session_end;
  }

  UTILITIES_LOG_WARN("[Telnet蜜罐] 攻击者已\"登录\": %s:%d",
                     conn->remote_ip, conn->remote_port);

  /* ---- Post-login MOTD and shell loop ---- */
  telnet_send_str(fd, TELNET_MOTD);

  while (1) {
    telnet_send_str(fd, TELNET_SHELL_PROMPT);

    ssize_t clen = telnet_read_line(fd, line_buf, sizeof(line_buf));
    if (clen < 0)
      break;

    if (strlen(line_buf) == 0)
      continue;

    UTILITIES_LOG_WARN("[Telnet蜜罐] 执行命令: \"%s\" 来自 %s:%d",
                       line_buf, conn->remote_ip, conn->remote_port);

    audit_record_command(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                         conn->remote_port, session_id, line_buf);

    const char *response = telnet_fake_response(line_buf, conn->remote_ip,
                                                conn->remote_port);
    if (!response) {
      UTILITIES_LOG_INFO("[Telnet蜜罐] 攻击者退出 shell: %s:%d",
                         conn->remote_ip, conn->remote_port);
      break;
    }

    if (strlen(response) > 0) {
      telnet_send_str(fd, response);
    }
  }

session_end:
  UTILITIES_LOG_INFO("[Telnet蜜罐] 会话已关闭: %s:%d",
                     conn->remote_ip, conn->remote_port);

  audit_record_disconnect(&g_audit, TELNET_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
