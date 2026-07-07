#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/dispatcher.h"
#include "../../include/logger.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SSH_HONEYPOT_MAX_AUTH_ATTEMPTS 3
#define SSH_HONEYPOT_SHELL_PROMPT "root@honeydew:~# "
#define SSH_HONEYPOT_MOTD                                                      \
  "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"     \
  "\r\n"                                                                       \
  " * Documentation:  https://help.ubuntu.com\r\n"                             \
  " * Management:     https://landscape.canonical.com\r\n"                     \
  " * Support:        https://ubuntu.com/pro\r\n"                              \
  "\r\n"                                                                       \
  "System information as of Sun Jul  6 14:23:01 UTC 2026\r\n"                  \
  "\r\n"                                                                       \
  "  System load:  0.08       Processes:           142\r\n"                    \
  "  Usage of /:   34.2%      Users logged in:     1\r\n"                      \
  "  Memory usage: 62%        IPv4 address for eth0: 10.0.2.15\r\n"            \
  "  Swap usage:   0%\r\n"                                                     \
  "\r\n"                                                                       \
  "Last login: Sun Jul  6 12:45:33 2026 from 203.0.113.42\r\n"

static const char *fake_command_response(const char *cmd) {
  if (strstr(cmd, "whoami"))
    return "root\r\n";
  if (strstr(cmd, "id"))
    return "uid=0(root) gid=0(root) groups=0(root)\r\n";
  if (strstr(cmd, "uname"))
    return "Linux honeydew 5.15.0-91-generic #101-Ubuntu SMP x86_64\r\n";
  if (strstr(cmd, "pwd"))
    return "/root\r\n";
  if (strstr(cmd, "ls"))
    return "Desktop  Documents  Downloads  .bash_history  .ssh\r\n";
  if (strstr(cmd, "cat /etc/passwd"))
    return "root:x:0:0:root:/root:/bin/bash\r\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n";
  if (strstr(cmd, "cat /etc/shadow"))
    return "cat: /etc/shadow: Permission denied\r\n";
  if (strstr(cmd, "ifconfig") || strstr(cmd, "ip addr"))
    return "eth0: inet 10.0.2.15/24 brd 10.0.2.255\r\n"
           "lo: inet 127.0.0.1/8\r\n";
  if (strstr(cmd, "ps"))
    return "  PID TTY          TIME CMD\r\n"
           "    1 ?        00:00:01 systemd\r\n"
           "  512 ?        00:00:00 sshd\r\n"
           " 1024 pts/0    00:00:00 bash\r\n";
  if (strstr(cmd, "exit") || strstr(cmd, "logout"))
    return NULL;
  return "bash: command not found\r\n";
}

void run_ssh_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  audit_generate_session_id(session_id, sizeof(session_id));

  UTILITIES_LOG_INFO("[SSH蜜罐] 新会话建立: %s:%d (套接字=%d)", conn->remote_ip,
                     conn->remote_port, conn->socket_file_descriptor);

  audit_record_connection(&g_audit, SSH_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  ssh_session session = ssh_new();
  if (!session) {
    UTILITIES_LOG_ERROR("[SSH蜜罐] 无法创建 SSH 会话");
    close(conn->socket_file_descriptor);
    return;
  }

  ssh_set_blocking(session, 1);

  int fd = conn->socket_file_descriptor;
  ssh_options_set(session, SSH_OPTIONS_FD, &fd);

  ssh_bind sshbind = ssh_bind_new();
  if (!sshbind) {
    UTILITIES_LOG_ERROR("[SSH蜜罐] 无法创建 SSH bind");
    ssh_free(session);
    close(conn->socket_file_descriptor);
    return;
  }

  config_t cfg = get_default_config();
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, cfg.ssh_host_key_path);

  if (ssh_bind_accept_fd(sshbind, session, fd) != SSH_OK) {
    UTILITIES_LOG_ERROR("[SSH蜜罐] ssh_bind_accept_fd 失败: %s",
                        ssh_get_error(sshbind));
    ssh_bind_free(sshbind);
    ssh_free(session);
    close(conn->socket_file_descriptor);
    return;
  }

  if (ssh_handle_key_exchange(session) != SSH_OK) {
    UTILITIES_LOG_ERROR("[SSH蜜罐] 密钥交换失败: %s", ssh_get_error(session));
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_free(session);
    return;
  }

  UTILITIES_LOG_INFO("[SSH蜜罐] 密钥交换成功: %s:%d", conn->remote_ip,
                     conn->remote_port);

  ssh_message msg;
  int authenticated = 0;
  int auth_attempts = 0;

  while (!authenticated && auth_attempts < SSH_HONEYPOT_MAX_AUTH_ATTEMPTS) {
    msg = ssh_message_get(session);
    if (!msg)
      break;

    if (ssh_message_type(msg) == SSH_REQUEST_AUTH) {
      if (ssh_message_subtype(msg) == SSH_AUTH_METHOD_PASSWORD) {
        const char *user = ssh_message_auth_user(msg);
        const char *pass = ssh_message_auth_password(msg);

        UTILITIES_LOG_WARN(
            "[SSH蜜罐] 捕获凭据: 用户=\"%s\" 密码=\"%s\" 来自 %s:%d",
            user ? user : "(空)", pass ? pass : "(空)", conn->remote_ip,
            conn->remote_port);

        auth_attempts++;

        int success = (auth_attempts >= SSH_HONEYPOT_MAX_AUTH_ATTEMPTS) ? 1 : 0;
        audit_record_auth(&g_audit, SSH_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id,
                          user ? user : "", pass ? pass : "", success);

        if (success) {
          ssh_message_auth_reply_success(msg, 0);
          authenticated = 1;
        } else {
          ssh_message_reply_default(msg);
        }
      } else if (ssh_message_subtype(msg) == SSH_AUTH_METHOD_NONE) {
        ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PASSWORD);
        ssh_message_reply_default(msg);
      } else {
        ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PASSWORD);
        ssh_message_reply_default(msg);
      }
    } else {
      ssh_message_reply_default(msg);
    }
    ssh_message_free(msg);
  }

  if (!authenticated) {
    UTILITIES_LOG_INFO("[SSH蜜罐] 认证超时或断开: %s:%d", conn->remote_ip,
                       conn->remote_port);
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_free(session);
    return;
  }

  UTILITIES_LOG_WARN("[SSH蜜罐] 攻击者已\"登录\": %s:%d", conn->remote_ip,
                     conn->remote_port);

  ssh_channel channel = NULL;
  int shell_requested = 0;

  while (!channel || !shell_requested) {
    msg = ssh_message_get(session);
    if (!msg)
      break;

    if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
        ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
      channel = ssh_message_channel_request_open_reply_accept(msg);
    } else if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
               channel != NULL) {
      int subtype = ssh_message_subtype(msg);
      if (subtype == SSH_CHANNEL_REQUEST_PTY) {
        ssh_message_channel_request_reply_success(msg);
      } else if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
        ssh_message_channel_request_reply_success(msg);
        shell_requested = 1;
      } else if (subtype == SSH_CHANNEL_REQUEST_ENV) {
        ssh_message_channel_request_reply_success(msg);
      } else {
        ssh_message_reply_default(msg);
      }
    } else {
      ssh_message_reply_default(msg);
    }
    ssh_message_free(msg);
  }

  if (!channel || !shell_requested) {
    UTILITIES_LOG_INFO("[SSH蜜罐] 通道建立失败: %s:%d", conn->remote_ip,
                       conn->remote_port);
    if (channel)
      ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_free(session);
    return;
  }

  ssh_channel_write(channel, SSH_HONEYPOT_MOTD, strlen(SSH_HONEYPOT_MOTD));
  ssh_channel_write(channel, SSH_HONEYPOT_SHELL_PROMPT,
                    strlen(SSH_HONEYPOT_SHELL_PROMPT));

  char cmd_buf[1024];
  size_t cmd_len = 0;

  while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
    char buf[256];
    int nbytes = ssh_channel_read(channel, buf, sizeof(buf) - 1, 0);
    if (nbytes <= 0)
      break;

    for (int i = 0; i < nbytes; i++) {
      char c = buf[i];

      if (c == '\r' || c == '\n') {
        ssh_channel_write(channel, "\r\n", 2);
        cmd_buf[cmd_len] = '\0';

        if (cmd_len > 0) {
          UTILITIES_LOG_WARN("[SSH蜜罐] 执行命令: \"%s\" 来自 %s:%d", cmd_buf,
                             conn->remote_ip, conn->remote_port);

          audit_record_command(&g_audit, SSH_PROTOCOL, conn->remote_ip,
                              conn->remote_port, session_id, cmd_buf);

          const char *response = fake_command_response(cmd_buf);
          if (!response) {
            UTILITIES_LOG_INFO("[SSH蜜罐] 攻击者退出 shell: %s:%d",
                               conn->remote_ip, conn->remote_port);
            goto session_end;
          }
          ssh_channel_write(channel, response, strlen(response));
        }

        ssh_channel_write(channel, SSH_HONEYPOT_SHELL_PROMPT,
                          strlen(SSH_HONEYPOT_SHELL_PROMPT));
        cmd_len = 0;
      } else if (c == 127 || c == '\b') {
        if (cmd_len > 0) {
          cmd_len--;
          ssh_channel_write(channel, "\b \b", 3);
        }
      } else if (c == 3) {
        ssh_channel_write(channel, "^C\r\n", 4);
        ssh_channel_write(channel, SSH_HONEYPOT_SHELL_PROMPT,
                          strlen(SSH_HONEYPOT_SHELL_PROMPT));
        cmd_len = 0;
      } else if (cmd_len < sizeof(cmd_buf) - 1) {
        cmd_buf[cmd_len++] = c;
        ssh_channel_write(channel, &c, 1);
      }
    }
  }

session_end:
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  ssh_disconnect(session);
  ssh_bind_free(sshbind);
  ssh_free(session);

  audit_record_disconnect(&g_audit, SSH_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  UTILITIES_LOG_INFO("[SSH蜜罐] 会话已关闭: %s:%d", conn->remote_ip,
                     conn->remote_port);
}
