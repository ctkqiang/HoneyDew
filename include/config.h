#pragma once

#ifndef CONFIG_H
#define CONFIG_H

#define SSH_KEY_DIR "keys"
#define SSH_HOST_KEY_PATH SSH_KEY_DIR "/ssh_host_rsa_key"
#define SSH_HOST_KEY_PUB_PATH SSH_HOST_KEY_PATH ".pub"

typedef struct {
  const char *log_file;
  const char *ssh_host_key_path;
  int max_connections;
  int listen_port;
} config_t;

static inline config_t get_default_config(void) {
  config_t c = {"蜜罐.log", SSH_HOST_KEY_PATH, 100, 9090};
  return c;
}

#endif
