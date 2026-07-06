#pragma once

#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
  const char *log_file;
  int max_connections;
  int listen_port;
} config_t;

static inline config_t get_default_config(void) {
  config_t c = {"蜜罐.log", 100, 9090};
  return c;
}

#endif
