#pragma once

#ifndef CONNECTION_H
#define CONNECTION_H

#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <time.h>

#include "session.h"
#include "state.h"

typedef struct connection {
  int socket_file_descriptor;
  char remote_ip[INET6_ADDRSTRLEN];
  uint16_t remote_port;
  protocol_type protocol;
  state_condition state;
  time_t last_activity;
  unsigned char *tcp_reassembly_buffer;
  size_t buffer_length;
  size_t buffer_capacity;
  pthread_mutex_t mutex;
} connection_t;

#endif
