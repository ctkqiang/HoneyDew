#pragma once

#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "logger.h"
#include "session.h"

typedef void (*service_handler_t)(connection_t *conn);

typedef struct {
  int port;
  service_handler_t handler;
} service_binding_t;

extern service_binding_t service_map[];

void run_http_service(connection_t *conn);

#endif
