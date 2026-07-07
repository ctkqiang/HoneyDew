#pragma once

#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "connection.h"
#include "logger.h"

typedef void (*service_handler_t)(connection_t *conn);

typedef struct {
  int port;
  protocol_type proto;
  service_handler_t handler;
} service_binding_t;

extern service_binding_t service_map[];

void run_http_service(connection_t *conn);
void run_ssh_service(connection_t *conn);
void run_ftp_service(connection_t *conn);
void run_telnet_service(connection_t *conn);
void run_smtp_service(connection_t *conn);
void run_mysql_service(connection_t *conn);
void run_redis_service(connection_t *conn);
void run_postgresql_service(connection_t *conn);
void run_pop3_service(connection_t *conn);
void run_imap_service(connection_t *conn);
void run_dns_service(connection_t *conn);
void run_questdb_service(connection_t *conn);

#endif
