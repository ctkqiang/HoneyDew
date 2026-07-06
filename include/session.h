#pragma once

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifndef SESSION_H
#define SESSION_H

#define SESSION_TABLE_SIZE 0x0100

typedef enum {
  UNKNOWN_PROTOCOL,
  HTTP_PROTOCOL,
  HTTPS_PROTOCOL,
  FTP_PROTOCOL,
  FTPS_PROTOCOL,
  SSH_PROTOCOL,
  TELNET_PROTOCOL,
  SMTP_PROTOCOL,
  POP3_PROTOCOL,
  IMAP_PROTOCOL,
  DNS_PROTOCOL,
  MYSQL_PROTOCOL,
  POSTGRESQL_PROTOCOL,
  REDIS_PROTOCOL,
  QUESTDB_PROTOCOL,
} protocol_type;

struct connection;

typedef struct session_node {
  struct connection *connection;
  struct session_node *next;
} session_node_t;

typedef struct {
  session_node_t *session_bucket[SESSION_TABLE_SIZE];
  pthread_mutex_t lock;
} session_table_t;

session_table_t *session_table_create(void);

void session_table_destroy(session_table_t *table);

void session_table_add(session_table_t *table, struct connection *conn);

struct connection *session_table_get(session_table_t *table, int sockfd);

void session_table_remove(session_table_t *table, int sockfd);

struct connection *connection_create(int sockfd, const char *ip, uint16_t port,
                                     protocol_type proto, int initial_state);

void connection_destroy(struct connection *conn);

void connection_append_data(struct connection *conn, const unsigned char *data,
                            size_t len);

void connection_consume_buffer(struct connection *conn, size_t n);

#endif
