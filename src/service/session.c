#include "../../include/session.h"
#include "../../include/connection.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned int hash_int(int key) {
  return (unsigned int)key % SESSION_TABLE_SIZE;
}

session_table_t *session_table_create(void) {
  session_table_t *t = calloc(1, sizeof(*t));
  pthread_mutex_init(&t->lock, NULL);
  return t;
}

void session_table_destroy(session_table_t *table) {
  pthread_mutex_lock(&table->lock);
  for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
    session_node_t *node = table->session_bucket[i];
    while (node) {
      session_node_t *next = node->next;
      connection_destroy(node->connection);
      free(node);
      node = next;
    }
  }
  pthread_mutex_unlock(&table->lock);
  pthread_mutex_destroy(&table->lock);
  free(table);
}

void session_table_add(session_table_t *table, connection_t *conn) {
  unsigned int idx = hash_int(conn->socket_file_descriptor);
  pthread_mutex_lock(&table->lock);
  session_node_t *node = malloc(sizeof(*node));
  node->connection = conn;
  node->next = table->session_bucket[idx];
  table->session_bucket[idx] = node;
  pthread_mutex_unlock(&table->lock);
}

connection_t *session_table_get(session_table_t *table, int sockfd) {
  unsigned int idx = hash_int(sockfd);
  pthread_mutex_lock(&table->lock);
  session_node_t *curr = table->session_bucket[idx];
  while (curr) {
    if (curr->connection->socket_file_descriptor == sockfd) {
      pthread_mutex_unlock(&table->lock);
      return curr->connection;
    }
    curr = curr->next;
  }
  pthread_mutex_unlock(&table->lock);
  return NULL;
}

void session_table_remove(session_table_t *table, int sockfd) {
  unsigned int idx = hash_int(sockfd);
  pthread_mutex_lock(&table->lock);
  session_node_t **prev = &table->session_bucket[idx];
  session_node_t *curr = table->session_bucket[idx];
  while (curr) {
    if (curr->connection->socket_file_descriptor == sockfd) {
      *prev = curr->next;
      connection_destroy(curr->connection);
      free(curr);
      break;
    }
    prev = &curr->next;
    curr = curr->next;
  }
  pthread_mutex_unlock(&table->lock);
}

connection_t *connection_create(int sockfd, const char *ip, uint16_t port,
                                protocol_type proto, int initial_state) {
  connection_t *conn = calloc(1, sizeof(*conn));
  conn->socket_file_descriptor = sockfd;
  strncpy(conn->remote_ip, ip, sizeof(conn->remote_ip) - 1);
  conn->remote_port = port;
  conn->protocol = proto;
  conn->state = (state_condition)initial_state;
  conn->last_activity = time(NULL);
  conn->tcp_reassembly_buffer = NULL;
  conn->buffer_length = 0;
  conn->buffer_capacity = 0;
  pthread_mutex_init(&conn->mutex, NULL);
  return conn;
}

void connection_destroy(connection_t *conn) {
  pthread_mutex_destroy(&conn->mutex);
  free(conn->tcp_reassembly_buffer);
  free(conn);
}

void connection_append_data(connection_t *conn, const unsigned char *data,
                            size_t len) {
  pthread_mutex_lock(&conn->mutex);
  if (conn->buffer_length + len > conn->buffer_capacity) {
    size_t new_cap = conn->buffer_capacity ? conn->buffer_capacity * 2 : 4096;
    while (conn->buffer_length + len > new_cap)
      new_cap *= 2;
    unsigned char *new_buf = realloc(conn->tcp_reassembly_buffer, new_cap);
    if (!new_buf) {
      pthread_mutex_unlock(&conn->mutex);
      return;
    }
    conn->tcp_reassembly_buffer = new_buf;
    conn->buffer_capacity = new_cap;
  }
  memcpy(conn->tcp_reassembly_buffer + conn->buffer_length, data, len);
  conn->buffer_length += len;
  pthread_mutex_unlock(&conn->mutex);
}

void connection_consume_buffer(connection_t *conn, size_t n) {
  pthread_mutex_lock(&conn->mutex);
  if (n >= conn->buffer_length) {
    conn->buffer_length = 0;
  } else {
    memmove(conn->tcp_reassembly_buffer, conn->tcp_reassembly_buffer + n,
            conn->buffer_length - n);
    conn->buffer_length -= n;
  }
  pthread_mutex_unlock(&conn->mutex);
}
