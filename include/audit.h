#pragma once

#ifndef AUDIT_H
#define AUDIT_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AUDIT_MAX_IP_LEN 46
#define AUDIT_MAX_USER_LEN 128
#define AUDIT_MAX_DETAIL_LEN 2048
#define AUDIT_MAX_SESSION_ID_LEN 64
#define AUDIT_LOG_DIR "audit_logs"
#define AUDIT_RING_BUFFER_SIZE 4096

typedef enum {
  AUDIT_EVENT_CONNECTION,
  AUDIT_EVENT_DISCONNECTION,
  AUDIT_EVENT_AUTH_ATTEMPT,
  AUDIT_EVENT_AUTH_SUCCESS,
  AUDIT_EVENT_AUTH_FAILURE,
  AUDIT_EVENT_COMMAND,
  AUDIT_EVENT_FILE_ACCESS,
  AUDIT_EVENT_FILE_MODIFY,
  AUDIT_EVENT_DATA_EXFIL,
  AUDIT_EVENT_SCAN_PROBE,
  AUDIT_EVENT_EXPLOIT_ATTEMPT,
  AUDIT_EVENT_PROTOCOL_ERROR,
} audit_event_type;

typedef enum {
  AUDIT_SEVERITY_LOW,
  AUDIT_SEVERITY_MEDIUM,
  AUDIT_SEVERITY_HIGH,
  AUDIT_SEVERITY_CRITICAL,
} audit_severity;

typedef struct {
  time_t timestamp;
  uint64_t sequence_number;
  audit_event_type event_type;
  audit_severity severity;
  int protocol;
  int source_port;
  char source_ip[AUDIT_MAX_IP_LEN];
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  char username[AUDIT_MAX_USER_LEN];
  char details[AUDIT_MAX_DETAIL_LEN];
  size_t raw_data_len;
} audit_record_t;

typedef struct {
  audit_record_t *ring_buffer;
  size_t capacity;
  size_t head;
  size_t count;
  uint64_t next_sequence;
  pthread_mutex_t mutex;
  pthread_cond_t flush_cond;
  pthread_t flush_thread;
  FILE *current_log_file;
  char current_log_path[512];
  int running;
  size_t total_records;
  size_t dropped_records;
} audit_trail_t;

int audit_init(audit_trail_t *trail);
void audit_shutdown(audit_trail_t *trail);

void audit_record_event(audit_trail_t *trail, audit_event_type type,
                        audit_severity severity, int protocol,
                        const char *source_ip, int source_port,
                        const char *session_id, const char *username,
                        const char *details_fmt, ...);

void audit_record_connection(audit_trail_t *trail, int protocol, const char *ip,
                             int port, const char *session_id);

void audit_record_auth(audit_trail_t *trail, int protocol, const char *ip,
                       int port, const char *session_id, const char *username,
                       const char *password, int success);

void audit_record_command(audit_trail_t *trail, int protocol, const char *ip,
                          int port, const char *session_id,
                          const char *command);

void audit_record_disconnect(audit_trail_t *trail, int protocol, const char *ip,
                             int port, const char *session_id);

extern audit_trail_t g_audit;

#ifdef __cplusplus
}
#endif

#endif
