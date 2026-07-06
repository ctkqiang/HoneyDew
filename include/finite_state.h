#pragma once

#ifndef FSM_H
#define FSM_H

#include "connection.h"

#define HTTP_STATE_BANNER 0
#define HTTP_STATE_WAIT_CMD 1
#define HTTP_STATE_PROCESS 2
#define HTTP_STATE_CLOSE 3

#define SSH_STATE_BANNER 0
#define SSH_STATE_WAIT_AUTH 1
#define SSH_STATE_AUTH_FAIL 2
#define SSH_STATE_CLOSE 3

unsigned char *handle_http(connection_t *conn, const unsigned char *input,
                           size_t input_len, size_t *out_len);

unsigned char *handle_ssh(connection_t *conn, const unsigned char *input,
                          size_t input_len, size_t *out_len);

#endif
