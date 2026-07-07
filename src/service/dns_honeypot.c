/**
 * 版权所有 (c) 2026 钟智强
 * 保留所有权利。
 *
 * DNS 蜜罐服务 (TCP)
 * 监听 TCP DNS 查询，解析域名，检测区域传送 (AXFR) 攻击。
 * 对普通查询返回伪造 A 记录 (10.0.2.15) 或 SERVFAIL。
 */

#include "../../include/audit.h"
#include "../../include/config.h"
#include "../../include/connection.h"
#include "../../include/logger.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DNS_RECV_BUFFER_SIZE 4096
#define DNS_HEADER_SIZE 12
#define DNS_QTYPE_A 1
#define DNS_QTYPE_AXFR 252
#define DNS_RCODE_SERVFAIL 2
#define DNS_FAKE_IP_A 10
#define DNS_FAKE_IP_B 0
#define DNS_FAKE_IP_C 2
#define DNS_FAKE_IP_D 15

static void dns_generate_session_id(char *buf, size_t len, int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  snprintf(buf, len, "dns_%d_%ld_%ld", fd, ts.tv_sec, ts.tv_nsec);
}

static int dns_parse_domain_name(const unsigned char *msg, size_t msg_len,
                                 size_t offset, char *domain, size_t dsize) {
  size_t pos = offset;
  size_t dpos = 0;
  int labels = 0;

  while (pos < msg_len) {
    uint8_t label_len = msg[pos];

    if (label_len == 0) {
      pos++;
      break;
    }

    if ((label_len & 0xC0) == 0xC0) {
      pos += 2;
      break;
    }

    pos++;
    if (pos + label_len > msg_len)
      return -1;

    if (labels > 0 && dpos < dsize - 1)
      domain[dpos++] = '.';

    for (uint8_t i = 0; i < label_len && dpos < dsize - 1; i++)
      domain[dpos++] = (char)msg[pos + i];

    pos += label_len;
    labels++;

    if (labels > 128)
      return -1;
  }

  domain[dpos] = '\0';
  return (int)(pos - offset);
}

static uint16_t dns_parse_qtype(const unsigned char *msg, size_t msg_len,
                                size_t qname_end) {
  if (qname_end + 2 > msg_len)
    return 0;
  return ((uint16_t)msg[qname_end] << 8) | (uint16_t)msg[qname_end + 1];
}

static size_t dns_build_servfail(const unsigned char *query, size_t qlen,
                                 unsigned char *resp, size_t rsize) {
  if (qlen < DNS_HEADER_SIZE || rsize < qlen)
    return 0;

  memcpy(resp, query, qlen);

  resp[2] = 0x81;
  resp[3] = (resp[3] & 0xF0) | DNS_RCODE_SERVFAIL;

  resp[6] = 0x00;
  resp[7] = 0x00;
  resp[8] = 0x00;
  resp[9] = 0x00;
  resp[10] = 0x00;
  resp[11] = 0x00;

  return qlen;
}

static size_t dns_build_fake_a_response(const unsigned char *query, size_t qlen,
                                        size_t qname_end, unsigned char *resp,
                                        size_t rsize) {
  size_t question_end = qname_end + 4;
  size_t answer_size = 2 + 2 + 2 + 4 + 2 + 4;
  size_t total = question_end + answer_size;

  if (qlen < DNS_HEADER_SIZE || rsize < total)
    return dns_build_servfail(query, qlen, resp, rsize);

  memcpy(resp, query, question_end);

  resp[2] = 0x81;
  resp[3] = 0x80;

  resp[6] = 0x00;
  resp[7] = 0x01;
  resp[8] = 0x00;
  resp[9] = 0x00;
  resp[10] = 0x00;
  resp[11] = 0x00;

  size_t pos = question_end;

  resp[pos++] = 0xC0;
  resp[pos++] = 0x0C;

  resp[pos++] = 0x00;
  resp[pos++] = 0x01;

  resp[pos++] = 0x00;
  resp[pos++] = 0x01;

  uint32_t ttl = htonl(300);
  memcpy(resp + pos, &ttl, 4);
  pos += 4;

  resp[pos++] = 0x00;
  resp[pos++] = 0x04;

  resp[pos++] = DNS_FAKE_IP_A;
  resp[pos++] = DNS_FAKE_IP_B;
  resp[pos++] = DNS_FAKE_IP_C;
  resp[pos++] = DNS_FAKE_IP_D;

  return pos;
}

void run_dns_service(connection_t *conn) {
  char session_id[AUDIT_MAX_SESSION_ID_LEN];
  dns_generate_session_id(session_id, sizeof(session_id),
                          conn->socket_file_descriptor);

  UTILITIES_LOG_INFO("[DNS蜜罐] 新连接建立: %s:%d (套接字=%d)", conn->remote_ip,
                     conn->remote_port, conn->socket_file_descriptor);

  audit_record_connection(&g_audit, DNS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);

  unsigned char raw[DNS_RECV_BUFFER_SIZE];
  ssize_t n = recv(conn->socket_file_descriptor, raw, sizeof(raw), 0);

  if (n <= 0) {
    UTILITIES_LOG_WARN("[DNS蜜罐] 未收到数据: %s:%d", conn->remote_ip,
                       conn->remote_port);
    goto dns_cleanup;
  }

  const unsigned char *dns_msg = raw;
  size_t dns_len = (size_t)n;
  int tcp_framed = 0;

  if (n >= 2) {
    uint16_t tcp_len = ((uint16_t)raw[0] << 8) | (uint16_t)raw[1];
    if (tcp_len > 0 && tcp_len <= (uint16_t)(n - 2) &&
        (size_t)(tcp_len + 2) >= DNS_HEADER_SIZE + 2) {
      dns_msg = raw + 2;
      dns_len = tcp_len;
      tcp_framed = 1;
    }
  }

  if (dns_len < DNS_HEADER_SIZE) {
    UTILITIES_LOG_WARN("[DNS蜜罐] DNS 消息过短 (%zu 字节): %s:%d", dns_len,
                       conn->remote_ip, conn->remote_port);
    goto dns_cleanup;
  }

  uint16_t qdcount = ((uint16_t)dns_msg[4] << 8) | (uint16_t)dns_msg[5];

  UTILITIES_LOG_DEBUG("[DNS蜜罐] DNS 头部: ID=0x%02x%02x QD=%u 来自 %s:%d",
                      dns_msg[0], dns_msg[1], qdcount, conn->remote_ip,
                      conn->remote_port);

  char domain[512] = {0};
  size_t qname_offset = DNS_HEADER_SIZE;
  int parsed = dns_parse_domain_name(dns_msg, dns_len, qname_offset, domain,
                                     sizeof(domain));

  if (parsed <= 0) {
    UTILITIES_LOG_WARN("[DNS蜜罐] 域名解析失败: %s:%d", conn->remote_ip,
                       conn->remote_port);

    unsigned char servfail[DNS_RECV_BUFFER_SIZE];
    size_t rlen =
        dns_build_servfail(dns_msg, dns_len, servfail, sizeof(servfail));
    if (rlen > 0) {
      if (tcp_framed) {
        uint16_t tcp_rlen = htons((uint16_t)rlen);
        send(conn->socket_file_descriptor, &tcp_rlen, 2, 0);
      }
      send(conn->socket_file_descriptor, servfail, rlen, 0);
    }
    goto dns_cleanup;
  }

  size_t qname_end = qname_offset + (size_t)parsed;
  uint16_t qtype = dns_parse_qtype(dns_msg, dns_len, qname_end);

  audit_record_command(&g_audit, DNS_PROTOCOL, conn->remote_ip,
                       conn->remote_port, session_id, domain);

  if (qtype == DNS_QTYPE_AXFR) {
    UTILITIES_LOG_ERROR(
        "[DNS蜜罐] 检测到区域传送 (AXFR) 攻击: 域名=\"%s\" 来自 %s:%d", domain,
        conn->remote_ip, conn->remote_port);

    audit_record_event(&g_audit, AUDIT_EVENT_EXPLOIT_ATTEMPT,
                       AUDIT_SEVERITY_CRITICAL, DNS_PROTOCOL, conn->remote_ip,
                       conn->remote_port, session_id, "",
                       "AXFR zone transfer attempt: %s", domain);

    unsigned char servfail[DNS_RECV_BUFFER_SIZE];
    size_t rlen =
        dns_build_servfail(dns_msg, dns_len, servfail, sizeof(servfail));
    if (rlen > 0) {
      servfail[3] = (servfail[3] & 0xF0) | 0x05;

      if (tcp_framed) {
        uint16_t tcp_rlen = htons((uint16_t)rlen);
        send(conn->socket_file_descriptor, &tcp_rlen, 2, 0);
      }
      send(conn->socket_file_descriptor, servfail, rlen, 0);
    }
  } else {
    UTILITIES_LOG_WARN("[DNS蜜罐] 查询域名: \"%s\" (类型=%u) 来自 %s:%d",
                       domain, qtype, conn->remote_ip, conn->remote_port);

    unsigned char resp_buf[DNS_RECV_BUFFER_SIZE];
    size_t rlen;

    if (qtype == DNS_QTYPE_A) {
      rlen = dns_build_fake_a_response(dns_msg, dns_len, qname_end, resp_buf,
                                       sizeof(resp_buf));
      UTILITIES_LOG_INFO("[DNS蜜罐] 返回伪造 A 记录 10.0.2.15: \"%s\" -> %s:%d",
                         domain, conn->remote_ip, conn->remote_port);
    } else {
      rlen = dns_build_servfail(dns_msg, dns_len, resp_buf, sizeof(resp_buf));
      UTILITIES_LOG_INFO("[DNS蜜罐] 返回 SERVFAIL: \"%s\" (类型=%u) -> %s:%d",
                         domain, qtype, conn->remote_ip, conn->remote_port);
    }

    if (rlen > 0) {
      if (tcp_framed) {
        uint16_t tcp_rlen = htons((uint16_t)rlen);
        send(conn->socket_file_descriptor, &tcp_rlen, 2, 0);
      }
      send(conn->socket_file_descriptor, resp_buf, rlen, 0);
    }
  }

dns_cleanup:
  UTILITIES_LOG_INFO("[DNS蜜罐] 会话结束: %s:%d", conn->remote_ip,
                     conn->remote_port);

  audit_record_disconnect(&g_audit, DNS_PROTOCOL, conn->remote_ip,
                          conn->remote_port, session_id);
  close(conn->socket_file_descriptor);
}
