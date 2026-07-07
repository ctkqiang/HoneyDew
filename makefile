CC      := gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -pthread
LDFLAGS := -pthread

HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
LIBSSH_CFLAGS  := -I$(HOMEBREW_PREFIX)/include
LIBSSH_LIBS    := -L$(HOMEBREW_PREFIX)/lib -lssh

CFLAGS  += $(LIBSSH_CFLAGS)
LDFLAGS += $(LIBSSH_LIBS)

TARGET   := 蜜罐
KEY_DIR  := keys
KEY_PRIV := $(KEY_DIR)/ssh_host_rsa_key
KEY_PUB  := $(KEY_PRIV).pub

SRCS := main.c \
        src/service/session.c \
        src/service/finite_state.c \
        src/service/dispatcher.c \
        src/service/ssh_honeypot.c \
        src/service/ftp_honeypot.c \
        src/service/telnet_honeypot.c \
        src/service/smtp_honeypot.c \
        src/service/mysql_honeypot.c \
        src/service/redis_honeypot.c \
        src/service/postgresql_honeypot.c \
        src/service/pop3_honeypot.c \
        src/service/imap_honeypot.c \
        src/service/dns_honeypot.c \
        src/service/questdb_honeypot.c \
        src/utilities/logger.c \
        src/utilities/audit.c

OBJS := $(SRCS:.c=.o)

.PHONY: all build run clean keys

all: build

$(KEY_PRIV):
	@mkdir -p $(KEY_DIR) && chmod 700 $(KEY_DIR)
	@echo "[密钥生成] 正在生成 RSA-2048 SSH 主机密钥..."
	@ssh-keygen -t rsa -b 2048 -f $(KEY_PRIV) -N "" -q -C "honeydew@蜜罐"
	@chmod 600 $(KEY_PRIV)
	@chmod 644 $(KEY_PUB)
	@echo "[密钥生成] 私钥: $(KEY_PRIV) (权限=0600)"
	@echo "[密钥生成] 公钥: $(KEY_PUB) (权限=0644)"
	@echo "[密钥验证] 正在验证密钥格式..."
	@head -1 $(KEY_PRIV) | grep -q "BEGIN" && echo "[密钥验证] 私钥格式正确 (PEM)" || (echo "[密钥验证] 私钥格式无效"; exit 1)
	@test -s $(KEY_PUB) && echo "[密钥验证] 公钥文件有效" || (echo "[密钥验证] 公钥文件为空"; exit 1)
	@echo "[密钥生成] SSH 密钥对生成并验证完毕"

keys: $(KEY_PRIV)

build: $(KEY_PRIV) $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(KEY_PRIV) $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
	rm -f *.log
	rm -rf *.dSYM
	rm -rf $(KEY_DIR)
	@echo "[清理] 已删除密钥目录: $(KEY_DIR)/"
