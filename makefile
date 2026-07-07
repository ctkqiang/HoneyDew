CC      := gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -pthread
LDFLAGS := -pthread

HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
LIBSSH_CFLAGS  := -I$(HOMEBREW_PREFIX)/include
LIBSSH_LIBS    := -L$(HOMEBREW_PREFIX)/lib -lssh

CFLAGS  += $(LIBSSH_CFLAGS)
LDFLAGS += $(LIBSSH_LIBS)

TARGET  := 蜜罐

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

.PHONY: all build run clean

all: build

build: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
	rm -f *.log
	rm -rf *.dSYM
