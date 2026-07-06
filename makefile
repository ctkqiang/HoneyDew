CC      := gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -pthread
LDFLAGS := -pthread

LIBSSH_CFLAGS := $(shell pkg-config --cflags libssh 2>/dev/null)
LIBSSH_LIBS   := $(shell pkg-config --libs libssh 2>/dev/null)

CFLAGS  += $(LIBSSH_CFLAGS)
LDFLAGS += $(LIBSSH_LIBS)

TARGET  := 蜜罐

SRCS := main.c \
        src/service/session.c \
        src/service/finite_state.c \
        src/service/dispatcher.c \
        src/service/ssh_honeypot.c \
        src/utilities/logger.c

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
