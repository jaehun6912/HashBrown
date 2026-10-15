CC = gcc
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
LDLIBS ?= -lcrypto
COMMON = eddsa.c aes.c x25519.c

.PHONY: all clean
all: build/server build/client

build:
	mkdir -p $@

build/server: server.c $(COMMON) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/client: client.c $(COMMON) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f build/server build/client
