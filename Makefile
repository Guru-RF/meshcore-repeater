# MeshCore repeater (plain C) - Raspberry Pi + NiceRF LoRa1268F30-433 (SX1268)
#
#   make            build the daemon (Linux/RPi; needs libgpiod-dev)
#   make test       build + run the host self-test (no hardware needed)
#   make install    install binary + systemd unit (run as root)
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CPPFLAGS += -D_GNU_SOURCE -Isrc
PREFIX  ?= /usr/local

LDLIBS_DAEMON = -lgpiod -lm
LDLIBS_TEST   = -lm

CORE = \
  src/packet.c src/util.c src/identity.c src/advert.c src/mesh.c \
  src/sx126x.c src/config.c src/log.c \
  src/crypto/tweetnacl.c src/crypto/sha256.c src/crypto/randombytes.c

DAEMON_SRC = $(CORE) src/cli.c src/hal_linux.c src/main.c
TEST_SRC   = $(CORE) tools/mock_hal.c tools/selftest.c

BIN = meshcore-repeater

all: $(BIN)

$(BIN): $(DAEMON_SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DAEMON_SRC) $(LDLIBS_DAEMON)

selftest: $(TEST_SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_SRC) $(LDLIBS_TEST)

test: selftest
	./selftest

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -Dm644 meshcore-repeater.conf $(DESTDIR)/etc/meshcore-repeater.conf
	install -Dm644 meshcore-repeater.service $(DESTDIR)/etc/systemd/system/meshcore-repeater.service
	@echo "edit /etc/meshcore-repeater.conf, then: systemctl enable --now meshcore-repeater"

clean:
	rm -f $(BIN) selftest

.PHONY: all test install clean
