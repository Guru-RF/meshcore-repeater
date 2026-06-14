# MeshCore repeater (plain C) - Raspberry Pi + NiceRF LoRa1262F30/LoRa1268F30-433
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

CORE_OBJ = \
  src/packet.o src/util.o src/identity.o src/advert.o src/mesh.o \
  src/sx126x.o src/config.o src/log.o
CRYPTO_OBJ = src/crypto/tweetnacl.o src/crypto/sha256.o src/crypto/randombytes.o

DAEMON_OBJ = $(CORE_OBJ) $(CRYPTO_OBJ) src/cli.o src/hal_linux.o src/main.o
TEST_OBJ   = $(CORE_OBJ) $(CRYPTO_OBJ) tools/mock_hal.o tools/selftest.o

BIN = meshcore-repeater

all: $(BIN)

# our code: full warnings
%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# vendored crypto: don't enforce our warning policy on third-party code
# (target-specific CFLAGS override - robust across make versions)
$(CRYPTO_OBJ): CFLAGS := -O2 -std=c11 -w

$(BIN): $(DAEMON_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DAEMON_OBJ) $(LDLIBS_DAEMON)

selftest: $(TEST_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_OBJ) $(LDLIBS_TEST)

test: selftest
	./selftest

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -Dm644 meshcore-repeater.conf $(DESTDIR)/etc/meshcore-repeater.conf
	install -Dm644 meshcore-repeater.service $(DESTDIR)/etc/systemd/system/meshcore-repeater.service
	@echo "edit /etc/meshcore-repeater.conf, then: systemctl enable --now meshcore-repeater"

clean:
	rm -f $(DAEMON_OBJ) $(TEST_OBJ) $(BIN) selftest

.PHONY: all test install clean
