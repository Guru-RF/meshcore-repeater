# MeshCore repeater (plain C) - Raspberry Pi + NiceRF LoRa1262F30/LoRa1268F30-433
#
#   make            build the daemon (Linux/RPi; needs libgpiod-dev)
#   make test       build + run the host self-test (no hardware needed)
#   make install    create the meshcore user, install to /opt + systemd unit (root)
#   make uninstall  remove the service (keeps /opt data + user)
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CPPFLAGS += -D_GNU_SOURCE -Isrc

# install layout: self-contained under /opt, run by a dedicated system user
INSTALL_DIR  ?= /opt/meshcore-repeater
SERVICE_USER ?= meshcore

# Auto-detect libgpiod (v1 on Bookworm, v2 on Trixie). v2 needs -DUSE_GPIOD_V2.
GPIOD_VER    := $(shell pkg-config --modversion libgpiod 2>/dev/null)
GPIOD_MAJOR  := $(firstword $(subst ., ,$(GPIOD_VER)))
GPIOD_CFLAGS := $(shell pkg-config --cflags libgpiod 2>/dev/null)
GPIOD_LIBS   := $(shell pkg-config --libs libgpiod 2>/dev/null)
ifeq ($(GPIOD_LIBS),)
  GPIOD_LIBS := -lgpiod
endif
ifeq ($(GPIOD_MAJOR),2)
  CPPFLAGS += -DUSE_GPIOD_V2
endif
CPPFLAGS += $(GPIOD_CFLAGS)

LDLIBS_DAEMON = $(GPIOD_LIBS) -lm
LDLIBS_TEST   = -lm

CORE_OBJ = \
  src/packet.o src/util.o src/identity.o src/advert.o src/mesh.o \
  src/sx126x.o src/config.o src/log.o src/hmac_sha256.o
CRYPTO_OBJ = src/crypto/tweetnacl.o src/crypto/sha256.o src/crypto/randombytes.o src/crypto/aes128.o

DAEMON_OBJ = $(CORE_OBJ) $(CRYPTO_OBJ) src/cli.o src/hal_linux.o src/main.o
TEST_OBJ   = $(CORE_OBJ) $(CRYPTO_OBJ) tools/mock_hal.o tools/selftest.o

BIN = meshcore-repeater
CLI = meshcore-cli

all: $(BIN) $(CLI)

# our code: full warnings
%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# vendored crypto: don't enforce our warning policy on third-party code
# (target-specific CFLAGS override - robust across make versions)
$(CRYPTO_OBJ): CFLAGS := -O2 -std=c11 -w

$(BIN): $(DAEMON_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DAEMON_OBJ) $(LDLIBS_DAEMON)

# standalone control client (no radio/crypto deps, builds anywhere)
$(CLI): tools/meshcore-cli.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<

selftest: $(TEST_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_OBJ) $(LDLIBS_TEST)

test: selftest
	./selftest

# One-shot install: dedicated user, binary + config + service all under /opt.
# Run as root (sudo make install). Hardware access comes from the unit's
# SupplementaryGroups=spi gpio, so those groups must exist.
install: $(BIN) $(CLI)
	getent group $(SERVICE_USER) >/dev/null || groupadd --system $(SERVICE_USER)
	id -u $(SERVICE_USER) >/dev/null 2>&1 || useradd --system --gid $(SERVICE_USER) \
	  --no-create-home --home-dir $(INSTALL_DIR) --shell /usr/sbin/nologin $(SERVICE_USER)
	install -d -o $(SERVICE_USER) -g $(SERVICE_USER) -m 750 $(DESTDIR)$(INSTALL_DIR)
	install -m 755 $(BIN) $(DESTDIR)$(INSTALL_DIR)/$(BIN)
	@if [ -f repeater.key ] && [ ! -f $(DESTDIR)$(INSTALL_DIR)/repeater.key ]; then \
	  install -m 600 -o $(SERVICE_USER) -g $(SERVICE_USER) repeater.key \
	    $(DESTDIR)$(INSTALL_DIR)/repeater.key; \
	  echo ">> preserved existing identity key -> $(INSTALL_DIR)/repeater.key"; \
	fi
	@if [ -f $(DESTDIR)$(INSTALL_DIR)/meshcore-repeater.conf ]; then \
	  echo ">> keeping existing $(INSTALL_DIR)/meshcore-repeater.conf"; \
	else \
	  install -m 644 -o $(SERVICE_USER) -g $(SERVICE_USER) meshcore-repeater.conf \
	    $(DESTDIR)$(INSTALL_DIR)/meshcore-repeater.conf; \
	  echo ">> installed default config to $(INSTALL_DIR)/meshcore-repeater.conf"; \
	fi
	install -Dm 644 meshcore-repeater.service $(DESTDIR)/etc/systemd/system/meshcore-repeater.service
	install -Dm 755 $(CLI) $(DESTDIR)/usr/local/bin/$(CLI)
	@systemctl daemon-reload 2>/dev/null || true
	@echo ""
	@echo "Installed: runs as '$(SERVICE_USER)' from $(INSTALL_DIR) (config + key live there too)."
	@echo "Review $(INSTALL_DIR)/meshcore-repeater.conf, then enable at boot + start:"
	@echo "  sudo systemctl enable --now meshcore-repeater"

uninstall:
	-systemctl disable --now meshcore-repeater 2>/dev/null
	rm -f $(DESTDIR)/etc/systemd/system/meshcore-repeater.service
	rm -f $(DESTDIR)/usr/local/bin/$(CLI)
	-systemctl daemon-reload 2>/dev/null
	@echo "service removed. Left $(INSTALL_DIR) and user '$(SERVICE_USER)' in place;"
	@echo "to fully purge: sudo rm -rf $(INSTALL_DIR) && sudo userdel $(SERVICE_USER)"

clean:
	rm -f $(DAEMON_OBJ) $(TEST_OBJ) $(BIN) $(CLI) selftest

.PHONY: all test install uninstall clean
