/* link.c - split RX/TX over a UDP link (see link.h). */
#include "link.h"
#include "log.h"
#include "util.h"
#include "hmac_sha256.h"
#include "crypto/sha256.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define LINK_VER        1
#define LINK_HDR        10       /* ver(1) + ts(4) + rssi(2) + snr(1) + len(2) */
#define LINK_MAC        4
#define LINK_MAX_FRAME  512      /* LoRa frames are <= 255; generous upper bound */
#define LINK_TS_WINDOW  60       /* seconds: reject stale/replayed datagrams */

static link_mode_t parse_mode(const char *s)
{
    if (!strcasecmp(s, "rx")) return LINK_RX;
    if (!strcasecmp(s, "tx")) return LINK_TX;
    return LINK_OFF;
}

int link_init(mc_link *lk, const mc_config_t *cfg)
{
    memset(lk, 0, sizeof(*lk));
    lk->fd = -1;
    lk->mode = parse_mode(cfg->link_mode);
    if (lk->mode == LINK_OFF)
        return 0;

    if (cfg->link_key[0] == '\0') {
        log_err("link: %s mode needs a link_key (shared secret)", cfg->link_mode);
        lk->mode = LINK_OFF;
        return -1;
    }
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)cfg->link_key, strlen(cfg->link_key));
    sha256_final(&c, lk->key);          /* HMAC key = SHA256(link_key) */

    lk->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (lk->fd < 0) {
        log_err("link: socket: %s", strerror(errno));
        lk->mode = LINK_OFF;
        return -1;
    }
    fcntl(lk->fd, F_SETFL, O_NONBLOCK);

    if (lk->mode == LINK_TX) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(cfg->link_port);
        if (bind(lk->fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
            log_err("link: bind udp/%u: %s", cfg->link_port, strerror(errno));
            close(lk->fd); lk->fd = -1; lk->mode = LINK_OFF;
            return -1;
        }
        log_info("link: TX node listening for RX frames on udp/%u", cfg->link_port);
    } else {                            /* LINK_RX */
        if (cfg->link_peer[0] == '\0') {
            log_err("link: rx mode needs link_peer (the TX-node host)");
            close(lk->fd); lk->fd = -1; lk->mode = LINK_OFF;
            return -1;
        }
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        char portstr[8];
        snprintf(portstr, sizeof(portstr), "%u", cfg->link_port);
        if (getaddrinfo(cfg->link_peer, portstr, &hints, &res) != 0 || !res) {
            log_err("link: cannot resolve link_peer '%s'", cfg->link_peer);
            close(lk->fd); lk->fd = -1; lk->mode = LINK_OFF;
            return -1;
        }
        memcpy(&lk->peer, res->ai_addr, sizeof(lk->peer));
        freeaddrinfo(res);
        log_info("link: RX node relaying frames to %s:%u", cfg->link_peer, cfg->link_port);
    }
    return 0;
}

void link_close(mc_link *lk)
{
    if (lk->fd >= 0)
        close(lk->fd);
    lk->fd = -1;
    lk->mode = LINK_OFF;
}

int link_pollfd(const mc_link *lk)
{
    return (lk->mode == LINK_TX) ? lk->fd : -1;
}

void link_relay(mc_link *lk, const uint8_t *frame, size_t len, int16_t rssi, int8_t snr)
{
    if (lk->mode != LINK_RX || lk->fd < 0 || len == 0 || len > LINK_MAX_FRAME)
        return;
    uint8_t d[LINK_HDR + LINK_MAX_FRAME + LINK_MAC];
    d[0] = LINK_VER;
    wr_u32le(&d[1], (uint32_t)time(NULL));
    wr_u16le(&d[5], (uint16_t)rssi);
    d[7] = (uint8_t)snr;
    wr_u16le(&d[8], (uint16_t)len);
    memcpy(&d[LINK_HDR], frame, len);
    uint8_t mac[32];
    hmac_sha256(lk->key, sizeof(lk->key), d, LINK_HDR + len, mac);
    memcpy(&d[LINK_HDR + len], mac, LINK_MAC);
    if (sendto(lk->fd, d, LINK_HDR + len + LINK_MAC, 0,
               (struct sockaddr *)&lk->peer, sizeof(lk->peer)) > 0)
        lk->frames_out++;
}

int link_recv(mc_link *lk, uint8_t *frame, size_t cap, size_t *len,
              int16_t *rssi, int8_t *snr)
{
    if (lk->mode != LINK_TX || lk->fd < 0)
        return 0;
    uint8_t d[LINK_HDR + LINK_MAX_FRAME + LINK_MAC];
    ssize_t r = recvfrom(lk->fd, d, sizeof(d), 0, NULL, NULL);
    if (r < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    if (r < LINK_HDR + LINK_MAC || d[0] != LINK_VER) { lk->frames_bad++; return 0; }

    size_t flen = rd_u16le(&d[8]);
    if ((size_t)r != LINK_HDR + flen + LINK_MAC || flen > cap) { lk->frames_bad++; return 0; }

    uint8_t mac[32];
    hmac_sha256(lk->key, sizeof(lk->key), d, LINK_HDR + flen, mac);
    if (memcmp(mac, &d[LINK_HDR + flen], LINK_MAC) != 0) { lk->frames_bad++; return 0; }

    uint32_t ts = rd_u32le(&d[1]);
    uint32_t now = (uint32_t)time(NULL);
    uint32_t diff = (now > ts) ? now - ts : ts - now;
    if (diff > LINK_TS_WINDOW) { lk->frames_bad++; return 0; }   /* stale/replayed */

    *rssi = (int16_t)rd_u16le(&d[5]);
    *snr  = (int8_t)d[7];
    *len  = flen;
    memcpy(frame, &d[LINK_HDR], flen);
    lk->frames_in++;
    return 1;
}
