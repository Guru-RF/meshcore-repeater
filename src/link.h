/*
 * link.h - optional split RX/TX over an IP (UDP) link.
 *
 * A repeater can be split into remote receiver(s) and one transmitter:
 *   - rx node: receives frames off the air and relays each one (+ the rssi/snr it
 *              measured) to the tx node as an HMAC-authenticated UDP datagram. It
 *              never transmits and never needs the channel keys.
 *   - tx node: listens for relayed frames from one or more rx nodes, verifies the
 *              HMAC, and injects each into the normal mesh_on_recv path - so its
 *              dedup ring merges every rx ear (and its own radio) and it does all
 *              the forwarding/TX.
 *
 * Datagram: [ver:1][ts:4 LE][rssi:2 LE][snr:1][len:2 LE][frame:len][mac:4]
 * mac = HMAC-SHA256(SHA256(link_key), bytes[0 .. hdr+len-1])[0..3].
 */
#ifndef MC_LINK_H
#define MC_LINK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include "config.h"

typedef enum { LINK_OFF = 0, LINK_RX, LINK_TX } link_mode_t;

typedef struct mc_link {
    link_mode_t mode;
    int         fd;                 /* UDP socket (-1 = none) */
    struct sockaddr_in peer;        /* rx mode: relay destination */
    uint8_t     key[32];            /* HMAC key = SHA256(link_key) */
    uint64_t    frames_out;         /* rx: relayed */
    uint64_t    frames_in;          /* tx: accepted */
    uint64_t    frames_bad;         /* tx: rejected (bad mac / stale / malformed) */
} mc_link;

/* Set up the link from config. Returns 0 (including mode OFF) or -1 on a hard
 * misconfiguration (missing key/peer, bind failure); mode is forced OFF then. */
int  link_init(mc_link *lk, const mc_config_t *cfg);
void link_close(mc_link *lk);
int  link_pollfd(const mc_link *lk);   /* fd to poll (tx node), else -1 */

/* rx mode: relay one received radio frame (+ measured rssi/snr) to the tx node. */
void link_relay(mc_link *lk, const uint8_t *frame, size_t len, int16_t rssi, int8_t snr);

/* tx mode: receive + authenticate one relayed frame. Returns 1 (got one, fields
 * filled), 0 (none pending), -1 (error). Call in a loop until it returns 0. */
int  link_recv(mc_link *lk, uint8_t *frame, size_t cap, size_t *len,
               int16_t *rssi, int8_t *snr);

#endif /* MC_LINK_H */
