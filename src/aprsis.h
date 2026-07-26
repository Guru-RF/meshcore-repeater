/*
 * aprsis.h - APRS-IS RX iGate: gate MeshCore adverts-with-coordinates to
 * APRS-IS, and beacon the repeater's own position.
 *
 * Non-blocking single-loop client (joins the daemon's poll set); never blocks
 * the time-sensitive radio loop. Verified design (passcode, qAO, '!' position,
 * R&/Mn symbols, callsign filter) - see memory/aprs-igate.md.
 */
#ifndef MC_APRSIS_H
#define MC_APRSIS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include "config.h"

#define APRSIS_MAX_NODES 64
#define APRSIS_TXBUF     2048
#define APRSIS_RXBUF     600

typedef struct {
    char     call[12];
    uint64_t last_ms;
    double   lat, lon;
} aprsis_node_t;

typedef enum {
    APRSIS_DISCONNECTED,
    APRSIS_CONNECTING,   /* non-blocking connect in progress */
    APRSIS_LOGIN,        /* connected, login sent, awaiting "verified" */
    APRSIS_READY,        /* verified - may inject */
} aprsis_state_t;

typedef struct mc_aprsis {
    const mc_config_t *cfg;
    uint8_t   our_pub[32];          /* our node pubkey (own-beacon exclusion) */
    int       passcode;

    int       fd;
    aprsis_state_t state;
    struct sockaddr_storage addr;   /* resolved server address (cached once) */
    socklen_t addrlen;
    int       resolved;

    uint64_t  next_connect_ms;      /* backoff gate */
    int       backoff_s;
    uint64_t  deadline_ms;          /* connect/login timeout */
    uint64_t  last_beacon_ms;

    char      txbuf[APRSIS_TXBUF];
    size_t    txlen;
    char      rxbuf[APRSIS_RXBUF];
    size_t    rxlen;

    aprsis_node_t nodes[APRSIS_MAX_NODES];
    int       n_nodes;

    uint64_t  stat_gated, stat_beacons, stat_dropped;
} mc_aprsis;

/* Compute the APRS-IS passcode for a callsign (SSID stripped, upper-cased). */
int  aprsis_passcode(const char *callsign);

/* Validate a MeshCore node name as a plausible ham callsign; upper-cases it
 * into out. Returns 1 (out filled) if valid for APRS-IS, 0 otherwise. */
int  aprsis_valid_callsign(const char *name, char *out, size_t outsz);

/* Init from config: resolve host once, compute passcode. 0 ok, -1 off/failed. */
int  aprsis_init(mc_aprsis *a, const mc_config_t *cfg, const uint8_t our_pub[32]);

/* Poll integration: returns the fd to poll (-1 if none) and sets *events. */
int  aprsis_pollfd(const mc_aprsis *a, short *events);

/* Advance the state machine + do I/O. revents = poll result (0 if not polled). */
void aprsis_service(mc_aprsis *a, uint64_t now_ms, short revents);

/* Gate a node's advertised position (validates callsign + rate-limits). */
void aprsis_gate_node(mc_aprsis *a, uint64_t now_ms, const char *name,
                      uint8_t type, double lat, double lon, const uint8_t pub[32]);

void aprsis_close(mc_aprsis *a);

#endif /* MC_APRSIS_H */
