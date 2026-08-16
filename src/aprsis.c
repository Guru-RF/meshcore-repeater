/* aprsis.c - APRS-IS RX iGate for the MeshCore repeater. */
#include "aprsis.h"
#include "aprs.h"
#include "advert.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SW_NAME "meshcore-repeater"
#define SW_VER  "1.0"

/* ---- passcode (APRS-IS "aprspass" hash) --------------------------------- */

int aprsis_passcode(const char *callsign)
{
    char root[16];
    int n = 0;
    for (const char *p = callsign; *p && *p != '-' && n < 15; ++p)
        root[n++] = (char)toupper((unsigned char)*p);
    unsigned int hash = 0x73e2;                 /* seed */
    for (int i = 0; i < n; i += 2) {
        hash ^= (unsigned int)(unsigned char)root[i] << 8;   /* even char */
        if (i + 1 < n)
            hash ^= (unsigned int)(unsigned char)root[i + 1]; /* odd char */
    }
    return (int)(hash & 0x7fff);                /* 0..32767 */
}

/* ---- callsign filter (two-layer: APRS-IS legality + ITU ham shape) ------ */

int aprsis_valid_callsign(const char *name, char *out, size_t outsz)
{
    char up[16];
    size_t n = 0;
    for (const char *p = name; *p; ++p) {
        char c = *p;
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
        if (n >= sizeof(up) - 1)
            return 0;
        up[n++] = c;
    }
    up[n] = '\0';

    char *dash = strchr(up, '-');
    size_t cl = dash ? (size_t)(dash - up) : n;     /* base-call length */
    if (cl < 3 || cl > 7)
        return 0;
    if (dash) {                                     /* SSID: 1-2 alnum, not "-0" */
        const char *s = dash + 1;
        size_t sl = strlen(s);
        if (sl < 1 || sl > 2)
            return 0;
        for (size_t i = 0; i < sl; ++i)
            if (!isalnum((unsigned char)s[i]))
                return 0;
        if (sl == 1 && s[0] == '0')
            return 0;
        if (cl + 1 + sl > 9)
            return 0;
    }
    /* ITU shape: prefix(1-2, >=1 letter) + call-area digit + suffix(1-4 letters) */
    size_t s = cl;
    while (s > 0 && up[s - 1] >= 'A' && up[s - 1] <= 'Z') s--;   /* trailing letters */
    size_t suf = cl - s;
    if (suf < 1 || suf > 4)
        return 0;
    if (s == 0)
        return 0;
    if (!(up[s - 1] >= '0' && up[s - 1] <= '9'))                 /* call-area digit */
        return 0;
    size_t pl = s - 1;
    if (pl < 1 || pl > 2)
        return 0;
    int alpha = 0;
    for (size_t i = 0; i < pl; ++i) {
        char c = up[i];
        if (c >= 'A' && c <= 'Z') alpha = 1;
        else if (!(c >= '0' && c <= '9')) return 0;
    }
    if (!alpha)
        return 0;

    if (out && outsz)
        snprintf(out, outsz, "%s", up);
    return 1;
}

/* ---- small helpers ------------------------------------------------------ */

static const char *type_name(uint8_t t)
{
    switch (t) {
    case ADV_TYPE_CHAT:     return "chat";
    case ADV_TYPE_REPEATER: return "repeater";
    case ADV_TYPE_ROOM:     return "room";
    case ADV_TYPE_SENSOR:   return "sensor";
    default:                return "node";
    }
}

/* Append a line to the outbound buffer (dropped if it would overflow). */
static void tx_queue(mc_aprsis *a, const char *line)
{
    size_t len = strlen(line);
    if (a->txlen + len > sizeof(a->txbuf)) {
        a->stat_dropped++;
        return;
    }
    memcpy(a->txbuf + a->txlen, line, len);
    a->txlen += len;
}

/* Build the iGate's own position beacon. */
static void build_beacon(mc_aprsis *a, char *out, size_t outsz)
{
    const mc_config_t *c = a->cfg;
    char pos[64];
    if (aprs_make_position(pos, sizeof(pos), c->latitude, c->longitude,
                           -1, -1, c->aprs_symbol) != 0) {
        out[0] = '\0';
        return;
    }
    char alt[24] = "";
    if (c->aprs_altitude != 0.0)
        snprintf(alt, sizeof(alt), " /A=%06d", (int)(c->aprs_altitude * 3.2808399));
    /* '!' = real-time, no timestamp, NOT message-capable (honest for R& gate) */
    snprintf(out, outsz, "%s>%s,TCPIP*:!%s %s%s\r\n",
             c->aprs_call, c->aprs_tocall, pos, c->aprs_comment, alt);
}

/* ---- per-node rate limiting --------------------------------------------- */

/* Rough great-circle distance in metres (equirectangular; fine for < few km). */
static double dist_m(double la1, double lo1, double la2, double lo2)
{
    double dlat = (la2 - la1) * 111320.0;
    double dlon = (lo2 - lo1) * 111320.0 * cos(la1 * 3.14159265358979 / 180.0);
    return sqrt(dlat * dlat + dlon * dlon);
}

/* Returns 1 if this call may be gated now (and records it), 0 to skip. */
static int rate_ok(mc_aprsis *a, const char *call, uint64_t now, double lat, double lon)
{
    uint64_t min_ms = (uint64_t)a->cfg->aprs_node_rate * 1000;
    aprsis_node_t *slot = NULL;
    for (int i = 0; i < a->n_nodes; i++) {
        if (!strcmp(a->nodes[i].call, call)) {
            aprsis_node_t *e = &a->nodes[i];
            if (now - e->last_ms < min_ms && dist_m(e->lat, e->lon, lat, lon) < 100.0)
                return 0;                         /* too soon and hasn't moved */
            e->last_ms = now; e->lat = lat; e->lon = lon;
            return 1;
        }
    }
    /* new node: append or LRU-evict the oldest */
    if (a->n_nodes < APRSIS_MAX_NODES) {
        slot = &a->nodes[a->n_nodes++];
    } else {
        slot = &a->nodes[0];
        for (int i = 1; i < a->n_nodes; i++)
            if (a->nodes[i].last_ms < slot->last_ms)
                slot = &a->nodes[i];
    }
    snprintf(slot->call, sizeof(slot->call), "%s", call);
    slot->last_ms = now; slot->lat = lat; slot->lon = lon;
    return 1;
}

/* ---- public: gate a node's advertised position -------------------------- */

void aprsis_gate_node(mc_aprsis *a, uint64_t now_ms, const char *name,
                      uint8_t type, double lat, double lon, const uint8_t pub[32])
{
    if (a->state != APRSIS_READY)
        return;
    /* own-beacon exclusion: never gate our own advert */
    if (memcmp(pub, a->our_pub, 32) == 0)
        return;
    /* only real stations */
    if (type != ADV_TYPE_CHAT && type != ADV_TYPE_REPEATER)
        return;
    char call[12];
    if (!aprsis_valid_callsign(name, call, sizeof(call)))
        return;
    if (!rate_ok(a, call, now_ms, lat, lon))
        return;

    char pos[64];
    if (aprs_make_position(pos, sizeof(pos), lat, lon, -1, -1, a->cfg->aprs_node_symbol) != 0)
        return;
    char line[300];
    snprintf(line, sizeof(line), "%s>%s,qAO,%s:!%s MeshCore %s\r\n",
             call, a->cfg->aprs_tocall, a->cfg->aprs_call, pos, type_name(type));
    tx_queue(a, line);
    a->stat_gated++;
    log_info("aprs: gated %s at %.5f,%.5f", call, lat, lon);
}

/* ---- connection state machine ------------------------------------------- */

static void go_disconnected(mc_aprsis *a, uint64_t now, int backoff_bump)
{
    if (a->fd >= 0) close(a->fd);
    a->fd = -1;
    a->state = APRSIS_DISCONNECTED;
    a->txlen = a->rxlen = 0;
    if (backoff_bump) {
        a->backoff_s = a->backoff_s < 5 ? 5 : a->backoff_s * 2;
        if (a->backoff_s > 300) a->backoff_s = 300;
    }
    a->next_connect_ms = now + (uint64_t)a->backoff_s * 1000;
}

static void start_connect(mc_aprsis *a, uint64_t now)
{
    int fd = socket(a->addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) { go_disconnected(a, now, 1); return; }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    int yes = 1, idle = 300, intvl = 30, cnt = 5;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#else
    (void)idle; (void)intvl; (void)cnt;
#endif
    int rc = connect(fd, (struct sockaddr *)&a->addr, a->addrlen);
    a->fd = fd;
    a->deadline_ms = now + 10000;
    if (rc == 0) {
        a->state = APRSIS_CONNECTING;   /* let the POLLOUT path send login uniformly */
    } else if (errno == EINPROGRESS) {
        a->state = APRSIS_CONNECTING;
    } else {
        go_disconnected(a, now, 1);
    }
}

static void send_login(mc_aprsis *a, uint64_t now)
{
    char login[128];
    snprintf(login, sizeof(login), "user %s pass %d vers %s %s\r\n",
             a->cfg->aprs_call, a->passcode, SW_NAME, SW_VER);
    tx_queue(a, login);
    a->state = APRSIS_LOGIN;
    a->deadline_ms = now + 10000;
    log_info("aprs: connected to %s:%u, logging in as %s",
             a->cfg->aprs_host, a->cfg->aprs_port, a->cfg->aprs_call);
}

/* Process one complete server line (LF-terminated, already NUL-cut). */
static void handle_server_line(mc_aprsis *a, char *line, uint64_t now)
{
    if (line[0] != '#')
        return;                                    /* data line - ignore */
    if (a->state == APRSIS_LOGIN && strstr(line, "logresp")) {
        /* match the " verified," TOKEN - NOT strstr("verified") (would match
         * "unverified,"): "unverified" has no space before its 'v'. */
        if (strstr(line, " verified,")) {
            a->state = APRSIS_READY;
            a->backoff_s = 5;
            a->last_beacon_ms = 0;                 /* beacon immediately */
            log_info("aprs: login verified");
        } else {
            log_warn("aprs: login NOT verified (check aprs_call/passcode): %s", line);
            go_disconnected(a, now, 1);
            a->backoff_s = 300;                    /* a bad passcode won't fix fast */
            a->next_connect_ms = now + 300000;
        }
    }
}

static void read_server(mc_aprsis *a, uint64_t now)
{
    ssize_t r = recv(a->fd, a->rxbuf + a->rxlen, sizeof(a->rxbuf) - 1 - a->rxlen, 0);
    if (r == 0) { go_disconnected(a, now, 1); return; }      /* peer closed */
    if (r < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            go_disconnected(a, now, 1);
        return;
    }
    a->rxlen += (size_t)r;
    a->rxbuf[a->rxlen] = '\0';

    size_t start = 0;
    for (size_t i = 0; i < a->rxlen; i++) {
        if (a->rxbuf[i] == '\n') {
            a->rxbuf[i] = '\0';
            size_t e = i;
            if (e > start && a->rxbuf[e - 1] == '\r') a->rxbuf[e - 1] = '\0';
            handle_server_line(a, a->rxbuf + start, now);
            if (a->state == APRSIS_DISCONNECTED) return;
            start = i + 1;
        }
    }
    if (start > 0) {
        memmove(a->rxbuf, a->rxbuf + start, a->rxlen - start);
        a->rxlen -= start;
    } else if (a->rxlen >= sizeof(a->rxbuf) - 1) {
        a->rxlen = 0;                              /* overlong line: drop */
    }
}

static void tx_flush(mc_aprsis *a, uint64_t now)
{
    while (a->txlen > 0) {
        ssize_t w = send(a->fd, a->txbuf, a->txlen, 0);
        if (w > 0) {
            memmove(a->txbuf, a->txbuf + w, a->txlen - (size_t)w);
            a->txlen -= (size_t)w;
        } else {
            if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                go_disconnected(a, now, 1);
            return;
        }
    }
}

int aprsis_pollfd(const mc_aprsis *a, short *events)
{
    if (a->fd < 0) { *events = 0; return -1; }
    if (a->state == APRSIS_CONNECTING) { *events = POLLOUT; return a->fd; }
    *events = POLLIN | (a->txlen > 0 ? POLLOUT : 0);
    return a->fd;
}

void aprsis_service(mc_aprsis *a, uint64_t now, short revents)
{
    switch (a->state) {
    case APRSIS_DISCONNECTED:
        if (a->resolved && now >= a->next_connect_ms)
            start_connect(a, now);
        return;

    case APRSIS_CONNECTING:
        if (revents & (POLLERR | POLLHUP | POLLNVAL)) { go_disconnected(a, now, 1); return; }
        if (revents & POLLOUT) {
            int err = 0; socklen_t l = sizeof(err);
            getsockopt(a->fd, SOL_SOCKET, SO_ERROR, &err, &l);
            if (err != 0) { go_disconnected(a, now, 1); return; }
            send_login(a, now);
            tx_flush(a, now);
        } else if (now > a->deadline_ms) {
            go_disconnected(a, now, 1);
        }
        return;

    case APRSIS_LOGIN:
    case APRSIS_READY:
        if (revents & (POLLERR | POLLHUP | POLLNVAL)) { go_disconnected(a, now, 1); return; }
        if (revents & POLLIN) read_server(a, now);
        if (a->state == APRSIS_DISCONNECTED) return;
        if (a->txlen > 0) tx_flush(a, now);
        if (a->state == APRSIS_LOGIN && now > a->deadline_ms) { go_disconnected(a, now, 1); return; }
        if (a->state == APRSIS_READY && a->cfg->aprs_beacon_interval &&
            now - a->last_beacon_ms >= (uint64_t)a->cfg->aprs_beacon_interval * 1000) {
            char beacon[400];
            build_beacon(a, beacon, sizeof(beacon));
            if (beacon[0]) { tx_queue(a, beacon); tx_flush(a, now); a->stat_beacons++;
                             log_info("aprs: sent position beacon"); }
            a->last_beacon_ms = now;
        }
        return;
    }
}

/* ---- init / close ------------------------------------------------------- */

int aprsis_init(mc_aprsis *a, const mc_config_t *cfg, const uint8_t our_pub[32])
{
    memset(a, 0, sizeof(*a));
    a->cfg = cfg;
    a->fd = -1;
    a->state = APRSIS_DISCONNECTED;
    a->backoff_s = 5;
    memcpy(a->our_pub, our_pub, 32);

    if (!cfg->aprs_enable || cfg->aprs_call[0] == '\0') {
        log_info("aprs: disabled");
        return -1;
    }
    if (!strcasecmp(cfg->aprs_passcode, "auto"))
        a->passcode = aprsis_passcode(cfg->aprs_call);
    else
        a->passcode = atoi(cfg->aprs_passcode);

    /* resolve the host once (blocking is fine here, before the radio loop) */
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", cfg->aprs_port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(cfg->aprs_host, portstr, &hints, &res) != 0 || !res) {
        log_warn("aprs: cannot resolve %s (will retry)", cfg->aprs_host);
        return 0;                                  /* enabled but unresolved yet */
    }
    memcpy(&a->addr, res->ai_addr, res->ai_addrlen);
    a->addrlen = res->ai_addrlen;
    a->resolved = 1;
    freeaddrinfo(res);
    log_info("aprs: iGate enabled - %s pass %d -> %s:%u (beacon %us)",
             cfg->aprs_call, a->passcode, cfg->aprs_host, cfg->aprs_port,
             cfg->aprs_beacon_interval);
    return 0;
}

void aprsis_close(mc_aprsis *a)
{
    if (a->fd >= 0) close(a->fd);
    a->fd = -1;
    a->state = APRSIS_DISCONNECTED;
}
