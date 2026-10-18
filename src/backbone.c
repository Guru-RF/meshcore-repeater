/* backbone.c - IP fallback backbone client (see backbone.h, docs/backbone.md). */
#include "backbone.h"
#include "mesh.h"
#include "packet.h"
#include "hal.h"
#include "log.h"
#include "util.h"
#include "hmac_sha256.h"
#include "crypto/sha256.h"
#include "crypto/tweetnacl.h"
#include "version.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void randombytes(unsigned char *x, unsigned long long xlen);

#define BB_CTX_HELLO   "MCBB1 HELLO"
#define BB_CTX_WELCOME "MCBB1 WELCOME"
#define BB_CTX_RESET   "MCBB1 RESET"
#define BB_LBL_UP      "MCBB1 up"
#define BB_LBL_DOWN    "MCBB1 down"

#define BB_TS_WINDOW        120     /* s: RESET timestamps must be this fresh */
#define BB_WELCOME_WAIT_MS 5000     /* resend HELLO after this */
#define BB_HELLO_TRIES        3     /* HELLOs per attempt before backing off */
#define BB_BACKOFF_MAX      300     /* s */
#define BB_TXQ_HEADROOM       8     /* keep this many TX queue slots for RF traffic */
#define BB_RX_BURST          16     /* datagrams read per service call */
#define BB_STATUS_JSON     1100     /* max JSON body (header + MAC keep it < BB_MAX_DGRAM) */

/* ======================================================================
 * codec
 * ====================================================================== */

static void put_hdr(uint8_t *d, uint8_t type)
{
    d[0] = 'M'; d[1] = 'B'; d[2] = BB_VERSION; d[3] = type;
}

static bool hdr_ok(const uint8_t *d, size_t len, uint8_t type)
{
    return len >= 4 && d[0] == 'M' && d[1] == 'B' && d[2] == BB_VERSION && d[3] == type;
}

/* Ed25519 over ctx || msg (the context string separates our signatures from
 * MeshCore's advert signatures, made with the same key). */
static int sign_ctx(const mc_identity_t *id, const char *ctx, const uint8_t *msg,
                    size_t len, uint8_t sig[64])
{
    uint8_t buf[160];
    size_t cl = strlen(ctx);
    if (cl + len > sizeof(buf))
        return -1;
    memcpy(buf, ctx, cl);
    memcpy(buf + cl, msg, len);
    return mc_identity_sign(id, sig, buf, cl + len);
}

static bool verify_ctx(const uint8_t pub[32], const char *ctx, const uint8_t *msg,
                       size_t len, const uint8_t sig[64])
{
    uint8_t buf[160];
    size_t cl = strlen(ctx);
    if (cl + len > sizeof(buf))
        return false;
    memcpy(buf, ctx, cl);
    memcpy(buf + cl, msg, len);
    return mc_identity_verify(pub, sig, buf, cl + len);
}

static void sha256_buf(const uint8_t *a, size_t al, const uint8_t *b, size_t bl, uint8_t out[32])
{
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, a, al);
    if (b && bl)
        sha256_update(&c, b, bl);
    sha256_final(&c, out);
}

size_t bb_build_hello(uint8_t *out, size_t cap, const mc_identity_t *id, uint8_t roles,
                      uint32_t ts, const uint8_t eph_pub[32], const char *name)
{
    size_t nl = name ? strlen(name) : 0;
    if (nl > BB_NAME_MAX) nl = BB_NAME_MAX;
    size_t len = BB_HELLO_FIXED + nl + 64;
    if (cap < len)
        return 0;
    put_hdr(out, BB_T_HELLO);
    out[4] = roles;
    out[5] = 0;
    wr_u32le(&out[6], ts);
    memcpy(&out[10], id->pub, 32);
    memcpy(&out[42], eph_pub, 32);
    out[74] = (uint8_t)nl;
    memcpy(&out[75], name, nl);
    if (sign_ctx(id, BB_CTX_HELLO, out, BB_HELLO_FIXED + nl, &out[BB_HELLO_FIXED + nl]) != 0)
        return 0;
    return len;
}

size_t bb_build_welcome(uint8_t *out, size_t cap, const mc_identity_t *hub,
                        const bb_welcome_t *w, const uint8_t hello_hash[32])
{
    if (cap < BB_WELCOME_LEN)
        return 0;
    put_hdr(out, BB_T_WELCOME);
    out[4] = w->roles;
    out[5] = 0;
    wr_u32le(&out[6], w->ts);
    wr_u32le(&out[10], w->sid);
    memcpy(&out[14], w->eph_pub, 32);
    memcpy(&out[46], hello_hash, 32);
    wr_u16le(&out[78], w->keepalive_s);
    wr_u16le(&out[80], w->status_s);
    wr_u16le(&out[82], w->neighbours_s);
    if (sign_ctx(hub, BB_CTX_WELCOME, out, 84, &out[84]) != 0)
        return 0;
    return BB_WELCOME_LEN;
}

int bb_check_welcome(const uint8_t *d, size_t len, const uint8_t hub_pub[32],
                     const uint8_t hello_hash[32], uint8_t roles_asked, bb_welcome_t *w)
{
    if (len != BB_WELCOME_LEN || !hdr_ok(d, len, BB_T_WELCOME))
        return -1;
    if (memcmp(&d[46], hello_hash, 32) != 0)
        return -2;                              /* answers some other HELLO */
    if (!verify_ctx(hub_pub, BB_CTX_WELCOME, d, 84, &d[84]))
        return -3;
    w->roles = d[4];
    w->ts    = rd_u32le(&d[6]);
    w->sid   = rd_u32le(&d[10]);
    memcpy(w->eph_pub, &d[14], 32);
    w->keepalive_s  = rd_u16le(&d[78]);
    w->status_s     = rd_u16le(&d[80]);
    w->neighbours_s = rd_u16le(&d[82]);
    if (w->sid == 0 || (w->roles & (uint8_t)~roles_asked) != 0)
        return -4;                              /* no session id, or roles we never asked for */
    return 0;
}

size_t bb_build_reset(uint8_t *out, size_t cap, const mc_identity_t *hub,
                      uint32_t sid, uint32_t seq, uint32_t ts)
{
    if (cap < BB_RESET_LEN)
        return 0;
    put_hdr(out, BB_T_RESET);
    wr_u32le(&out[4], sid);
    wr_u32le(&out[8], seq);
    wr_u32le(&out[12], ts);
    if (sign_ctx(hub, BB_CTX_RESET, out, 16, &out[16]) != 0)
        return 0;
    return BB_RESET_LEN;
}

int bb_check_reset(const uint8_t *d, size_t len, const uint8_t hub_pub[32],
                   uint32_t *sid, uint32_t *seq, uint32_t *ts)
{
    if (len != BB_RESET_LEN || !hdr_ok(d, len, BB_T_RESET))
        return -1;
    if (!verify_ctx(hub_pub, BB_CTX_RESET, d, 16, &d[16]))
        return -3;
    *sid = rd_u32le(&d[4]);
    *seq = rd_u32le(&d[8]);
    *ts  = rd_u32le(&d[12]);
    return 0;
}

int bb_derive_keys(const uint8_t shared[32], const uint8_t *hello, size_t hello_len,
                   const uint8_t *welcome, size_t welcome_len,
                   uint8_t k_up[32], uint8_t k_down[32])
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++)
        acc |= shared[i];
    if (acc == 0)
        return -1;

    uint8_t th[32];                             /* transcript hash */
    sha256_buf(hello, hello_len, welcome, welcome_len, th);

    uint8_t msg[16 + 32];
    size_t ll = strlen(BB_LBL_UP);
    memcpy(msg, BB_LBL_UP, ll);
    memcpy(msg + ll, th, 32);
    hmac_sha256(shared, 32, msg, ll + 32, k_up);
    ll = strlen(BB_LBL_DOWN);
    memcpy(msg, BB_LBL_DOWN, ll);
    memcpy(msg + ll, th, 32);
    hmac_sha256(shared, 32, msg, ll + 32, k_down);
    return 0;
}

size_t bb_seal(uint8_t *out, size_t cap, uint8_t type, uint32_t sid, uint32_t seq,
               const uint8_t *body, size_t blen, const uint8_t key[32])
{
    size_t len = BB_HDR + blen + BB_MAC;
    if (cap < len || len > BB_MAX_DGRAM)
        return 0;
    put_hdr(out, type);
    wr_u32le(&out[4], sid);
    wr_u32le(&out[8], seq);
    if (blen)
        memcpy(&out[BB_HDR], body, blen);
    uint8_t mac[32];
    hmac_sha256(key, 32, out, BB_HDR + blen, mac);
    memcpy(&out[BB_HDR + blen], mac, BB_MAC);
    return len;
}

int bb_open(const uint8_t *d, size_t len, const uint8_t key[32], uint8_t *type,
            uint32_t *sid, uint32_t *seq, const uint8_t **body, size_t *blen)
{
    if (len < BB_HDR + BB_MAC || d[0] != 'M' || d[1] != 'B' || d[2] != BB_VERSION)
        return -1;
    uint8_t mac[32];
    hmac_sha256(key, 32, d, len - BB_MAC, mac);
    uint8_t diff = 0;                           /* constant-time compare */
    for (int i = 0; i < BB_MAC; i++)
        diff |= (uint8_t)(mac[i] ^ d[len - BB_MAC + i]);
    if (diff)
        return -2;
    *type = d[3];
    *sid  = rd_u32le(&d[4]);
    *seq  = rd_u32le(&d[8]);
    *body = &d[BB_HDR];
    *blen = len - BB_HDR - BB_MAC;
    return 0;
}

bool bb_replay_check(bb_replay_t *w, uint32_t seq)
{
    if (seq == 0)
        return false;                           /* sequence numbers start at 1 */
    if (seq > w->top) {
        uint32_t shift = seq - w->top;
        w->bits = (shift >= 64) ? 0 : (w->bits << shift);
        w->bits |= 1;
        w->top = seq;
        return true;
    }
    uint32_t back = w->top - seq;
    if (back >= 64)
        return false;                           /* older than the window */
    if (w->bits & (1ull << back))
        return false;                           /* already seen */
    w->bits |= 1ull << back;
    return true;
}

/* ======================================================================
 * client
 * ====================================================================== */

static const char *const state_names[] = { "off", "idle", "resolving", "hello-sent", "up" };

const char *backbone_state_name(const mc_backbone *bb) { return state_names[bb->state]; }
bool backbone_up(const mc_backbone *bb) { return bb && bb->state == BB_UP; }

static void sock_close(mc_backbone *bb)
{
    if (bb->fd >= 0)
        close(bb->fd);
    bb->fd = -1;
}

static void send_raw(mc_backbone *bb, const uint8_t *d, size_t n)
{
    if (bb->fd >= 0 && send(bb->fd, d, n, 0) == (ssize_t)n)
        bb->dgrams_out++;
}

static void send_session(mc_backbone *bb, uint8_t type, const uint8_t *body, size_t blen)
{
    uint8_t d[BB_MAX_DGRAM];
    size_t n = bb_seal(d, sizeof(d), type, bb->sid, ++bb->seq_out, body, blen, bb->k_up);
    if (n)
        send_raw(bb, d, n);
}

static void forget_session(mc_backbone *bb)
{
    memset(bb->k_up, 0, sizeof(bb->k_up));
    memset(bb->k_down, 0, sizeof(bb->k_down));
    memset(bb->eph_sec, 0, sizeof(bb->eph_sec));
    bb->sid = 0;
    bb->roles = 0;
    bb->seq_out = 0;
    memset(&bb->rwin, 0, sizeof(bb->rwin));
    sock_close(bb);
    bb->state = BB_IDLE;
}

/* An attempt failed: wait the backoff (+0..25 % jitter), then double it. */
static void retry_later(mc_backbone *bb, uint64_t now)
{
    forget_session(bb);
    int b = bb->backoff_s;
    bb->next_try_ms = now + (uint64_t)b * 1000 + hal_rng_int(0, (uint32_t)b * 250);
    bb->backoff_s = (b * 2 > BB_BACKOFF_MAX) ? BB_BACKOFF_MAX : b * 2;
}

static void send_hello(mc_backbone *bb, uint64_t now)
{
    uint8_t eph_pub[32];
    randombytes(bb->eph_sec, sizeof(bb->eph_sec));
    crypto_scalarmult_base(eph_pub, bb->eph_sec);       /* X25519 clamps the scalar */
    uint32_t ts = (uint32_t)time(NULL);
    if (ts <= bb->last_hello_ts)
        ts = bb->last_hello_ts + 1;                    /* strictly increasing */
    bb->last_hello_ts = ts;
    bb->hello_len = bb_build_hello(bb->hello, sizeof(bb->hello), bb->id, bb->roles_asked,
                                   ts, eph_pub, bb->cfg->name);
    if (bb->hello_len == 0) {
        log_err("backbone: could not sign a HELLO (no secret key?)");
        retry_later(bb, now);
        return;
    }
    sha256_buf(bb->hello, bb->hello_len, NULL, 0, bb->hello_hash);
    send_raw(bb, bb->hello, bb->hello_len);
    bb->hello_tries++;
    bb->state = BB_HELLO_SENT;
    bb->deadline_ms = now + BB_WELCOME_WAIT_MS;
}

/* Start an attempt: resolve the hub again without blocking (getaddrinfo_a). */
static void start_attempt(mc_backbone *bb, uint64_t now)
{
    forget_session(bb);
    bb->hello_tries = 0;
    bb->have_addr = false;
    memset(&bb->gai, 0, sizeof(bb->gai));
    memset(&bb->gai_hints, 0, sizeof(bb->gai_hints));
    bb->gai_hints.ai_family = AF_INET;
    bb->gai_hints.ai_socktype = SOCK_DGRAM;
    snprintf(bb->gai_host, sizeof(bb->gai_host), "%s", bb->cfg->backbone_host);
    snprintf(bb->gai_port, sizeof(bb->gai_port), "%u", bb->cfg->backbone_port);
    bb->gai.ar_name = bb->gai_host;
    bb->gai.ar_service = bb->gai_port;
    bb->gai.ar_request = &bb->gai_hints;
    struct gaicb *list[1] = { &bb->gai };
    if (getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) != 0) {
        log_warn("backbone: could not start a DNS lookup for %s", bb->gai_host);
        retry_later(bb, now);
        return;
    }
    bb->gai_busy = true;
    bb->state = BB_RESOLVING;
}

static void check_resolved(mc_backbone *bb, uint64_t now)
{
    int e = gai_error(&bb->gai);
    if (e == EAI_INPROGRESS)
        return;
    bb->gai_busy = false;
    struct addrinfo *res = bb->gai.ar_result;
    bb->gai.ar_result = NULL;
    if (e != 0 || !res) {
        log_warn("backbone: cannot resolve %s (%s) - retrying in %ds",
                 bb->gai_host, gai_strerror(e), bb->backoff_s);
        if (res) freeaddrinfo(res);
        retry_later(bb, now);
        return;
    }
    memcpy(&bb->addr, res->ai_addr, sizeof(bb->addr));
    freeaddrinfo(res);
    bb->have_addr = true;

    /* a connected socket only accepts datagrams from the hub's address */
    bb->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (bb->fd < 0 || connect(bb->fd, (struct sockaddr *)&bb->addr, sizeof(bb->addr)) != 0) {
        log_warn("backbone: socket to %s: %s", bb->gai_host, strerror(errno));
        retry_later(bb, now);
        return;
    }
    send_hello(bb, now);
}

/* ---- status reports (JSON) ---- */

typedef struct { char *p; size_t cap, len; bool full; } jbuf_t;

static void jb_add(jbuf_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jb_add(jbuf_t *j, const char *fmt, ...)
{
    if (j->full) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(j->p + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= j->cap - j->len) { j->full = true; return; }
    j->len += (size_t)n;
}

/* Length of the valid UTF-8 sequence at s, or 0 if it is invalid. */
static size_t utf8_seq(const unsigned char *s)
{
    unsigned char c = s[0];
    if (c < 0x80) return 1;
    size_t n; uint32_t cp, min;
    if ((c & 0xE0) == 0xC0)      { n = 2; cp = c & 0x1F; min = 0x80; }
    else if ((c & 0xF0) == 0xE0) { n = 3; cp = c & 0x0F; min = 0x800; }
    else if ((c & 0xF8) == 0xF0) { n = 4; cp = c & 0x07; min = 0x10000; }
    else return 0;
    for (size_t i = 1; i < n; i++) {
        if ((s[i] & 0xC0) != 0x80) return 0;           /* also stops at the NUL */
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return n;
}

/* A JSON string: escaped, invalid UTF-8 replaced by '?'. */
static void jb_str(jbuf_t *j, const char *s)
{
    jb_add(j, "\"");
    const unsigned char *u = (const unsigned char *)(s ? s : "");
    while (*u) {
        size_t n = utf8_seq(u);
        if (n == 0)                       { jb_add(j, "?"); u++; continue; }
        if (*u == '"' || *u == '\\')      jb_add(j, "\\%c", *u);
        else if (*u < 0x20)               jb_add(j, "\\u%04x", *u);
        else                              jb_add(j, "%.*s", (int)n, (const char *)u);
        u += n;
    }
    jb_add(j, "\"");
}

static void send_status(mc_backbone *bb, uint64_t now)
{
    const mc_config_t *c = bb->cfg;
    const mc_mesh_t *m = bb->mesh;
    if (!m)
        return;
    const mesh_stats_t *s = &m->stats;
    char buf[BB_STATUS_JSON + 1];
    jbuf_t j = { buf, sizeof(buf), 0, false };
    typedef unsigned long long ull;

    jb_add(&j, "{\"name\":");
    jb_str(&j, c->name);
    jb_add(&j, ",\"fw\":");
    jb_str(&j, MC_VERSION);
    jb_add(&j, ",\"uptime\":%llu,\"role\":\"%s\"", (ull)((now - m->start_ms) / 1000),
           c->role == ROLE_HOTSPOT ? "hotspot" : "repeater");
    if (c->role == ROLE_HOTSPOT)
        jb_add(&j, ",\"rf_silent\":%s", mesh_rf_silent(m, now) ? "true" : "false");
    if (c->has_location)
        jb_add(&j, ",\"lat\":%.6f,\"lon\":%.6f", c->latitude, c->longitude);
    jb_add(&j, ",\"radio\":{\"freq\":%.3f,\"bw\":%g,\"sf\":%u,\"cr\":%u,\"tx_power\":%d}",
           c->frequency, c->bandwidth, c->spreading_factor, c->coding_rate, c->tx_power);
    jb_add(&j, ",\"rx\":{\"total\":%llu,\"dup\":%llu,\"bad\":%llu,\"crc_err\":%llu,"
               "\"hdr_err\":%llu,\"adverts\":%llu,\"adverts_bad\":%llu}",
           (ull)s->rx_total, (ull)s->rx_dup, (ull)s->rx_bad_parse, (ull)s->rx_crc_err,
           (ull)s->rx_hdr_err, (ull)s->rx_advert, (ull)s->rx_advert_bad);
    jb_add(&j, ",\"fwd\":{\"flood\":%llu,\"direct\":%llu,\"dropped\":%llu,\"denied\":%llu,"
               "\"grp_public\":%llu,\"region\":%llu}",
           (ull)s->fwd_flood, (ull)s->fwd_direct, (ull)s->fwd_dropped, (ull)s->fwd_denied,
           (ull)s->fwd_grp_public, (ull)s->fwd_region);
    jb_add(&j, ",\"tx\":{\"total\":%llu,\"failed\":%llu,\"cad_busy\":%llu,\"queue_full\":%llu,"
               "\"radio_resets\":%llu,\"adverts\":%llu}",
           (ull)s->tx_total, (ull)s->tx_failed, (ull)s->tx_cad_busy, (ull)s->tx_queue_full,
           (ull)s->radio_resets, (ull)s->adverts_sent);
    jb_add(&j, ",\"airtime_ms\":{\"tx\":%llu,\"rx\":%llu}", (ull)s->tx_airtime_ms, (ull)s->rx_airtime_ms);
    jb_add(&j, ",\"neighbours\":%d", mesh_neighbor_count(m));
    jb_add(&j, ",\"backbone\":{\"observed\":%llu,\"offered\":%llu,\"injected\":%llu,"
               "\"limited\":%llu,\"rejected\":%llu}}",
           (ull)bb->observed, (ull)bb->offered, (ull)bb->injected, (ull)bb->limited,
           (ull)bb->rejected);
    if (j.full) {
        log_warn("backbone: status report too large, not sent");
        return;
    }
    send_session(bb, BB_T_STATUS, (const uint8_t *)buf, j.len);
}

/* One neighbour as a JSON object into out; returns its length (0 if it won't fit). */
static size_t neighbour_json(const mesh_neighbor_t *n, uint32_t now_s, char *out, size_t cap)
{
    jbuf_t j = { out, cap, 0, false };
    char pub[MC_PUB_KEY_SIZE * 2 + 1];
    bin2hex(n->pub, MC_PUB_KEY_SIZE, pub, sizeof(pub));
    jb_add(&j, "{\"pub\":\"%s\",\"name\":", pub);
    jb_str(&j, n->name);
    jb_add(&j, ",\"type\":%u,\"hops\":%u,\"rssi\":%d,\"snr\":%.2f,\"age\":%u,\"count\":%u}",
           n->type, n->hops, n->rssi, n->snr_q / 4.0,
           now_s > n->last_seen ? now_s - n->last_seen : 0, n->count);
    return j.full ? 0 : j.len;
}

#define BB_PAGE_WRAP 48   /* {"page":NN,"pages":NN,"list":[ ... ]} */

static void send_neighbours(mc_backbone *bb)
{
    const mc_mesh_t *m = bb->mesh;
    if (!m)
        return;
    uint32_t now_s = (uint32_t)time(NULL);
    const size_t budget = BB_STATUS_JSON - BB_PAGE_WRAP;
    char ent[512];                    /* a 31-char name of control bytes escapes to ~190 */

    /* pass 1: count the pages (greedy) */
    int pages = 1;
    size_t used = 0;
    for (int i = 0; i < MESH_MAX_NEIGHBORS; i++) {
        if (!m->neighbors[i].used) continue;
        size_t el = neighbour_json(&m->neighbors[i], now_s, ent, sizeof(ent));
        if (el == 0) continue;
        if (used && used + 1 + el > budget) { pages++; used = 0; }
        used += (used ? 1 : 0) + el;
    }

    /* pass 2: build and send them, back to back */
    char buf[BB_STATUS_JSON + 1];
    jbuf_t j = { buf, sizeof(buf), 0, false };
    int page = 1;
    used = 0;
    jb_add(&j, "{\"page\":%d,\"pages\":%d,\"list\":[", page, pages);
    for (int i = 0; i < MESH_MAX_NEIGHBORS; i++) {
        if (!m->neighbors[i].used) continue;
        size_t el = neighbour_json(&m->neighbors[i], now_s, ent, sizeof(ent));
        if (el == 0) continue;
        if (used && used + 1 + el > budget) {
            jb_add(&j, "]}");
            send_session(bb, BB_T_NEIGHBOURS, (const uint8_t *)buf, j.len);
            j.len = 0;
            used = 0;
            jb_add(&j, "{\"page\":%d,\"pages\":%d,\"list\":[", ++page, pages);
        }
        jb_add(&j, "%s%s", used ? "," : "", ent);
        used += (used ? 1 : 0) + el;
    }
    jb_add(&j, "]}");
    if (!j.full)
        send_session(bb, BB_T_NEIGHBOURS, (const uint8_t *)buf, j.len);
}

/* ---- incoming datagrams ---- */

static uint16_t clamp_iv(uint16_t v, uint16_t lo, uint16_t hi, uint16_t def)
{
    if (v == 0) return def;
    return v < lo ? lo : (v > hi ? hi : v);
}

static void on_welcome(mc_backbone *bb, uint64_t now, const uint8_t *d, size_t len)
{
    bb_welcome_t w;
    if (bb->state != BB_HELLO_SENT ||
        bb_check_welcome(d, len, bb->hub_pub, bb->hello_hash, bb->roles_asked, &w) != 0) {
        bb->rejected++;
        return;
    }
    uint8_t shared[32];
    crypto_scalarmult(shared, bb->eph_sec, w.eph_pub);
    int rc = bb_derive_keys(shared, bb->hello, bb->hello_len, d, len, bb->k_up, bb->k_down);
    memset(shared, 0, sizeof(shared));
    memset(bb->eph_sec, 0, sizeof(bb->eph_sec));
    if (rc != 0) {
        bb->rejected++;
        return;
    }
    bb->sid = w.sid;
    bb->roles = w.roles;
    bb->seq_out = 0;
    memset(&bb->rwin, 0, sizeof(bb->rwin));
    bb->keepalive_s  = clamp_iv(w.keepalive_s, 10, 120, 25);
    bb->status_s     = clamp_iv(w.status_s, 30, 3600, 60);
    bb->neighbours_s = clamp_iv(w.neighbours_s, 60, 65535, 300);
    bb->state = BB_UP;
    bb->sessions++;
    bb->backoff_s = 5;
    bb->up_since_ms = bb->last_rx_ms = now;
    bb->dgrams_in++;
    log_info("backbone: session %08x up with %s:%u, roles%s%s%s", (unsigned)bb->sid,
             bb->gai_host, bb->cfg->backbone_port,
             (bb->roles & BB_ROLE_OBSERVE) ? " observe" : "",
             (bb->roles & BB_ROLE_BRIDGE) ? " bridge" : "", bb->roles ? "" : " none");

    send_session(bb, BB_T_KEEPALIVE, NULL, 0);          /* confirms the session at the hub */
    bb->next_keepalive_ms = now + (uint64_t)bb->keepalive_s * 1000;
    if (bb->roles & BB_ROLE_OBSERVE) {
        send_status(bb, now);
        bb->next_status_ms = now + (uint64_t)bb->status_s * 1000;
        bb->next_neighbours_ms = now + 5000;
    }
}

static void on_reset(mc_backbone *bb, uint64_t now, const uint8_t *d, size_t len)
{
    /* cheap field checks before the signature check */
    if (bb->state != BB_UP || len != BB_RESET_LEN) { bb->rejected++; return; }
    uint32_t sid = rd_u32le(&d[4]), seq = rd_u32le(&d[8]), ts = rd_u32le(&d[12]);
    uint32_t now_s = (uint32_t)time(NULL);
    uint32_t skew = now_s > ts ? now_s - ts : ts - now_s;
    if (sid != bb->sid || seq == 0 || seq > bb->seq_out || bb->seq_out - seq >= 64 ||
        skew > BB_TS_WINDOW ||
        bb_check_reset(d, len, bb->hub_pub, &sid, &seq, &ts) != 0) {
        bb->rejected++;
        return;
    }
    log_info("backbone: hub reset session %08x - registering again", (unsigned)bb->sid);
    forget_session(bb);
    uint64_t earliest = bb->last_reset_ms ? bb->last_reset_ms + 5000 : now;
    bb->next_try_ms = earliest > now ? earliest : now;    /* at most once per 5 s */
    bb->last_reset_ms = now;
}

static void on_frame(mc_backbone *bb, uint64_t now, const uint8_t *body, size_t blen)
{
    if (!(bb->roles & BB_ROLE_BRIDGE) || blen < 10 || body[1] == 0 || 10u + body[1] > blen) {
        bb->rejected++;
        return;
    }
    const uint8_t *frame = &body[10];
    size_t flen = body[1];

    /* token bucket: refills at backbone_rate per minute, holds rate/3 (min 1) */
    uint32_t rate = bb->cfg->backbone_rate ? bb->cfg->backbone_rate : 1;
    double cap = (rate / 3) ? (double)(rate / 3) : 1.0;
    if (bb->tokens_ms == 0) {
        bb->tokens = cap;
    } else {
        bb->tokens += (double)(now - bb->tokens_ms) * rate / 60000.0;
        if (bb->tokens > cap) bb->tokens = cap;
    }
    bb->tokens_ms = now;

    bool room = !bb->mesh || mesh_txq_free(bb->mesh) >= BB_TXQ_HEADROOM;
    if (bb->tokens < 1.0 || !room) {
        bb->limited++;
        backbone_observe(bb, frame, flen, 0, 0, BB_OBS_FROM_BACKBONE, BB_DISP_LIMITED);
        return;
    }
    bb->tokens -= 1.0;
    int disp = bb->mesh ? mesh_on_backbone(bb->mesh, frame, flen) : MESH_RX_LOCAL;
    if (disp == MESH_RX_MALFORMED) {
        bb->rejected++;
        return;
    }
    bb->injected++;
    backbone_observe(bb, frame, flen, 0, 0, BB_OBS_FROM_BACKBONE, disp);
}

static void on_session(mc_backbone *bb, uint64_t now, const uint8_t *d, size_t len)
{
    uint8_t type;
    uint32_t sid, seq;
    const uint8_t *body;
    size_t blen;
    if (bb->state != BB_UP || len < BB_HDR + BB_MAC || rd_u32le(&d[4]) != bb->sid ||
        bb_open(d, len, bb->k_down, &type, &sid, &seq, &body, &blen) != 0 ||
        !bb_replay_check(&bb->rwin, seq)) {
        bb->rejected++;
        return;
    }
    bb->dgrams_in++;
    bb->last_rx_ms = now;
    switch (type) {
    case BB_T_KEEPALIVE_ACK:
        break;
    case BB_T_FRAME:
        on_frame(bb, now, body, blen);
        break;
    case BB_T_BYE_DOWN: {
        uint8_t reason = blen ? body[0] : BB_BYE_SHUTDOWN;
        if (reason == BB_BYE_NOT_ALLOWED) {
            log_warn("backbone: hub closed the session: not allowed (is this node's key "
                     "on the hub allowlist?) - retrying in %ds", BB_BACKOFF_MAX);
            forget_session(bb);
            bb->backoff_s = BB_BACKOFF_MAX;
            bb->next_try_ms = now + (uint64_t)BB_BACKOFF_MAX * 1000;
        } else {
            log_info("backbone: hub closed the session (reason %u) - retrying in %ds",
                     reason, bb->backoff_s);
            retry_later(bb, now);
        }
        break;
    }
    default:
        bb->rejected++;                                 /* authentic, but not ours to handle */
        break;
    }
}

static void read_datagrams(mc_backbone *bb, uint64_t now)
{
    for (int i = 0; i < BB_RX_BURST && bb->fd >= 0; i++) {
        uint8_t d[BB_MAX_DGRAM + 1];
        ssize_t r = recv(bb->fd, d, sizeof(d), 0);
        if (r < 0)
            return;                 /* EAGAIN, or a refused port (ICMP): timers cope */
        size_t len = (size_t)r;
        if (len > BB_MAX_DGRAM || len < 4 || d[0] != 'M' || d[1] != 'B' || d[2] != BB_VERSION) {
            bb->rejected++;
            continue;
        }
        if (d[3] == BB_T_WELCOME)                      on_welcome(bb, now, d, len);
        else if (d[3] == BB_T_RESET)                   on_reset(bb, now, d, len);
        else if (d[3] >= 0x20 && d[3] <= 0x2F)         on_session(bb, now, d, len);
        else                                           bb->rejected++;
    }
}

/* ---- public ---- */

int backbone_init(mc_backbone *bb, const mc_config_t *cfg, const mc_identity_t *id,
                  struct mc_mesh *mesh)
{
    memset(bb, 0, sizeof(*bb));
    bb->cfg = cfg;
    bb->id = id;
    bb->mesh = mesh;
    bb->fd = -1;
    bb->state = BB_OFF;
    bb->backoff_s = 5;
    if (!cfg->backbone_enable)
        return 0;
    if (!cfg->backbone_have_hub_key) {
        log_err("backbone: needs backbone_hub_key (the hub's Ed25519 public key, 64 hex) - backbone off");
        return -1;
    }
    if (cfg->backbone_host[0] == '\0' || cfg->backbone_port == 0) {
        log_err("backbone: needs backbone_host and backbone_port - backbone off");
        return -1;
    }
    memcpy(bb->hub_pub, cfg->backbone_hub_key, 32);
    bb->roles_asked = (uint8_t)((cfg->backbone_observe ? BB_ROLE_OBSERVE : 0) |
                                (cfg->backbone_bridge ? BB_ROLE_BRIDGE : 0));
    char hex[MC_PUB_KEY_SIZE * 2 + 1];
    bin2hex(id->pub, MC_PUB_KEY_SIZE, hex, sizeof(hex));
    log_info("backbone: enabled -> %s:%u, roles%s%s%s", cfg->backbone_host, cfg->backbone_port,
             cfg->backbone_observe ? " observe" : "", cfg->backbone_bridge ? " bridge" : "",
             bb->roles_asked ? "" : " none");
    log_info("backbone: node key %s (the hub allowlists this)", hex);
    bb->state = BB_IDLE;
    bb->next_try_ms = hal_millis();
    return 0;
}

void backbone_close(mc_backbone *bb)
{
    if (bb->state == BB_UP) {
        uint8_t reason = BB_BYE_SHUTDOWN;
        send_session(bb, BB_T_BYE, &reason, 1);
    }
    if (bb->gai_busy && gai_cancel(&bb->gai) == EAI_CANCELED)
        bb->gai_busy = false;          /* a lookup that can't be cancelled is left to finish */
    forget_session(bb);
    bb->state = BB_OFF;
}

int backbone_pollfd(const mc_backbone *bb)
{
    return (bb->state == BB_HELLO_SENT || bb->state == BB_UP) ? bb->fd : -1;
}

void backbone_service(mc_backbone *bb, uint64_t now)
{
    switch (bb->state) {
    case BB_OFF:
        return;
    case BB_IDLE:
        if (now >= bb->next_try_ms)
            start_attempt(bb, now);
        break;
    case BB_RESOLVING:
        check_resolved(bb, now);
        break;
    default:
        break;
    }

    if (bb->fd >= 0)
        read_datagrams(bb, now);

    if (bb->state == BB_HELLO_SENT && now >= bb->deadline_ms) {
        if (bb->hello_tries < BB_HELLO_TRIES) {
            send_hello(bb, now);
        } else {
            log_info("backbone: no WELCOME from %s after %d HELLOs (hub down, or this node "
                     "not on its allowlist?) - retrying in %ds", bb->gai_host, BB_HELLO_TRIES,
                     bb->backoff_s);
            retry_later(bb, now);
        }
    }

    if (bb->state != BB_UP)
        return;
    if (now - bb->last_rx_ms > (uint64_t)(3 * bb->keepalive_s + 5) * 1000) {
        log_warn("backbone: nothing from the hub for %ds - session %08x lost, reconnecting",
                 3 * bb->keepalive_s + 5, (unsigned)bb->sid);
        forget_session(bb);
        bb->next_try_ms = now;
        return;
    }
    if (bb->seq_out >= 0x80000000u) {                   /* new keys long before seq wraps */
        uint8_t reason = BB_BYE_REKEY;
        send_session(bb, BB_T_BYE, &reason, 1);
        forget_session(bb);
        bb->next_try_ms = now;
        return;
    }
    if (now >= bb->next_keepalive_ms) {
        send_session(bb, BB_T_KEEPALIVE, NULL, 0);
        bb->next_keepalive_ms = now + (uint64_t)bb->keepalive_s * 1000;
    }
    if (bb->roles & BB_ROLE_OBSERVE) {
        if (now >= bb->next_status_ms) {
            send_status(bb, now);
            bb->next_status_ms = now + (uint64_t)bb->status_s * 1000;
        }
        if (now >= bb->next_neighbours_ms) {
            send_neighbours(bb);
            bb->next_neighbours_ms = now + (uint64_t)bb->neighbours_s * 1000;
        }
    }
}

void backbone_observe(mc_backbone *bb, const uint8_t *frame, size_t len,
                      int16_t rssi, int8_t snr_q, uint8_t flags, int disposition)
{
    if (!bb || bb->state != BB_UP || !(bb->roles & BB_ROLE_OBSERVE))
        return;
    if (disposition < 0 || disposition > BB_DISP_LIMITED || len == 0 || len > BB_MAX_FRAME)
        return;
    mc_packet_t p;
    if (pkt_parse(&p, frame, len) != 0)
        return;
    uint8_t body[14 + BB_MAX_FRAME];
    body[0] = flags;
    body[1] = (uint8_t)disposition;
    wr_u16le(&body[2], (uint16_t)rssi);
    body[4] = (uint8_t)snr_q;
    body[5] = (uint8_t)len;
    pkt_calc_hash(&p, &body[6]);
    memcpy(&body[14], frame, len);
    send_session(bb, BB_T_OBSERVE, body, 14 + len);
    bb->observed++;
}

void backbone_status_soon(mc_backbone *bb)
{
    if (bb && bb->state == BB_UP)
        bb->next_status_ms = 0;
}

void backbone_offer(mc_backbone *bb, const uint8_t *frame, size_t len, bool own)
{
    if (!bb || bb->state != BB_UP || !(bb->roles & BB_ROLE_BRIDGE))
        return;
    if (len == 0 || len > BB_MAX_FRAME)
        return;
    mc_packet_t p;
    if (pkt_parse(&p, frame, len) != 0)
        return;
    if (pkt_is_route_direct(&p) && pkt_path_hash_count(&p) == 0)
        return;                                         /* zero-hop: nowhere to route it */
    uint8_t body[10 + BB_MAX_FRAME];
    body[0] = own ? BB_BRIDGE_OWN : 0;
    body[1] = (uint8_t)len;
    pkt_calc_hash(&p, &body[2]);
    memcpy(&body[10], frame, len);
    send_session(bb, BB_T_BRIDGE, body, 10 + len);
    bb->offered++;
}
