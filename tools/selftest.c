/*
 * selftest.c - host-side unit tests for the protocol core.
 *
 * Validates the interop-critical pieces with no radio: header bit packing,
 * wire (de)serialisation, path encoding/append, dedup hashing, Ed25519
 * sign/verify, advert build/verify/extract, and the mesh flood/direct
 * forwarding decisions. Exits non-zero on any failure.
 */
#include "../src/packet.h"
#include "../src/identity.h"
#include "../src/advert.h"
#include "../src/mesh.h"
#include "../src/config.h"
#include "../src/sx126x.h"
#include "../src/util.h"
#include "../src/hmac_sha256.h"
#include "../src/aprs.h"
#include "../src/aprsis.h"
#include "../src/crypto/sha256.h"
#include "../src/crypto/aes128.h"
#include "../src/monitor.h"
#include "../src/link.h"
#include "../src/backbone.h"
#include "../src/crypto/tweetnacl.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

void randombytes(unsigned char *x, unsigned long long xlen);

static int g_fail = 0;
#define CHECK(cond, ...) do { \
    if (cond) { printf("  ok   : " __VA_ARGS__); printf("\n"); } \
    else { printf("  FAIL : " __VA_ARGS__); printf("\n"); g_fail++; } \
} while (0)

static void test_header(void)
{
    printf("[header bit packing]\n");
    uint8_t h = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD);
    CHECK(h == 0x11, "advert flood header == 0x11 (got 0x%02X)", h);

    mc_packet_t p = {0};
    p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT);
    CHECK(pkt_route_type(&p) == ROUTE_TYPE_DIRECT, "route type round-trips");
    CHECK(pkt_payload_type(&p) == PAYLOAD_TYPE_TXT_MSG, "payload type round-trips");
    CHECK(pkt_payload_ver(&p) == PAYLOAD_VER_1, "payload version round-trips");
    CHECK(pkt_is_route_direct(&p) && !pkt_is_route_flood(&p), "direct classified");
}

static void test_pathlen(void)
{
    printf("[path_len encoding]\n");
    mc_packet_t p = {0};
    p.path_len = 0x45; /* 5 hops, 2-byte hashes */
    CHECK(pkt_path_hash_count(&p) == 5, "0x45 -> 5 hops");
    CHECK(pkt_path_hash_size(&p) == 2, "0x45 -> hash size 2");
    CHECK(pkt_path_byte_len(&p) == 10, "0x45 -> 10 path bytes");
    CHECK(pkt_valid_path_len(0x8A), "0x8A valid (10x3)");
    CHECK(!pkt_valid_path_len(0xC0), "0xC0 invalid (hash size 4)");
    pkt_set_path_hash_count(&p, 6);
    CHECK(pkt_path_hash_count(&p) == 6 && pkt_path_hash_size(&p) == 2,
          "set count preserves hash size");
}

static void test_serialize(void)
{
    printf("[wire serialise/parse round-trip]\n");
    mc_packet_t p = {0};
    p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD);
    p.path_len = 0x03;          /* 3 hops x 1 byte */
    p.path[0] = 0xAA; p.path[1] = 0xBB; p.path[2] = 0xCC;
    const char *msg = "hello mesh";
    p.payload_len = (uint16_t)strlen(msg);
    memcpy(p.payload, msg, p.payload_len);

    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&p, raw, sizeof(raw));
    CHECK(n == 1 + 1 + 3 + (int)strlen(msg), "raw length correct (got %d)", n);
    /* expected: header, path_len, path(3), payload */
    CHECK(raw[0] == p.header && raw[1] == 0x03 && raw[2] == 0xAA,
          "first bytes laid out correctly");

    mc_packet_t q = {0};
    int rc = pkt_parse(&q, raw, (size_t)n);
    CHECK(rc == 0, "parse succeeds");
    CHECK(q.header == p.header && q.path_len == p.path_len, "header/path_len match");
    CHECK(q.payload_len == p.payload_len &&
          memcmp(q.payload, p.payload, p.payload_len) == 0, "payload matches");
    CHECK(memcmp(q.path, p.path, 3) == 0, "path matches");
}

static void test_transport_codes(void)
{
    printf("[transport codes presence]\n");
    mc_packet_t p = {0};
    p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_TRANSPORT_FLOOD);
    p.transport_codes[0] = 0x1234;
    p.transport_codes[1] = 0xABCD;
    p.path_len = 0;
    p.payload_len = 4;
    memcpy(p.payload, "data", 4);

    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&p, raw, sizeof(raw));
    CHECK(n == 1 + 4 + 1 + 0 + 4, "transport packet raw len (got %d)", n);
    CHECK(raw[1] == 0x34 && raw[2] == 0x12, "transport_code[0] little-endian");

    mc_packet_t q = {0};
    CHECK(pkt_parse(&q, raw, (size_t)n) == 0, "parse transport packet");
    CHECK(q.transport_codes[0] == 0x1234 && q.transport_codes[1] == 0xABCD,
          "transport codes round-trip");
}

static void test_identity(void)
{
    printf("[Ed25519 identity]\n");
    mc_identity_t id;
    mc_identity_generate(&id);
    CHECK(id.has_secret, "keypair generated");

    const uint8_t *m = (const uint8_t *)"the quick brown fox";
    size_t mlen = 19;
    uint8_t sig[MC_SIGNATURE_SIZE];
    CHECK(mc_identity_sign(&id, sig, m, mlen) == 0, "sign ok");
    CHECK(mc_identity_verify(id.pub, sig, m, mlen), "verify ok");

    sig[0] ^= 0x01;
    CHECK(!mc_identity_verify(id.pub, sig, m, mlen), "tampered signature rejected");
    sig[0] ^= 0x01;
    uint8_t badmsg[19]; memcpy(badmsg, m, 19); badmsg[0] ^= 0x01;
    CHECK(!mc_identity_verify(id.pub, sig, badmsg, mlen), "tampered message rejected");
}

static void test_advert(void)
{
    printf("[advert build/verify/extract]\n");
    mc_identity_t id;
    mc_identity_generate(&id);

    mc_advert_info_t info = { .type = ADV_TYPE_REPEATER, .has_location = false,
                              .name = "ON0TEST" };
    mc_packet_t p;
    CHECK(mc_advert_build(&p, &id, &info, 0x60000000) == 0, "advert built");
    CHECK(pkt_payload_type(&p) == PAYLOAD_TYPE_ADVERT, "type is ADVERT");
    CHECK(pkt_route_type(&p) == ROUTE_TYPE_FLOOD, "route is FLOOD");

    uint8_t pub[MC_PUB_KEY_SIZE];
    CHECK(mc_advert_verify(&p, pub), "advert signature verifies");
    CHECK(memcmp(pub, id.pub, MC_PUB_KEY_SIZE) == 0, "advertised pubkey matches");

    uint8_t type = 0; char name[32];
    mc_advert_extract(&p, &type, name, sizeof(name));
    CHECK(type == ADV_TYPE_REPEATER, "extracted type REPEATER");
    CHECK(strcmp(name, "ON0TEST") == 0, "extracted name '%s'", name);

    /* tamper the signature byte -> verify must fail */
    p.payload[36] ^= 0xFF;
    CHECK(!mc_advert_verify(&p, pub), "forged advert rejected");
}

/* Build a GRP_TXT packet on cfg's first public channel with a valid MAC. */
static void make_public_grp(const mc_config_t *cfg, uint8_t route, mc_packet_t *p)
{
    static const uint8_t ct[16] = "grouptext-12345";   /* stand-in ciphertext */
    uint8_t mac[32];
    hmac_sha256(cfg->public_channels[0].secret, 32, ct, sizeof(ct), mac);

    memset(p, 0, sizeof(*p));
    p->header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, route);
    p->payload[0] = cfg->public_channels[0].hash;   /* channel selector (0x11 for Public) */
    p->payload[1] = mac[0];
    p->payload[2] = mac[1];
    memcpy(&p->payload[3], ct, sizeof(ct));
    p->payload_len = 3 + sizeof(ct);                /* 19 */
}

static void test_mesh_flood(void)
{
    printf("[mesh flood forwarding + dedup]\n");
    mc_identity_t id;
    mc_identity_generate(&id);
    mc_config_t cfg;
    config_defaults(&cfg);
    CHECK(config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==") == 0 &&
          cfg.n_public_channels == 1 && cfg.public_channels[0].hash == 0x11,
          "default Public channel configured (hash 0x11)");

    /* init radio (mock HAL) so airtime calc works */
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio);
    sx126x_init(&radio);

    mc_mesh_t mesh;
    mesh_init(&mesh, &id, &cfg);

    /* craft an inbound flood public-channel group message with one hop in path */
    mc_packet_t p;
    make_public_grp(&cfg, ROUTE_TYPE_FLOOD, &p);
    p.path_len = 0x01;          /* 1 hop, 1-byte hash */
    p.path[0] = 0x42;

    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&p, raw, sizeof(raw));

    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.fwd_flood == 1, "first copy forwarded (fwd_flood=%llu)",
          (unsigned long long)mesh.stats.fwd_flood);
    CHECK(mesh.stats.fwd_grp_public == 1, "counted as a public-channel forward");

    /* the queued packet should have our hash appended as a 2nd hop */
    int found = -1;
    for (int i = 0; i < MESH_TXQ_SIZE; i++) if (mesh.txq[i].used) { found = i; break; }
    CHECK(found >= 0, "packet enqueued for TX");
    if (found >= 0) {
        mc_packet_t *q = &mesh.txq[found].pkt;
        CHECK(pkt_path_hash_count(q) == 2, "hop count incremented to 2");
        CHECK(q->path[0] == 0x42 && q->path[1] == id.pub[0],
              "our path hash (0x%02X) appended", id.pub[0]);
    }

    /* a duplicate must be dropped */
    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.rx_dup == 1, "duplicate dropped (rx_dup=%llu)",
          (unsigned long long)mesh.stats.rx_dup);
    CHECK(mesh.stats.fwd_flood == 1, "duplicate not re-forwarded");
}

static void test_mesh_direct(void)
{
    printf("[mesh direct forwarding]\n");
    mc_identity_t id;
    mc_identity_generate(&id);
    mc_config_t cfg;
    config_defaults(&cfg);
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);

    /* direct public-channel packet whose first path hash is us, then downstream */
    mc_packet_t p;
    make_public_grp(&cfg, ROUTE_TYPE_DIRECT, &p);
    p.path_len = 0x02;          /* 2 hops, 1-byte */
    p.path[0] = id.pub[0];      /* us */
    p.path[1] = 0x99;           /* next hop */

    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&p, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);

    CHECK(mesh.stats.fwd_direct == 1, "direct packet forwarded (fwd_direct=%llu)",
          (unsigned long long)mesh.stats.fwd_direct);
    int found = -1;
    for (int i = 0; i < MESH_TXQ_SIZE; i++) if (mesh.txq[i].used) { found = i; break; }
    if (found >= 0) {
        mc_packet_t *q = &mesh.txq[found].pkt;
        CHECK(pkt_path_hash_count(q) == 1 && q->path[0] == 0x99,
              "self stripped, next hop now at path[0]");
    }
}

static void test_mesh_policy(void)
{
    printf("[mesh strict public-only content policy]\n");
    mc_identity_t id; mc_identity_generate(&id);
    mc_config_t cfg; config_defaults(&cfg);
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n;

    /* 1. a private direct message must be dropped */
    mc_packet_t dm = {0};
    dm.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD);
    dm.payload_len = 20;
    memcpy(dm.payload, "a-private-direct-msg", 20);
    n = pkt_serialize(&dm, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.fwd_flood == 0 && mesh.stats.fwd_denied_dm == 1,
          "private DM dropped (denied_dm=%llu)", (unsigned long long)mesh.stats.fwd_denied_dm);

    /* 2. a group message on an UNKNOWN channel must be dropped */
    mc_packet_t g = {0};
    g.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_FLOOD);
    g.payload[0] = 0x77;                 /* not the Public 0x11 */
    memset(&g.payload[1], 0xAB, 18);
    g.payload_len = 19;
    n = pkt_serialize(&g, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.fwd_denied_grp == 1 && mesh.stats.fwd_flood == 0,
          "group msg on unconfigured channel dropped");

    /* 3. Public channel hash but a corrupted MAC must be dropped (mac-fail) */
    mc_packet_t b;
    make_public_grp(&cfg, ROUTE_TYPE_FLOOD, &b);
    b.payload[1] ^= 0xFF;                /* break the MAC deterministically */
    n = pkt_serialize(&b, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.grp_mac_fail == 1 && mesh.stats.fwd_flood == 0,
          "public-hash + bad MAC dropped (mac-fail)");

    /* 4. an unknown / non-allow-listed payload type must be dropped */
    mc_packet_t u = {0};
    u.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_CONTROL, ROUTE_TYPE_FLOOD);
    u.payload_len = 10;
    memset(u.payload, 1, 10);
    n = pkt_serialize(&u, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.fwd_denied_other == 1, "control/unknown type dropped");

    CHECK(mesh.stats.fwd_flood == 0 && mesh.stats.fwd_grp_public == 0,
          "nothing forwarded under strict policy in this test");
    CHECK(mesh.stats.fwd_denied == 4, "all four packets counted as denied");
}

/* Build an encrypted public GRP_TXT carrying `text` (as MeshCore would). */
static void build_public_text(const mc_config_t *cfg, const char *text, mc_packet_t *p)
{
    const mc_pub_channel_t *ch = &cfg->public_channels[0];
    uint8_t plain[64];
    size_t i = 0;
    plain[0] = 1; plain[1] = 2; plain[2] = 3; plain[3] = 4; i = 4;  /* timestamp */
    plain[i++] = 0;                                                 /* txt_type */
    size_t tl = strlen(text);
    memcpy(&plain[i], text, tl); i += tl;
    size_t ctlen = (i + 15) & ~(size_t)15;
    while (i < ctlen) plain[i++] = 0;

    aes128_ctx_t ac; aes128_init(&ac, ch->secret);
    aes128_ecb_encrypt(&ac, plain, ctlen);

    memset(p, 0, sizeof(*p));
    p->header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_FLOOD);
    p->payload[0] = ch->hash;
    uint8_t mac[32]; hmac_sha256(ch->secret, 32, plain, ctlen, mac);
    p->payload[1] = mac[0]; p->payload[2] = mac[1];
    memcpy(&p->payload[3], plain, ctlen);
    p->payload_len = (uint16_t)(3 + ctlen);
}

static void test_ping_pong(void)
{
    printf("[public channel ping/pong]\n");
    mc_identity_t id; mc_identity_generate(&id);
    mc_config_t cfg; config_defaults(&cfg);
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    cfg.ping_pong = true;
    cfg.ping_channel[0] = '\0';            /* answer on any channel (test the mechanism) */
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    uint8_t raw[MC_MAX_TRANS_UNIT];

    /* a "ping" on the public channel triggers a "pong" */
    mc_packet_t ping;
    build_public_text(&cfg, "Alice: ping", &ping);
    int n = pkt_serialize(&ping, raw, sizeof(raw));
    uint64_t rx_at = hal_millis();
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);
    CHECK(mesh.stats.ping_seen == 1 && mesh.stats.pong_sent == 1, "ping seen -> pong sent");
    CHECK(mesh.stats.fwd_grp_public == 1, "the ping itself was forwarded (public)");

    /* the enqueued pong must decrypt to '<name>: pong' on the same channel */
    int found = -1;
    for (int k = 0; k < MESH_TXQ_SIZE; k++)
        if (mesh.txq[k].used && pkt_payload_type(&mesh.txq[k].pkt) == PAYLOAD_TYPE_GRP_TXT) { found = k; break; }
    CHECK(found >= 0, "pong enqueued for TX");
    if (found >= 0) {
        CHECK(mesh.txq[found].due_ms >= rx_at + MESH_REPLY_DELAY_MS,
              "pong held >= %d ms so the pinger is back in RX", MESH_REPLY_DELAY_MS);
        CHECK(mesh.txq[found].due_ms <= hal_millis() + MESH_REPLY_DELAY_MS + 150,
              "pong goes out within %d ms (no long back-off)", MESH_REPLY_DELAY_MS + 150);
        mc_packet_t *q = &mesh.txq[found].pkt;
        const mc_pub_channel_t *ch = &cfg.public_channels[0];
        size_t ctl = (size_t)q->payload_len - 3;
        uint8_t mac[32]; hmac_sha256(ch->secret, 32, &q->payload[3], ctl, mac);
        CHECK(q->payload[0] == ch->hash && mac[0] == q->payload[1] && mac[1] == q->payload[2],
              "pong is a valid public-channel packet (hash + MAC)");
        uint8_t dec[64]; memcpy(dec, &q->payload[3], ctl);
        aes128_ctx_t ac; aes128_init(&ac, ch->secret);
        aes128_ecb_decrypt(&ac, dec, ctl); dec[ctl] = 0;
        /* ping was heard at rssi -70, snr_q 20 (= 5.0 dB) */
        CHECK(strstr((const char *)&dec[5], ": pong rssi -70dBm snr 5.0dB") != NULL,
              "pong reports the ping's rssi/snr (got '%s')", (const char *)&dec[5]);
    }

    /* a non-ping public message must NOT trigger a pong */
    mc_mesh_t mesh2; mesh_init(&mesh2, &id, &cfg);
    mc_packet_t chat;
    build_public_text(&cfg, "Bob: hello world", &chat);
    n = pkt_serialize(&chat, raw, sizeof(raw));
    mesh_on_recv(&mesh2, raw, (size_t)n, -70, 20);
    CHECK(mesh2.stats.pong_sent == 0 && mesh2.stats.fwd_grp_public == 1,
          "non-ping public message forwarded, no pong");

    /* with ping_pong disabled, a ping is forwarded but not answered */
    mc_config_t cfg2; config_defaults(&cfg2);
    config_set(&cfg2, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    cfg2.ping_pong = false;
    mc_mesh_t mesh3; mesh_init(&mesh3, &id, &cfg2);
    build_public_text(&cfg2, "Al: ping", &chat);
    n = pkt_serialize(&chat, raw, sizeof(raw));
    mesh_on_recv(&mesh3, raw, (size_t)n, -70, 20);
    CHECK(mesh3.stats.pong_sent == 0, "ping_pong=off -> no pong");
}

/* The mock radio never raises TxDone, so every transmit times out - exactly a
 * wedged chip. One failure must be counted, drop the packet and reset the radio. */
static void test_tx_failure_resets_radio(void)
{
    printf("[a failed transmit resets the radio]\n");
    mc_identity_t id; mc_identity_generate(&id);
    mc_config_t cfg; config_defaults(&cfg);
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    cfg.ping_pong = true;
    cfg.ping_channel[0] = '\0';
    cfg.use_cad = false;                   /* straight to TX (mock CAD would time out too) */
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    uint8_t raw[MC_MAX_TRANS_UNIT];

    mc_packet_t ping;
    build_public_text(&cfg, "Al: ping", &ping);
    int n = pkt_serialize(&ping, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);
    int queued = 0;
    for (int k = 0; k < MESH_TXQ_SIZE; k++) queued += mesh.txq[k].used;

    mesh_service_tx(&mesh, hal_millis() + 60000);   /* first due packet; TX times out */
    int left = 0;
    for (int k = 0; k < MESH_TXQ_SIZE; k++) left += mesh.txq[k].used;
    CHECK(mesh.stats.tx_total == 0 && mesh.stats.tx_failed == 1,
          "timed-out transmit counted as failed, not sent");
    CHECK(mesh.stats.radio_resets == 1, "one failure -> the radio is reset");
    CHECK(left == queued - 1, "the failed packet is dropped, the rest stay queued");
}

/* Packets the radio heard but could not decode are counted and shown as drops. */
static void test_rx_errors(void)
{
    printf("[corrupt receptions are counted and monitored]\n");
    mc_identity_t id; mc_identity_generate(&id);
    mc_config_t cfg; config_defaults(&cfg);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    mc_monitor mon; monitor_init(&mon);
    mesh.mon = &mon;
    int q[2];
    if (pipe(q) != 0) { CHECK(0, "pipe() for rx-error test"); return; }
    monitor_add(&mon, dup(q[1]), "monitor drops");

    mesh_on_rx_error(&mesh, SX126X_RX_CRC_ERR, -118, -50);
    mesh_on_rx_error(&mesh, SX126X_RX_HDR_ERR, 0, 0);
    CHECK(mesh.stats.rx_crc_err == 1 && mesh.stats.rx_hdr_err == 1 && mesh.stats.rx_total == 0,
          "CRC + header errors counted apart from good packets");
    char buf[512]; ssize_t rr = read(q[0], buf, sizeof(buf) - 1);
    buf[rr > 0 ? rr : 0] = '\0';
    CHECK(strstr(buf, "CRC error (rssi -118 snr -12.5)") && strstr(buf, "corrupt LoRa header"),
          "both show in the drops monitor, the CRC error with its signal");
    for (int i = 0; i < mon.n; i++) close(mon.conn[i].fd);
    close(q[0]); close(q[1]);
}

static void test_ping_channel(void)
{
    printf("[ping restricted to the built-in #mesh channel]\n");
    mc_identity_t id; mc_identity_generate(&id);
    uint8_t raw[MC_MAX_TRANS_UNIT]; int n;

    /* config_load auto-ensures the #mesh channel even with no room line, and the
     * default ping_channel is #mesh */
    { const char *tmp = "/tmp/mc_ping_ensure.conf";
      FILE *f = fopen(tmp, "w"); if (f) { fputs("name = ON0TEST\n", f); fclose(f); }
      mc_config_t c; config_defaults(&c); config_load(&c, tmp);
      int has_mesh = 0;
      for (int i = 0; i < c.n_public_channels; i++)
          if (strcmp(c.public_channels[i].name, "#mesh") == 0) has_mesh = 1;
      CHECK(has_mesh && strcmp(c.ping_channel, "#mesh") == 0,
            "config_load ensures the #mesh ping channel (built in)");
      remove(tmp); }

    /* the no-file path of config_load also ensures #mesh */
    { mc_config_t c; config_defaults(&c);
      config_load(&c, "/nonexistent/does-not-exist.conf");   /* returns -1 */
      int has_mesh = 0;
      for (int i = 0; i < c.n_public_channels; i++)
          if (strcmp(c.public_channels[i].name, "#mesh") == 0) has_mesh = 1;
      CHECK(has_mesh, "config_load ensures #mesh even with no config file");
      /* a '#'-comment-stripped ping_channel value is rejected (keeps the default), not silently 'any' */
      CHECK(config_set(&c, "ping_channel", "") == -2 && strcmp(c.ping_channel, "#mesh") == 0,
            "empty ping_channel rejected, default #mesh kept"); }

    /* a "ping" ON #mesh is answered (ping_channel defaults to #mesh) */
    { mc_config_t cfg; config_defaults(&cfg);
      config_set(&cfg, "room", "mesh");             /* #mesh becomes public_channels[0] */
      sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "Bob: ping", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.stats.ping_seen == 1 && m.stats.pong_sent == 1, "ping on #mesh -> pong"); }

    /* a "ping" on a DIFFERENT channel is seen but NOT answered (ping moved to #mesh) */
    { mc_config_t cfg; config_defaults(&cfg);
      config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");  /* Public = [0], unnamed */
      config_set(&cfg, "room", "mesh");                                /* #mesh = [1] */
      sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "Bob: ping", &p);         /* on Public */
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.stats.ping_seen == 1 && m.stats.pong_sent == 0, "ping off the ping channel -> no pong"); }

    /* ping_channel round-trips through save/load ('#' is a comment in the file) */
    { mc_config_t a; config_defaults(&a);
      config_set(&a, "ping_channel", "test-chan");     /* -> "#test-chan" */
      const char *tmp = "/tmp/mc_pingch_rt.conf";
      config_save(&a, tmp);
      mc_config_t b; config_defaults(&b);
      config_load(&b, tmp);
      CHECK(strcmp(b.ping_channel, "#test-chan") == 0, "ping_channel survives save->load (bare in file)");
      config_set(&a, "ping_channel", "any"); config_save(&a, tmp);
      mc_config_t d; config_defaults(&d); config_load(&d, tmp);
      CHECK(d.ping_channel[0] == '\0', "ping_channel 'any' round-trips to answer-on-any");
      remove(tmp); }
}

static void test_probe(void)
{
    printf("[probe: authorised coverage/range test on #mesh]\n");
    mc_identity_t id; mc_identity_generate(&id);
    uint8_t raw[MC_MAX_TRANS_UNIT]; int n;

    /* authorisation: empty list = off; wildcard match otherwise */
    { mc_config_t c; config_defaults(&c);
      CHECK(!config_probe_allowed(&c, "OR7F-1"), "probe off by default (empty allow list)");
      config_set(&c, "probe_allow", "OR7F*");
      config_set(&c, "probe_allow", "ON6URE*");
      CHECK(config_probe_allowed(&c, "OR7F-3") && config_probe_allowed(&c, "ON6URE-1") &&
            !config_probe_allowed(&c, "ON4XYZ-2"), "probe_allow wildcard match"); }

    /* an authorised "probe 2 3" on #mesh starts a 3-probe run; service sends them */
    { mc_config_t cfg; config_defaults(&cfg);
      config_set(&cfg, "room", "mesh");                 /* #mesh = public_channels[0] */
      config_set(&cfg, "probe_allow", "OR7F*");
      sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "OR7F-1: probe 2 3", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.probe_remaining == 3, "authorised 'probe 2 3' -> 3 pending");
      uint64_t t0 = m.probe_next_ms;                    /* first probe is due at t0 */
      mesh_service_probe(&m, t0);
      CHECK(m.stats.probes_sent == 1 && m.probe_remaining == 2, "first probe sent when due");
      mesh_service_probe(&m, t0 + 1000);                /* 1s < 2s interval */
      CHECK(m.stats.probes_sent == 1, "second probe waits for the interval");
      mesh_service_probe(&m, t0 + 2000);                /* interval elapsed */
      CHECK(m.stats.probes_sent == 2 && m.probe_remaining == 1, "next probe after the interval"); }

    /* an UNauthorised sender is ignored */
    { mc_config_t cfg; config_defaults(&cfg);
      config_set(&cfg, "room", "mesh"); config_set(&cfg, "probe_allow", "OR7F*");
      sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "ON4XYZ-2: probe 2 3", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.probe_remaining == 0, "unauthorised probe request ignored"); }

    /* count is clamped to the max */
    { mc_config_t cfg; config_defaults(&cfg);
      config_set(&cfg, "room", "mesh"); config_set(&cfg, "probe_allow", "OR7F*");
      sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "OR7F-1: probe 1 99999", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.probe_remaining == 100, "probe count clamped to the max (100)"); }

    /* probe_allow round-trips through save/load */
    { mc_config_t a; config_defaults(&a);
      config_set(&a, "probe_allow", "OR7F*"); config_set(&a, "probe_allow", "ON6URE*");
      const char *tmp = "/tmp/mc_probe_rt.conf"; config_save(&a, tmp);
      mc_config_t b; config_defaults(&b); config_load(&b, tmp);
      CHECK(b.n_probe_allow == 2 && config_probe_allowed(&b, "ON6URE-9"),
            "probe_allow survives save->load");
      remove(tmp); }
}

static void test_link(void)
{
    printf("[split RX/TX link: HMAC-authenticated UDP relay]\n");
    uint16_t port = (uint16_t)(45400 + (getpid() % 120));

    mc_config_t txcfg; config_defaults(&txcfg);
    config_set(&txcfg, "link_mode", "tx"); config_set(&txcfg, "link_key", "s3cret");
    txcfg.link_port = port;
    mc_link tx;
    CHECK(link_init(&tx, &txcfg) == 0 && tx.mode == LINK_TX, "tx link binds udp port");

    mc_config_t rxcfg; config_defaults(&rxcfg);
    config_set(&rxcfg, "link_mode", "rx"); config_set(&rxcfg, "link_key", "s3cret");
    config_set(&rxcfg, "link_peer", "127.0.0.1"); rxcfg.link_port = port;
    mc_link rx;
    CHECK(link_init(&rx, &rxcfg) == 0 && rx.mode == LINK_RX, "rx link resolves peer");

    CHECK(link_init(&(mc_link){0}, &(mc_config_t){0}) == 0, "off-mode link is a no-op");

    uint8_t frame[19]; for (int i = 0; i < 19; i++) frame[i] = (uint8_t)(0xA0 + i);
    uint8_t got[MC_MAX_TRANS_UNIT]; size_t glen = 0; int16_t grssi = 0; int8_t gsnr = 0;

    /* relay a frame; the tx side receives + authenticates it (poll loopback) */
    link_relay(&rx, frame, sizeof(frame), -73, 28);
    int n = 0;
    for (int t = 0; t < 100 && n == 0; t++) { n = link_recv(&tx, got, sizeof(got), &glen, &grssi, &gsnr); if (!n) usleep(2000); }
    CHECK(n == 1 && glen == 19 && memcmp(got, frame, 19) == 0 && grssi == -73 && gsnr == 28,
          "frame + rssi/snr relayed and authenticated");
    CHECK(rx.frames_out == 1 && tx.frames_in == 1, "link stats counted");

    /* a datagram signed with the WRONG key is rejected, not injected */
    mc_config_t badcfg; config_defaults(&badcfg);
    config_set(&badcfg, "link_mode", "rx"); config_set(&badcfg, "link_key", "wrong-key");
    config_set(&badcfg, "link_peer", "127.0.0.1"); badcfg.link_port = port;
    mc_link bad; link_init(&bad, &badcfg);
    uint64_t bad0 = tx.frames_bad, in0 = tx.frames_in;
    link_relay(&bad, frame, sizeof(frame), -73, 28);
    for (int t = 0; t < 100 && tx.frames_bad == bad0; t++) { link_recv(&tx, got, sizeof(got), &glen, &grssi, &gsnr); usleep(2000); }
    CHECK(tx.frames_bad == bad0 + 1 && tx.frames_in == in0, "wrong-key datagram rejected (not injected)");

    /* a missing key is a hard misconfiguration (mode forced off) */
    mc_config_t nk; config_defaults(&nk); config_set(&nk, "link_mode", "tx");
    mc_link no_key;
    CHECK(link_init(&no_key, &nk) == -1 && no_key.mode == LINK_OFF, "link_mode without link_key -> off");

    link_close(&tx); link_close(&rx); link_close(&bad);
}

static void test_blacklist(void)
{
    printf("[blacklist / moderation]\n");
    mc_config_t cfg; config_defaults(&cfg);

    /* config helpers */
    CHECK(config_blacklist_add(&cfg, "ON0XYZ") == 0 && cfg.n_blacklist == 1, "add ON0XYZ");
    CHECK(config_blacklist_add(&cfg, "on0xyz") == 1, "duplicate (case-insensitive) rejected");
    CHECK(config_is_blacklisted(&cfg, "ON0XYZ") && config_is_blacklisted(&cfg, "on0xyz"),
          "matches case-insensitively");
    CHECK(!config_is_blacklisted(&cfg, "ON0ABC"), "other name not blacklisted");
    CHECK(config_blacklist_remove(&cfg, "ON0XYZ") == 0 && cfg.n_blacklist == 0, "remove");
    CHECK(config_blacklist_remove(&cfg, "ON0XYZ") == -1, "remove missing -> not found");

    /* mesh application */
    mc_identity_t id; mc_identity_generate(&id);
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    config_blacklist_add(&cfg, "Spammer");
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    uint8_t raw[MC_MAX_TRANS_UNIT];

    mc_packet_t p;
    build_public_text(&cfg, "Spammer: spam spam", &p);
    int n = pkt_serialize(&p, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);
    CHECK(mesh.stats.blacklisted == 1 && mesh.stats.fwd_grp_public == 0 && mesh.stats.fwd_flood == 0,
          "blacklisted public sender dropped (not forwarded)");

    build_public_text(&cfg, "Friend: hi", &p);
    n = pkt_serialize(&p, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);
    CHECK(mesh.stats.fwd_grp_public == 1, "non-blacklisted sender forwarded");

    /* a signed advert from a blacklisted node is dropped (not registered) */
    mc_advert_info_t info; memset(&info, 0, sizeof(info));
    info.type = ADV_TYPE_REPEATER; info.name = "Spammer";
    mc_packet_t adv;
    mc_advert_build(&adv, &id, &info, 1000);
    n = pkt_serialize(&adv, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);
    CHECK(mesh.stats.blacklisted == 2 && mesh.stats.rx_advert == 0,
          "blacklisted advert dropped (not registered as neighbour)");
}

static void test_aprs(void)
{
    printf("[aprs: passcode, callsign filter, compressed position]\n");

    /* APRS-IS passcode known-answer vectors (aprslib) + this operator's call */
    CHECK(aprsis_passcode("N0CALL") == 13023, "passcode N0CALL=13023 (got %d)", aprsis_passcode("N0CALL"));
    CHECK(aprsis_passcode("TESTCALL") == 31742, "passcode TESTCALL=31742");
    CHECK(aprsis_passcode("SUCHCALL") == 27890, "passcode SUCHCALL=27890");
    CHECK(aprsis_passcode("WOW") == 29613, "passcode WOW=29613");
    CHECK(aprsis_passcode("ON6URE") == 22716 && aprsis_passcode("ON6URE-6") == 22716,
          "passcode ON6URE = ON6URE-6 = 22716 (SSID stripped)");

    /* callsign filter: gate only plausible ham calls, upper-cased */
    char cs[12];
    CHECK(aprsis_valid_callsign("ON6URE-6", cs, sizeof(cs)) && !strcmp(cs, "ON6URE-6"), "accept ON6URE-6");
    CHECK(aprsis_valid_callsign("on0xyz", cs, sizeof(cs)) && !strcmp(cs, "ON0XYZ"), "accept + upcase on0xyz");
    CHECK(aprsis_valid_callsign("W1AW", cs, sizeof(cs)) &&
          aprsis_valid_callsign("2E0ABC", cs, sizeof(cs)) &&
          aprsis_valid_callsign("DL1ABC-9", cs, sizeof(cs)), "accept W1AW / 2E0ABC / DL1ABC-9");
    CHECK(!aprsis_valid_callsign("HamRepeater", cs, sizeof(cs)), "reject HamRepeater");
    CHECK(!aprsis_valid_callsign("ROOM", cs, sizeof(cs)) &&
          !aprsis_valid_callsign("K3", cs, sizeof(cs)) &&
          !aprsis_valid_callsign("SENSOR3", cs, sizeof(cs)), "reject ROOM / K3 / SENSOR3");

    /* base-91 compressed position (worked example verified in the design workflow) */
    char pos[64];
    CHECK(aprs_make_position(pos, sizeof(pos), 51.2095, 2.9247, -1, -1, "Mn") == 0 &&
          !strcmp(pos, "M4XB$O69En  A"), "compressed position ON0XYZ (got '%s')", pos);
    CHECK(aprs_make_position(pos, sizeof(pos), 51.151987, 2.765479, -1, -1, "R&") == 0,
          "compressed iGate beacon position builds (got '%s')", pos);
}

static int first_used(mc_mesh_t *m) { for (int i = 0; i < MESH_TXQ_SIZE; i++) if (m->txq[i].used) return i; return -1; }
static int grp_slot(mc_mesh_t *m) { int s = -1; for (int i = 0; i < MESH_TXQ_SIZE; i++) if (m->txq[i].used && pkt_payload_type(&m->txq[i].pkt) == PAYLOAD_TYPE_GRP_TXT) s = i; return s; }
/* last enqueued GRP_TXT sent as a routed DIRECT packet (an mbox reply) */
static int direct_grp_slot(mc_mesh_t *m)
{
    int s = -1;
    for (int i = 0; i < MESH_TXQ_SIZE; i++) {
        mc_packet_t *q = &m->txq[i].pkt;
        if (m->txq[i].used && pkt_payload_type(q) == PAYLOAD_TYPE_GRP_TXT
            && pkt_route_type(q) == ROUTE_TYPE_DIRECT)
            s = i;
    }
    return s;
}

/* Decrypt an enqueued public GRP_TXT's "sender: text" into out (NUL-terminated). */
static void decrypt_grp(const mc_pub_channel_t *ch, const mc_packet_t *q, char *out, size_t outsz)
{
    size_t ctl = (size_t)q->payload_len - 3;
    uint8_t dec[128]; if (ctl > sizeof(dec)) ctl = sizeof(dec);
    memcpy(dec, &q->payload[3], ctl);
    aes128_ctx_t ac; aes128_init(&ac, ch->secret);
    aes128_ecb_decrypt(&ac, dec, ctl);
    size_t body = ctl > 5 ? ctl - 5 : 0;
    if (body >= outsz) body = outsz - 1;
    memcpy(out, &dec[5], body); out[body] = '\0';
}

static void test_mbox(void)
{
    printf("[#mbox mailbox: store @mentions, route fetch/help replies back]\n");
    mc_identity_t id; mc_identity_generate(&id);
    uint8_t raw[MC_MAX_TRANS_UNIT]; int n;

    /* --- unit: classify --- */
    { char ment[MC_MBOX_CALL]; const char *msg = NULL;
      CHECK(mbox_classify("@ON4ABC hello there", ment, sizeof(ment), &msg) == MBOX_MENTION
            && strcmp(ment, "ON4ABC") == 0 && strcmp(msg, "hello there") == 0, "classify @mention");
      CHECK(mbox_classify("fetch", ment, sizeof(ment), &msg) == MBOX_FETCH, "classify fetch");
      CHECK(mbox_classify("  fetch  ", ment, sizeof(ment), &msg) == MBOX_FETCH, "classify fetch (whitespace)");
      CHECK(mbox_classify("@ON4ABC", ment, sizeof(ment), &msg) == MBOX_OTHER, "@mention needs text -> other");
      CHECK(mbox_classify("hello", ment, sizeof(ment), &msg) == MBOX_OTHER, "plain text -> other (help)"); }

    /* --- unit: store + fetch format (base-call, SSID- and case-insensitive, oldest first) --- */
    { mc_mbox mb; mbox_init(&mb);
      mbox_store(&mb, "ON4ABC", "OR7F-1", "see you at 8", 1000);
      mbox_store(&mb, "ON4XYZ", "OR7F-1", "not for abc", 1001);
      mbox_store(&mb, "on4abc-5", "K1ABC", "second one", 1002);
      char out[160];
      int total = -1;
      int c = mbox_format_fetch(&mb, "ON4ABC-9", out, sizeof(out), &total);
      CHECK(c == 2 && total == 2 && strstr(out, "[OR7F-1] see you at 8") && strstr(out, "[K1ABC] second one")
            && !strstr(out, "not for abc"), "fetch matches base call (SSID/case-insensitive)");
      CHECK(mbox_format_fetch(&mb, "ON0NON", out, sizeof(out), &total) == 0 && total == 0,
            "fetch with no match -> 0 shown, 0 total");

      /* a buffer that holds exactly one entry: shown(1) < total(2), and the second
       * (overflowing) entry is backed out whole - never truncated mid-message */
      char small[30];
      int st = -1;
      int sh = mbox_format_fetch(&mb, "ON4ABC", small, sizeof(small), &st);
      CHECK(st == 2 && sh == 1, "buffer full -> shown(1) < total(2), honest count");
      CHECK(strstr(small, "see you at 8") && !strstr(small, "second one"),
            "only the whole first entry is written, the overflow is backed out (got '%s')", small); }

    /* --- runtime `set mbox on` must register the #mbox channel (no reload) --- */
    { mc_config_t c; config_defaults(&c);
      config_set(&c, "mbox", "on");
      int has = 0;
      for (int i = 0; i < c.n_public_channels; i++)
          if (strcmp(c.public_channels[i].name, "#mbox") == 0) has = 1;
      CHECK(c.mbox_enable && has, "set mbox on registers #mbox immediately (runtime toggle works)"); }

    /* --- integration on the REPEATER --- */
    mc_config_t cfg; config_defaults(&cfg);
    config_set(&cfg, "name", "ON0RPT");
    config_set(&cfg, "room", "mbox");        /* #mbox derived channel = public_channels[0] */
    config_set(&cfg, "mbox", "on");
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    const mc_pub_channel_t *mbch = &cfg.public_channels[0];
    CHECK(strcmp(mbch->name, "#mbox") == 0 && cfg.mbox_enable, "#mbox registered + mailbox enabled");

    /* 1. an @mention is stored AND still floods to the network */
    mc_mesh_t m; mesh_init(&m, &id, &cfg);
    { mc_packet_t p; build_public_text(&cfg, "OR7F-1: @ON4ABC ping me back", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.stats.mbox_stored == 1 && m.mbox.count == 1, "@mention stored");
      CHECK(m.stats.fwd_grp_public == 1 && m.stats.fwd_flood == 1, "@mention still floods to the network");
      CHECK(direct_grp_slot(&m) < 0, "no reply is sent for an @mention"); }

    /* 2. a directly-heard "fetch" -> a zero-hop reply carrying the mailbox; NOT re-flooded */
    { uint64_t flood0 = m.stats.fwd_flood;
      mc_packet_t f; build_public_text(&cfg, "ON4ABC-9: fetch", &f);
      n = pkt_serialize(&f, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.stats.mbox_replies == 1, "fetch -> one reply");
      CHECK(m.stats.fwd_flood == flood0, "the fetch command is NOT re-flooded");
      int s = direct_grp_slot(&m);
      CHECK(s >= 0, "reply enqueued as a routed DIRECT packet");
      if (s >= 0) {
          mc_packet_t *q = &m.txq[s].pkt;
          CHECK(pkt_route_type(q) == ROUTE_TYPE_DIRECT && pkt_path_hash_count(q) == 0,
                "reply to a directly-heard fetch is a zero-hop DIRECT packet");
          char body[128]; decrypt_grp(mbch, q, body, sizeof(body));
          CHECK(strstr(body, "mbox 1: [OR7F-1] ping me back") != NULL,
                "reply carries the fetcher's mailbox (got '%s')", body); } }

    /* 2b. a nameless command (plaintext has no "sender: " prefix -> sender "") is NOT
     *     answered: an empty sender must not bypass the per-sender rate gate */
    { mc_mesh_t mn; mesh_init(&mn, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "fetch", &p);   /* no "name: " -> sender "" */
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&mn, raw, (size_t)n, -60, 24);
      CHECK(mn.stats.mbox_replies == 0 && direct_grp_slot(&mn) < 0,
            "a nameless fetch is not answered (empty sender can't bypass the gate)"); }

    /* 3. reverse-path routing: a fetch that arrived via hops [A(near source), B(near us)]
     *    is answered along the reverse [B, A] (path[0] = the hop closest to us) */
    { mc_mesh_t m2; mesh_init(&m2, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "OR7F-1: @ON4ABC hi", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&m2, raw, (size_t)n, -60, 24);
      mc_packet_t f; build_public_text(&cfg, "ON4ABC-9: fetch", &f);
      f.path_len = 0x02; f.path[0] = 0xA1; f.path[1] = 0xB2;   /* [H1=A1, H2=B2] */
      n = pkt_serialize(&f, raw, sizeof(raw)); mesh_on_recv(&m2, raw, (size_t)n, -60, 24);
      int s = direct_grp_slot(&m2);
      CHECK(s >= 0, "routed reply enqueued");
      if (s >= 0) {
          mc_packet_t *q = &m2.txq[s].pkt;
          CHECK(pkt_path_hash_count(q) == 2 && q->path[0] == 0xB2 && q->path[1] == 0xA1,
                "reply path is the reverse of the fetch path (path[0]=closest hop)"); } }

    /* 3b. a DIRECT reply passing THROUGH a repeater is forwarded, never treated as
     *     a command (else a second mbox repeater would "help"-reply to it) */
    { mc_mesh_t m3; mesh_init(&m3, &id, &cfg);
      mc_packet_t rep; build_public_text(&cfg, "ON0OTH: mbox 1: [OR7F-1] hi", &rep);
      rep.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_DIRECT);
      rep.path_len = 0x01; rep.path[0] = id.pub[0];   /* routed through us */
      n = pkt_serialize(&rep, raw, sizeof(raw));
      mesh_on_recv(&m3, raw, (size_t)n, -60, 24);
      CHECK(m3.stats.mbox_replies == 0 && m3.stats.mbox_stored == 0,
            "a routed DIRECT #mbox reply is forwarded, not answered as a command");
      CHECK(m3.stats.fwd_direct == 1, "the routed reply is forwarded on"); }

    /* 4. a HOTSPOT does not run the mailbox: it forwards #mbox UP to the repeater */
    mc_config_t hc; config_defaults(&hc);
    config_set(&hc, "name", "ON0HOT");
    config_set(&hc, "role", "hotspot");
    config_set(&hc, "affinity", "ON0RPT");   /* the repeater we bridge to (owns the mailbox) */
    config_set(&hc, "home", "ON4ABC*");
    config_set(&hc, "hotspot_power_high", "10");
    config_set(&hc, "hotspot_power_low", "-5");
    config_set(&hc, "room", "mbox");
    config_set(&hc, "mbox", "on");
    config_to_sx126x(&hc, &radio); sx126x_init(&radio);
    { mc_mesh_t hm; mesh_init(&hm, &id, &hc);
      mc_packet_t f; build_public_text(&hc, "ON4ABC-9: fetch", &f);
      n = pkt_serialize(&f, raw, sizeof(raw)); mesh_on_recv(&hm, raw, (size_t)n, -50, 40);
      CHECK(hm.stats.mbox_stored == 0 && hm.stats.mbox_replies == 0,
            "hotspot neither stores nor answers #mbox locally");
      int s = grp_slot(&hm);
      CHECK(hm.stats.fwd_flood == 1 && s >= 0 && hm.txq[s].power_dbm == 10,
            "hotspot forwards the fetch UP to the repeater (uplink, high power)");

      /* 5. the repeater's DIRECT reply routes back DOWN through the hotspot to the
       *    household device: path[0] = the hotspot's own hash -> stripped, low power */
      mc_packet_t rep; build_public_text(&hc, "ON0RPT: mbox 1: [OR7F-1] hi", &rep);
      rep.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_DIRECT);
      rep.path_len = 0x01; rep.path[0] = id.pub[0];   /* addressed to this hotspot */
      n = pkt_serialize(&rep, raw, sizeof(raw));
      uint64_t fd0 = hm.stats.fwd_direct;
      mesh_on_recv(&hm, raw, (size_t)n, -50, 40);
      int ds = direct_grp_slot(&hm);
      CHECK(hm.stats.fwd_direct == fd0 + 1 && ds >= 0,
            "hotspot ROUTES the DIRECT reply back (not dropped by personal scope)");
      if (ds >= 0) {
          CHECK(pkt_path_hash_count(&hm.txq[ds].pkt) == 0,
                "hotspot stripped itself -> zero-hop to the household device");
          CHECK(hm.txq[ds].power_dbm == -5, "reply relayed at low last-mile downlink power"); }

      /* 6. a STRANGER's crafted DIRECT public packet addressed to the hotspot is NOT
       *    relayed - only affinity-repeater replies / home-device traffic pass scope */
      mc_packet_t ev; build_public_text(&hc, "ON9EVL: free relay pls", &ev);
      ev.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_DIRECT);
      ev.path_len = 0x02; ev.path[0] = id.pub[0]; ev.path[1] = 0x5c;  /* addressed to us -> a target */
      n = pkt_serialize(&ev, raw, sizeof(raw));
      uint64_t fd1 = hm.stats.fwd_direct;
      mesh_on_recv(&hm, raw, (size_t)n, -50, 40);
      CHECK(hm.stats.fwd_direct == fd1,
            "hotspot drops a stranger's DIRECT public packet (no free relay hop)"); }
}

static void test_timeofday(void)
{
    printf("[#mesh time/date service: minute-aligned broadcast]\n");
    mc_identity_t id; mc_identity_generate(&id);
    uint8_t raw[MC_MAX_TRANS_UNIT]; int n;

    mc_config_t cfg; config_defaults(&cfg);
    config_set(&cfg, "name", "OR7F-4");
    config_set(&cfg, "room", "mesh");             /* #mesh = public_channels[0], the ping channel */
    CHECK(cfg.timeofday_enable, "timeofday on by default");
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    const mc_pub_channel_t *mesh_ch = &cfg.public_channels[0];

    /* a "time" request ARMS a pending broadcast but does NOT send mid-minute */
    mc_mesh_t m; mesh_init(&m, &id, &cfg);
    { mc_packet_t p; build_public_text(&cfg, "ON4XYZ: time", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&m, raw, (size_t)n, -60, 24);
      CHECK(m.tod_time_pending && !m.tod_date_pending, "'time' arms a pending broadcast");
      mesh_service_timeofday(&m, hal_millis());
      CHECK(m.tod_time_pending && m.stats.timeofday_sent == 0,   /* the request itself floods; no broadcast yet */
            "no broadcast within the same minute (waits for the tick)"); }

    /* the minute rolls over -> the broadcast fires, HH:MM with no seconds */
    m.tod_minute -= 1;                             /* simulate 'a new minute began' */
    mesh_service_timeofday(&m, hal_millis());
    CHECK(!m.tod_time_pending && m.stats.timeofday_sent == 1, "a new minute -> time broadcast sent");
    { int s = grp_slot(&m);
      CHECK(s >= 0, "time broadcast enqueued (flood)");
      if (s >= 0) {
          CHECK(pkt_route_type(&m.txq[s].pkt) == ROUTE_TYPE_FLOOD, "time broadcast is a FLOOD");
          char body[128]; decrypt_grp(mesh_ch, &m.txq[s].pkt, body, sizeof(body));
          const char *tp = strstr(body, "time ");
          CHECK(tp && strstr(body, "UTC"), "reply is 'time HH:MM UTC' (got '%s')", body);
          /* "HH:MM" then a space -> exactly one colon, no seconds */
          CHECK(tp && tp[7] == ':' && tp[10] == ' ',
                "time is HH:MM with no seconds (got '%s')", tp ? tp : ""); } }

    /* "date" -> "date YYYY-MM-DD" at the next minute */
    { mc_mesh_t md; mesh_init(&md, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "ON4XYZ: date", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&md, raw, (size_t)n, -60, 24);
      CHECK(md.tod_date_pending && !md.tod_time_pending, "'date' arms a pending date broadcast");
      md.tod_minute -= 1; mesh_service_timeofday(&md, hal_millis());
      int s = grp_slot(&md);
      CHECK(s >= 0 && md.stats.timeofday_sent == 1, "date broadcast sent at the next minute");
      if (s >= 0) {
          char body[128]; decrypt_grp(mesh_ch, &md.txq[s].pkt, body, sizeof(body));
          const char *dp = strstr(body, "date ");
          CHECK(dp && dp[9] == '-' && dp[12] == '-',
                "reply is 'date YYYY-MM-DD' (got '%s')", body); } }

    /* multiple requests in one minute COALESCE into a single broadcast per type */
    { mc_mesh_t mc; mesh_init(&mc, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "A: time", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&mc, raw, (size_t)n, -60, 24);
      build_public_text(&cfg, "B: time", &p);       /* a 2nd requester, same minute */
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&mc, raw, (size_t)n, -60, 24);
      mc.tod_minute -= 1; mesh_service_timeofday(&mc, hal_millis());
      CHECK(mc.stats.timeofday_sent == 1, "two 'time' requests in a minute -> one broadcast (coalesced)"); }

    /* off the ping channel, and when disabled, "time" is NOT armed */
    { mc_config_t c2; config_defaults(&c2);
      config_set(&c2, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");  /* Public = [0] */
      config_set(&c2, "room", "mesh");                                /* #mesh = [1] */
      config_to_sx126x(&c2, &radio); sx126x_init(&radio);
      mc_mesh_t m2; mesh_init(&m2, &id, &c2);
      mc_packet_t p; build_public_text(&c2, "X: time", &p);           /* built on Public, not #mesh */
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&m2, raw, (size_t)n, -60, 24);
      CHECK(!m2.tod_time_pending, "'time' off the ping channel is not armed"); }
    { mc_config_t c3; config_defaults(&c3);
      config_set(&c3, "room", "mesh");
      config_set(&c3, "timeofday", "off");
      config_to_sx126x(&c3, &radio); sx126x_init(&radio);
      mc_mesh_t m3; mesh_init(&m3, &id, &c3);
      mc_packet_t p; build_public_text(&c3, "X: time", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&m3, raw, (size_t)n, -60, 24);
      CHECK(!m3.tod_time_pending && !c3.timeofday_enable, "timeofday=off -> 'time' ignored"); }

    /* "help" -> a one-line summary of the enabled commands (flooded, rate-limited) */
    { mc_mesh_t mh; mesh_init(&mh, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "ON4XYZ: help", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&mh, raw, (size_t)n, -60, 24);
      CHECK(mh.stats.help_sent == 1, "'help' -> one command summary");
      char body[160]; body[0] = '\0';              /* find the reply by content (the request also floods) */
      for (int i = 0; i < MESH_TXQ_SIZE; i++)
          if (mh.txq[i].used && pkt_payload_type(&mh.txq[i].pkt) == PAYLOAD_TYPE_GRP_TXT) {
              char b[160]; decrypt_grp(mesh_ch, &mh.txq[i].pkt, b, sizeof(b));
              if (strstr(b, "commands:")) { snprintf(body, sizeof(body), "%s", b); break; }
          }
      CHECK(strstr(body, "commands:") && strstr(body, "ping") &&
            strstr(body, "time/date") && strstr(body, "help") && !strstr(body, "probe"),
            "help lists the enabled commands (got '%s')", body);
      /* a 2nd help within the cooldown is suppressed (distinct sender to dodge dedup) */
      build_public_text(&cfg, "ON4ABC: help", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&mh, raw, (size_t)n, -60, 24);
      CHECK(mh.stats.help_sent == 1, "a 2nd 'help' within the cooldown is suppressed"); }
}

static void test_hotspot(void)
{
    printf("[hotspot role: personal scope + power asymmetry]\n");
    mc_config_t cfg; config_defaults(&cfg);
    CHECK(config_set(&cfg, "role", "hotspot") == 0 && cfg.role == ROLE_HOTSPOT, "role=hotspot");
    config_set(&cfg, "affinity", "ON0XYZ");
    config_set(&cfg, "home", "ON6URE*");
    config_set(&cfg, "hotspot_power_high", "10");
    config_set(&cfg, "hotspot_power_low", "-5");
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    CHECK(config_name_matches("ON6URE*", "ON6URE-7") && !config_name_matches("ON6URE*", "ON4ABC"),
          "wildcard prefix match");
    CHECK(config_is_home(&cfg, "ON6URE-7") && !config_is_home(&cfg, "ON4ABC-1"), "is_home");
    CHECK(config_is_affinity(&cfg, "ON0XYZ") && !config_is_affinity(&cfg, "ON6URE-7"), "is_affinity");
    CHECK(config_set(&cfg, "home", "*") == -2 && config_set(&cfg, "affinity", "*") == -2,
          "reject bare '*' pattern (would void scoping)");
    config_set(&cfg, "home", "ON6URE-LONGDEVICENAME12345");   /* 26 chars */
    CHECK(config_is_home(&cfg, "ON6URE-LONGDEVICENAME12345"),
          "long exact pattern matches (pattern buffer >= name buffer)");

    mc_identity_t id; mc_identity_generate(&id);
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    uint8_t raw[MC_MAX_TRANS_UNIT]; int n;

    /* 1. home device's public message, heard locally -> uplink at HIGH power */
    { mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "ON6URE-7: hello", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      int s = first_used(&m);
      CHECK(m.stats.fwd_flood == 1 && s >= 0 && m.txq[s].power_dbm == 10,
            "home msg uplinked at high power (%d)", s >= 0 ? m.txq[s].power_dbm : 0); }

    /* 2. non-home local message -> dropped (out of personal scope) */
    { mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "ON4ABC-1: hi", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.stats.fwd_flood == 0, "non-home local msg dropped"); }

    /* 3. learn affinity from its advert; the advert is downlinked at LOW power */
    { mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_identity_t aff; mc_identity_generate(&aff);
      mc_advert_info_t info; memset(&info, 0, sizeof(info));
      info.type = ADV_TYPE_REPEATER; info.name = "ON0XYZ";
      mc_packet_t adv; mc_advert_build(&adv, &aff, &info, 1000);
      n = pkt_serialize(&adv, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.n_affinity_hash == 1 && m.affinity_hash[0] == aff.pub[0], "learned affinity path-hash");
      int s = first_used(&m);
      CHECK(s >= 0 && m.txq[s].power_dbm == -5, "affinity advert downlinked at low power");

      /* 4. a message that arrived VIA the affinity repeater -> downlink LOW (any sender) */
      mc_packet_t p; build_public_text(&cfg, "ON4ABC-1: relayed", &p);
      p.path_len = 0x01; p.path[0] = aff.pub[0];    /* 1 hop = the affinity repeater */
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      int g = grp_slot(&m);
      CHECK(g >= 0 && m.txq[g].power_dbm == -5, "msg via affinity repeater downlinked at low power"); }

    /* 5. multiple affinity repeaters (redundancy): both learned; via either -> downlink */
    { config_set(&cfg, "affinity", "ON0ABC");     /* a 2nd repeater alongside ON0XYZ */
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_identity_t r1, r2; mc_identity_generate(&r1);
      do { mc_identity_generate(&r2); } while (r2.pub[0] == r1.pub[0]);  /* distinct hashes */
      mc_advert_info_t info; memset(&info, 0, sizeof(info)); info.type = ADV_TYPE_REPEATER;
      mc_packet_t adv;
      info.name = "ON0XYZ"; mc_advert_build(&adv, &r1, &info, 1000);
      n = pkt_serialize(&adv, raw, sizeof(raw)); mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      info.name = "ON0ABC"; mc_advert_build(&adv, &r2, &info, 1001);
      n = pkt_serialize(&adv, raw, sizeof(raw)); mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.n_affinity_hash == 2, "learned two affinity repeaters (redundancy)");
      mc_packet_t p; build_public_text(&cfg, "ON4XYZ-2: hi", &p);
      p.path_len = 0x01; p.path[0] = r2.pub[0];   /* arrived via the SECOND repeater */
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      int g = grp_slot(&m);
      CHECK(g >= 0 && m.txq[g].power_dbm == -5, "downlink via a second affinity repeater"); }

    /* 6. ping/pong works in hotspot role (any sender) */
    { mc_config_t hc; config_defaults(&hc);
      config_set(&hc, "role", "hotspot");
      config_set(&hc, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
      hc.ping_pong = true; hc.ping_channel[0] = '\0';   /* answer on any channel */
      config_to_sx126x(&hc, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &hc);
      mc_packet_t p; build_public_text(&hc, "ON4ABC-9: ping", &p);
      n = pkt_serialize(&p, raw, sizeof(raw)); mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.stats.pong_sent == 1, "ping/pong works in hotspot role"); }

    /* 7. from the backbone hub (no repeater in RF range): downlink at LOW power
     *    whoever the sender; adverts only for an affinity repeater; never uplinked */
    { config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
      mc_mesh_t m; mesh_init(&m, &id, &cfg);
      mc_packet_t p; build_public_text(&cfg, "ON4ABC-1: via the hub", &p);
      p.path_len = 0x02; p.path[0] = 0xA1; p.path[1] = 0xB2;   /* relayed in another island */
      n = pkt_serialize(&p, raw, sizeof(raw));
      int r = mesh_on_backbone(&m, raw, (size_t)n);
      int g = grp_slot(&m);
      CHECK(r == MESH_RX_FORWARDED && g >= 0 && m.txq[g].power_dbm == -5,
            "hub msg (any sender) downlinked at low power");
      build_public_text(&cfg, "ON6URE-7: echoed by the hub", &p);
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_backbone(&m, raw, (size_t)n);
      bool low = true;
      for (int i = 0; i < MESH_TXQ_SIZE; i++)
          if (m.txq[i].used && m.txq[i].power_dbm != -5) low = false;
      CHECK(low && m.stats.fwd_flood == 2, "home device's msg from the hub goes down too, never up");
      mc_identity_t far; mc_identity_generate(&far);
      mc_advert_info_t info; memset(&info, 0, sizeof(info)); info.type = ADV_TYPE_REPEATER;
      mc_packet_t adv;
      info.name = "ON0FAR"; mc_advert_build(&adv, &far, &info, 1002);
      n = pkt_serialize(&adv, raw, sizeof(raw));
      CHECK(mesh_on_backbone(&m, raw, (size_t)n) == MESH_RX_POLICY && mesh_neighbor_count(&m) == 0,
            "hub advert of a non-affinity repeater: not downlinked, no neighbour");
      info.name = "ON0XYZ"; mc_advert_build(&adv, &far, &info, 1003);
      n = pkt_serialize(&adv, raw, sizeof(raw));
      CHECK(mesh_on_backbone(&m, raw, (size_t)n) == MESH_RX_FORWARDED && m.n_affinity_hash == 0,
            "hub advert of an affinity repeater downlinked (path-hash learned from RF only)"); }
}

static void test_crypto(void)
{
    printf("[crypto: hmac-sha256, channel hash, base64]\n");

    /* HMAC-SHA256, RFC 4231 test case 2 */
    uint8_t out[32], exp[32];
    hmac_sha256((const uint8_t *)"Jefe", 4,
                (const uint8_t *)"what do ya want for nothing?", 28, out);
    hex2bin("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            exp, sizeof(exp));
    CHECK(memcmp(out, exp, 32) == 0, "HMAC-SHA256 matches RFC 4231 test case 2");

    /* the default Public PSK: base64 -> 16 bytes -> channel hash 0x11 */
    uint8_t psk[32], pskhex[16];
    int len = base64_decode("izOH6cXN6mrJ5e26oRXNcg==", psk, sizeof(psk));
    hex2bin("8b3387e9c5cdea6ac9e5edbaa115cd72", pskhex, sizeof(pskhex));
    CHECK(len == 16 && memcmp(psk, pskhex, 16) == 0,
          "base64 decodes Public PSK to the 16 expected bytes");

    SHA256_CTX c; uint8_t d[SHA256_BLOCK_SIZE];
    sha256_init(&c); sha256_update(&c, psk, 16); sha256_final(&c, d);
    CHECK(d[0] == 0x11, "Public channel hash byte == 0x11 (got 0x%02X)", d[0]);

    CHECK(base64_decode("bad*chars==", psk, sizeof(psk)) == -1, "base64 rejects bad input");

    /* AES-128 FIPS-197 known-answer test (encrypt + decrypt) */
    uint8_t key[16], block[16], ct128[16];
    hex2bin("000102030405060708090a0b0c0d0e0f", key, sizeof(key));
    hex2bin("00112233445566778899aabbccddeeff", block, sizeof(block));
    hex2bin("69c4e0d86a7b0430d8cdb78070b4c55a", ct128, sizeof(ct128));
    aes128_ctx_t ac; aes128_init(&ac, key);
    aes128_encrypt_block(&ac, block);
    CHECK(memcmp(block, ct128, 16) == 0, "AES-128 encrypt matches FIPS-197 vector");
    aes128_decrypt_block(&ac, block);
    uint8_t pt128[16]; hex2bin("00112233445566778899aabbccddeeff", pt128, sizeof(pt128));
    CHECK(memcmp(block, pt128, 16) == 0, "AES-128 decrypt inverts encrypt");
}

static void test_airtime(void)
{
    printf("[airtime sanity]\n");
    mc_config_t cfg; config_defaults(&cfg);
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    uint32_t a20 = sx126x_airtime_ms(20);
    uint32_t a60 = sx126x_airtime_ms(60);
    /* SF10/BW250: ~150-400 ms range for small packets */
    CHECK(a20 > 50 && a20 < 1000, "20-byte airtime plausible (%u ms)", a20);
    CHECK(a60 > a20, "longer packet -> more airtime (%u > %u)", a60, a20);
}

static void test_config(void)
{
    printf("[config defaults + set/get]\n");
    mc_config_t cfg; config_defaults(&cfg);
    CHECK(cfg.sync_word == 0x1424, "default sync word is MeshCore PRIVATE 0x1424");
    CHECK(cfg.frequency == 434.890 && cfg.bandwidth == 62.5 &&
          cfg.spreading_factor == 8 && cfg.coding_rate == 8,
          "default modem params match the IARU R1 RFC (434.890/BW62.5/SF8/CR4-8)");
    CHECK(config_set(&cfg, "frequency", "434.000") == 0 && cfg.frequency == 434.0,
          "set frequency");
    CHECK(config_set(&cfg, "frequency", "9999") == -2, "reject out-of-range frequency");
    CHECK(config_set(&cfg, "sync_word", "public") == 0 && cfg.sync_word == 0x3444,
          "sync_word public -> 0x3444");
    CHECK(config_set(&cfg, "bogus", "x") == -1, "unknown key rejected");
    CHECK(config_set(&cfg, "bandwidth", "62.5") == 0 && cfg.bandwidth == 62.5,
          "accept fractional bandwidth 62.5 kHz");
    CHECK(config_set(&cfg, "bandwidth", "500") == 0 && cfg.bandwidth == 500.0,
          "accept bandwidth 500 kHz");
    CHECK(config_set(&cfg, "bandwidth", "62") == -2, "reject unsupported bandwidth 62 kHz");

    /* schematic-matched wiring defaults */
    mc_config_t w; config_defaults(&w);
    CHECK(w.gpio_reset == 18 && w.gpio_busy == 20 && w.gpio_dio1 == 16 && w.gpio_nss == 21,
          "default pin map matches schematic (rst18/busy20/dio1_16/nss21)");
    CHECK(w.rf_switch_dio2 == true, "default RF switch = DIO2 (no RXEN/TXEN)");
    CHECK(w.gpio_led_on == 19 && w.gpio_led_data == 26, "LED pins ON=19 DATA=26");
    CHECK(config_set(&w, "rf_switch", "external") == 0 && w.rf_switch_dio2 == false,
          "rf_switch external toggles off DIO2");
    CHECK(config_set(&w, "rf_switch", "dio2") == 0 && w.rf_switch_dio2 == true,
          "rf_switch dio2 toggles on DIO2");

    /* radio config projection carries the DIO2 flag */
    sx126x_cfg_t radio; config_to_sx126x(&w, &radio);
    CHECK(radio.dio2_rf_switch == true, "config_to_sx126x carries dio2_rf_switch");

    /* public channel parsing: base64 + hex, hash derivation, dedup, validation */
    mc_config_t pc; config_defaults(&pc);
    CHECK(pc.n_public_channels == 0, "no public channels by default");
    CHECK(config_set(&pc, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==") == 0 &&
          pc.n_public_channels == 1 && pc.public_channels[0].hash == 0x11 &&
          pc.public_channels[0].secret_len == 16,
          "public_channel base64 PSK -> hash 0x11, 16 bytes");
    CHECK(config_set(&pc, "public_channel", "Club:8b3387e9c5cdea6ac9e5edbaa115cd72") == 0 &&
          pc.n_public_channels == 1,
          "same key via hex (named) is deduped -> still 1 channel");
    CHECK(config_set(&pc, "public_channel", "0011223344556677889900aabbccddee") == 0 &&
          pc.n_public_channels == 2, "a distinct hex key adds a 2nd channel");
    CHECK(config_set(&pc, "public_channel", "deadbeef") == -2,
          "reject a wrong-length channel key");
}

static void test_node_name(void)
{
    printf("[node name: bare callsign (repeater) vs CALL-NN SSID (hotspot only)]\n");
    char why[128];
#define VALID(n, r) config_valid_node_name((n), (r), why, sizeof(why))
    /* bare names: fine in either role, no base-shape enforcement */
    CHECK(VALID("ON6URE", ROLE_REPEATER),      "bare callsign ok for a repeater");
    CHECK(VALID("ON6URE", ROLE_HOTSPOT),       "bare callsign ok for a hotspot");
    CHECK(VALID("HamRepeater", ROLE_REPEATER), "no-dash default name does not warn");
    /* hotspot CALL-NN across the 00..99 range */
    CHECK(VALID("ON6URE-1",  ROLE_HOTSPOT),    "hotspot CALL-1 ok");
    CHECK(VALID("ON6URE-0",  ROLE_HOTSPOT),    "hotspot CALL-0 ok");
    CHECK(VALID("ON6URE-00", ROLE_HOTSPOT),    "hotspot CALL-00 ok");
    CHECK(VALID("ON6URE-99", ROLE_HOTSPOT),    "hotspot CALL-99 ok");
    /* the "only for hotspots" rule, with a reason */
    CHECK(!VALID("ON6URE-6", ROLE_REPEATER),   "a repeater may NOT carry an SSID suffix");
    CHECK(why[0] != '\0',                      "  ... and it explains why");
    /* malformed hotspot SSIDs */
    CHECK(!VALID("ON6URE-100", ROLE_HOTSPOT),  "reject 3-digit SSID");
    CHECK(!VALID("ON6URE-1A",  ROLE_HOTSPOT),  "reject non-numeric SSID");
    CHECK(!VALID("ON6URE-",    ROLE_HOTSPOT),  "reject empty SSID");
    CHECK(!VALID("ON6URE-1-2", ROLE_HOTSPOT),  "reject two-dash SSID");
    CHECK(!VALID("-5",         ROLE_HOTSPOT),  "reject missing callsign before '-'");
    CHECK(!VALID("",           ROLE_HOTSPOT),  "reject empty name");
    (void)VALID("ON6URE-7", ROLE_HOTSPOT);
    CHECK(why[0] == '\0',                      "why[] is cleared when the name is valid");
#undef VALID

    /* end to end: config_set never rejects a name (validation is advisory), and
     * the same name flips valid<->invalid with the role. */
    mc_config_t c; config_defaults(&c);
    CHECK(config_set(&c, "name", "ON6URE-3") == 0, "config_set stores any name (advisory only)");
    config_set(&c, "role", "hotspot");
    CHECK(config_valid_node_name(c.name, c.role, why, sizeof(why)),  "ON6URE-3 valid once role=hotspot");
    config_set(&c, "role", "repeater");
    CHECK(!config_valid_node_name(c.name, c.role, why, sizeof(why)), "ON6URE-3 flagged once role=repeater");
}

static void test_rooms(void)
{
    printf("[transport hashtag rooms (#name regions): SHA256(name) key + transport-code gate]\n");

    /* config: normalisation, dedup, and the derived key vs an independent
     * Python SHA256("#test")[0..15] = 9cd8fcf22a47333b591d96a2b848b73f */
    mc_config_t cfg; config_defaults(&cfg);
    CHECK(cfg.n_rooms == 0, "no rooms by default");
    CHECK(config_set(&cfg, "room", "#test") == 0 && cfg.n_rooms == 1, "room #test added");
    static const uint8_t K[16] = { 0x9c,0xd8,0xfc,0xf2,0x2a,0x47,0x33,0x3b,
                                   0x59,0x1d,0x96,0xa2,0xb8,0x48,0xb7,0x3f };
    CHECK(memcmp(cfg.room_key[0], K, 16) == 0, "room_key = SHA256(\"#test\")[0..15]");
    CHECK(cfg.n_public_channels == 1 && cfg.public_channels[0].derived &&
          cfg.public_channels[0].secret_len == 16 &&
          memcmp(cfg.public_channels[0].secret, K, 16) == 0,
          "room #test also registers a derived public channel (same key)");
    CHECK(config_set(&cfg, "room", "test") == 0 && cfg.n_rooms == 1, "bare 'test' normalises to #test (dedup)");
    CHECK(config_set(&cfg, "room", "#other") == 0 && cfg.n_rooms == 2, "a second region adds");
    CHECK(config_set(&cfg, "room", "#") == -2, "bare '#' rejected");
    CHECK(config_set(&cfg, "room", "") == -2, "empty room rejected");
    /* length boundary: a normalised name must fit MC_ROOM_NAME_LEN (incl. '#'),
     * and an over-long one is REJECTED, never truncated to a wrong-hash region */
    { char at_limit[64], over[64];
      memset(at_limit, 'a', MC_ROOM_NAME_LEN - 1); at_limit[0] = '#'; at_limit[MC_ROOM_NAME_LEN - 1] = '\0';
      memset(over, 'a', MC_ROOM_NAME_LEN);         over[0] = '#';     over[MC_ROOM_NAME_LEN] = '\0';
      mc_config_t rc; config_defaults(&rc);
      CHECK(config_set(&rc, "room", at_limit) == 0 && rc.n_rooms == 1, "room name at length limit accepted");
      CHECK(rc.n_public_channels == 1 && strcmp(rc.public_channels[0].name, rc.rooms[0]) == 0,
            "derived channel stores the FULL room name (no truncation -> monitor #longname works)");
      CHECK(config_set(&rc, "room", over) == -2, "over-long room name rejected (not truncated)"); }

    /* save -> load round-trip: rooms are stored "#ora" but MUST be written as the
     * bare name, since '#' starts a comment and would be stripped on reload */
    { mc_config_t rt; config_defaults(&rt);
      CHECK(config_set(&rt, "room", "#ora") == 0 && strcmp(rt.rooms[0], "#ora") == 0, "room #ora stored with '#'");
      const char *tmp = "/tmp/mc_rooms_roundtrip.conf";
      CHECK(config_save(&rt, tmp) == 0, "config_save ok");
      mc_config_t rl; config_defaults(&rl);
      config_load(&rl, tmp);
      CHECK(rl.n_rooms == 1 && strcmp(rl.rooms[0], "#ora") == 0, "room survives save->load round-trip");
      CHECK(memcmp(rl.room_key[0], rt.room_key[0], 16) == 0, "round-tripped room key matches");
      int n_ora = 0;
      for (int i = 0; i < rl.n_public_channels; i++)
          if (strcmp(rl.public_channels[i].name, "#ora") == 0 && rl.public_channels[i].derived) n_ora++;
      CHECK(n_ora == 1, "derived #ora channel re-created exactly once (not lost/double-written)");
      remove(tmp); }

    mc_identity_t id; mc_identity_generate(&id);
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    uint8_t raw[300]; int n;
    /* channel_hash 0x11 + 2B MAC + 16B ciphertext (unconfigured channel here) */
    uint8_t body[19] = { 0x11,0xAA,0xBB, 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
                         0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };
    mc_packet_t p; memset(&p, 0, sizeof(p));
    p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_TRANSPORT_FLOOD);
    p.path_len = 0x00;
    memcpy(p.payload, body, sizeof(body)); p.payload_len = sizeof(body);

    /* transport code 0x587D (Python) for [0x05]||body -> matches #test -> relayed opaque */
    { mc_mesh_t m; mesh_init(&m, &id, &cfg);
      p.transport_codes[0] = 0x587D;
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.stats.rx_transport_flood == 1, "transport-flood counted (diagnostic)");
      CHECK(m.stats.fwd_region == 1, "group traffic for a served #room is relayed without the key"); }

    /* wrong transport code -> not our region -> dropped */
    { mc_mesh_t m; mesh_init(&m, &id, &cfg);
      p.transport_codes[0] = 0x587C;
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.stats.fwd_region == 0 && m.stats.fwd_denied_grp == 1, "mismatched transport code dropped"); }

    /* correct code but PLAIN flood (no transport codes) -> no region -> dropped */
    { mc_mesh_t m; mesh_init(&m, &id, &cfg);
      p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_FLOOD);
      p.transport_codes[0] = 0x587D;
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.stats.fwd_region == 0 && m.stats.rx_transport_flood == 0, "plain-flood group (no region tag) dropped"); }

    /* same transport-flood but NO #rooms configured -> dropped (strict default holds) */
    { mc_config_t c2; config_defaults(&c2);
      mc_mesh_t m; mesh_init(&m, &id, &c2);
      p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_TRANSPORT_FLOOD);
      p.transport_codes[0] = 0x587D;
      n = pkt_serialize(&p, raw, sizeof(raw));
      mesh_on_recv(&m, raw, (size_t)n, -50, 40);
      CHECK(m.stats.fwd_region == 0, "no #rooms configured -> region traffic still dropped"); }
}

static void test_monitor(void)
{
    printf("[monitor: target parsing + routing predicates]\n");
    mc_monitor mon; monitor_init(&mon);
    CHECK(monitor_count(&mon) == 0, "no monitors initially");

    int pp[2];
    if (pipe(pp) != 0) { CHECK(0, "pipe() for monitor test"); return; }

    /* parsing: each target string -> kind + stored target */
    CHECK(monitor_add(&mon, dup(pp[1]), "monitor") && mon.conn[0].kind == MON_ALL,
          "monitor (no arg) -> MON_ALL");
    CHECK(monitor_add(&mon, dup(pp[1]), "monitor public") && mon.conn[1].kind == MON_PUBLIC,
          "monitor public -> MON_PUBLIC");
    CHECK(monitor_add(&mon, dup(pp[1]), "monitor #sysop") && mon.conn[2].kind == MON_ROOM
          && !strcmp(mon.conn[2].target, "#sysop"), "monitor #sysop -> MON_ROOM '#sysop'");
    CHECK(monitor_add(&mon, dup(pp[1]), "monitor other") && mon.conn[3].kind == MON_CHANNEL
          && !strcmp(mon.conn[3].target, "other"), "monitor other -> MON_CHANNEL 'other'");
    CHECK(monitor_count(&mon) == 4, "four monitors registered");

    int f5 = dup(pp[1]);
    CHECK(!monitor_add(&mon, f5, "monitor all") && monitor_count(&mon) == 4,
          "a 5th monitor is rejected at the cap");
    close(f5);

    /* routing predicates */
    CHECK(monitor_wants_public(&mon.conn[0], "AnyChan"), "MON_ALL wants any public channel");
    CHECK(monitor_wants_public(&mon.conn[1], "AnyChan"), "MON_PUBLIC wants any public channel");
    CHECK(monitor_wants_public(&mon.conn[3], "other") && !monitor_wants_public(&mon.conn[3], "public"),
          "MON_CHANNEL 'other' matches only channel 'other'");
    CHECK(monitor_wants_public(&mon.conn[2], "#sysop") && !monitor_wants_public(&mon.conn[2], "AnyChan"),
          "MON_ROOM '#sysop' also matches the #sysop channel by name");
    CHECK(monitor_wants_room(&mon.conn[0], "#sysop"), "MON_ALL wants any room");
    CHECK(monitor_wants_room(&mon.conn[2], "#sysop") && !monitor_wants_room(&mon.conn[2], "#other"),
          "MON_ROOM '#sysop' matches only '#sysop' (case-sensitive)");
    CHECK(!monitor_wants_room(&mon.conn[1], "#sysop"), "MON_PUBLIC ignores rooms");
    /* rooms/hashtag channels are case-sensitive (distinct keys) - the channel-name
     * match must be too, or `monitor #sysop` would show an unrelated #SYSOP */
    CHECK(monitor_wants_public(&mon.conn[2], "#sysop") && !monitor_wants_public(&mon.conn[2], "#SYSOP"),
          "MON_ROOM channel match is case-sensitive (#sysop != #SYSOP)");

    for (int i = 0; i < mon.n; i++) close(mon.conn[i].fd);
    close(pp[0]); close(pp[1]);

    /* new firehose sub-filters: adverts + drops */
    { mc_monitor m4; monitor_init(&m4);
      int r[2];
      if (pipe(r) == 0) {
          CHECK(monitor_add(&m4, dup(r[1]), "monitor adverts") && m4.conn[0].kind == MON_ADVERT,
                "monitor adverts -> MON_ADVERT");
          CHECK(monitor_add(&m4, dup(r[1]), "monitor drops") && m4.conn[1].kind == MON_DROP,
                "monitor drops -> MON_DROP");
          CHECK(monitor_wants_advert(&m4.conn[0]) && !monitor_wants_drop(&m4.conn[0]),
                "MON_ADVERT wants adverts only");
          CHECK(monitor_wants_drop(&m4.conn[1]) && !monitor_wants_advert(&m4.conn[1]),
                "MON_DROP wants drops only");
          CHECK(!monitor_wants_public(&m4.conn[0], "AnyChan") && !monitor_wants_room(&m4.conn[1], "#x"),
                "advert/drop monitors ignore the public + room message streams");
          CHECK(monitor_add(&m4, dup(r[1]), "monitor tx") && m4.conn[2].kind == MON_TX,
                "monitor tx -> MON_TX");
          CHECK(monitor_wants_tx(&m4.conn[2]) && !monitor_wants_drop(&m4.conn[2])
                && !monitor_wants_public(&m4.conn[2], "AnyChan"),
                "MON_TX wants transmissions only");
          CHECK(!monitor_wants_tx(&m4.conn[0]) && !monitor_wants_tx(&m4.conn[1]),
                "advert/drop monitors ignore transmissions");
          for (int i = 0; i < m4.n; i++) close(m4.conn[i].fd);
          close(r[0]); close(r[1]);
      } }

    /* emit path: a MON_ALL monitor receives public + region + advert + drop lines */
    { mc_monitor m2; monitor_init(&m2);
      int q[2];
      if (pipe(q) == 0) {
          monitor_add(&m2, dup(q[1]), "monitor all");        /* header written to pipe */
          monitor_public(&m2, "TestChan", "ON4XYZ: hi", -70, 32);
          monitor_region(&m2, "#sysop", 0x05, 42, -80, 20);
          monitor_advert(&m2, "ON0RFG", 1, true, 50.85000, 4.35000, -60, 24);
          monitor_drop(&m2, 0x03, "private unicast (DM)", -1);
          monitor_tx(&m2, "GRP_TXT", true, 53, 0, 22, 574, "[#mesh] ON0RFG: pong");
          char buf[1024]; ssize_t rr = read(q[0], buf, sizeof(buf) - 1);
          buf[rr > 0 ? rr : 0] = '\0';
          CHECK(strstr(buf, "[public TestChan]") && strstr(buf, "ON4XYZ: hi"),
                "monitor_public streams a formatted line");
          CHECK(strstr(buf, "[room #sysop]") && strstr(buf, "type=0x05") && strstr(buf, "len=42B"),
                "monitor_region streams region metadata");
          CHECK(strstr(buf, "[advert] 'ON0RFG'") && strstr(buf, "loc 50.85000,4.35000"),
                "monitor_advert streams name + location");
          CHECK(strstr(buf, "[drop]") && strstr(buf, "private unicast (DM)"),
                "monitor_drop streams the discard reason");
          CHECK(strstr(buf, "[tx] GRP_TXT flood 53B 0hop 22dBm 574ms  [#mesh] ON0RFG: pong"),
                "monitor_tx streams route/size/power/airtime + the text");
          for (int i = 0; i < m2.n; i++) close(m2.conn[i].fd);
          close(q[0]); close(q[1]);
      }
    }

    /* routing isolation: an 'adverts' monitor sees ONLY adverts (not public/drop),
     * a 'drops' monitor sees ONLY drops */
    { mc_monitor ma; monitor_init(&ma);
      int a[2];
      if (pipe(a) == 0) {
          monitor_add(&ma, dup(a[1]), "monitor adverts");
          monitor_public(&ma, "C", "X: hi", -70, 20);        /* not for an adverts monitor */
          monitor_drop(&ma, 0x03, "dm", -1);                 /* not for an adverts monitor */
          monitor_advert(&ma, "ON0ABC", 2, false, 0, 0, -55, 28);
          char b[512]; ssize_t rr = read(a[0], b, sizeof(b) - 1); b[rr > 0 ? rr : 0] = '\0';
          CHECK(strstr(b, "[advert] 'ON0ABC'") && !strstr(b, "[public") && !strstr(b, "[drop]"),
                "MON_ADVERT carries adverts only");
          for (int i = 0; i < ma.n; i++) close(ma.conn[i].fd);
          close(a[0]); close(a[1]);
      } }
    { mc_monitor md; monitor_init(&md);
      int a[2];
      if (pipe(a) == 0) {
          monitor_add(&md, dup(a[1]), "monitor drops");
          monitor_advert(&md, "ON0ABC", 2, false, 0, 0, -55, 28); /* not for a drops monitor */
          monitor_public(&md, "C", "X: hi", -70, 20);             /* not for a drops monitor */
          monitor_drop(&md, 0x05, "unconfigured channel", 0x8b);
          char b[512]; ssize_t rr = read(a[0], b, sizeof(b) - 1); b[rr > 0 ? rr : 0] = '\0';
          CHECK(strstr(b, "[drop]") && strstr(b, "chan=0x8B") && !strstr(b, "[advert]") && !strstr(b, "[public"),
                "MON_DROP carries drops only (with channel hash)");
          for (int i = 0; i < md.n; i++) close(md.conn[i].fd);
          close(a[0]); close(a[1]);
      } }

    /* reap: a monitor whose client has gone is dropped on the next poll (this is
     * the bug that leaked zombie monitors until the table filled) */
    { mc_monitor m3; monitor_init(&m3);
      int sp[2];
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
          monitor_add(&m3, sp[0], "monitor all");      /* sp[0] = daemon side */
          CHECK(monitor_count(&m3) == 1, "reap: monitor registered");
          close(sp[1]);                                 /* client goes away */
          struct pollfd pf; int k = monitor_pollfds(&m3, &pf, 1);
          poll(&pf, k, 200);
          monitor_reap(&m3, &pf, k);
          CHECK(monitor_count(&m3) == 0, "reap: a closed client is dropped (no zombie leak)");
      }
    }
}

/* ---- IP backbone (docs/backbone.md) ---- */

static void seed_seq(uint8_t *b, uint8_t start) { for (int i = 0; i < 32; i++) b[i] = (uint8_t)(start + i); }

static bool hex_eq(const uint8_t *b, size_t n, const char *hex)
{
    uint8_t want[256];
    return strlen(hex) == n * 2 && hex2bin(hex, want, sizeof(want)) == (int)n && memcmp(b, want, n) == 0;
}

/* An identity from an RFC 8032 seed and its (vector) public key. */
static void vec_identity(mc_identity_t *id, uint8_t seed_start, const char *pub_hex)
{
    memset(id, 0, sizeof(*id));
    hex2bin(pub_hex, id->pub, sizeof(id->pub));
    seed_seq(id->sec, seed_start);
    memcpy(&id->sec[32], id->pub, 32);             /* TweetNaCl secret key = seed || pub */
    id->has_secret = true;
}

static void test_backbone_codec(void)
{
    printf("[backbone: wire format against the docs/backbone.md vectors]\n");
    mc_identity_t rep, hub;
    vec_identity(&rep, 0x00, "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    vec_identity(&hub, 0x20, "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7");
    uint8_t r_sec[32], h_sec[32], r_pub[32], h_pub[32];
    seed_seq(r_sec, 0x40); seed_seq(h_sec, 0x60);
    crypto_scalarmult_base(r_pub, r_sec);
    crypto_scalarmult_base(h_pub, h_sec);
    CHECK(hex_eq(r_pub, 32, "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a") &&
          hex_eq(h_pub, 32, "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f"),
          "X25519 ephemeral public keys");

    uint8_t hello[200];
    size_t hl = bb_build_hello(hello, sizeof(hello), &rep, 0x03, 1792000000u, r_pub, "ON0RFG");
    CHECK(hl == 145 && hex_eq(hello, hl,
          "4d420101030000c0cf6a03a107bff3ce10be1d70dd18e74bc09967e4d6309ba5"
          "0d5f1ddc8664125531b879a631eede1bf9c98f12032cdeadd0e7a079398fc786"
          "b88cc846ec89af85a51a064f4e3052464772325767d90b5585b5c869ce17adc0"
          "e8f74e92f152d3477ff99a441b2db0efd18ccd7110639f44ea3c211d4c9c1783"
          "bae163f4d80503c556271a1ce798c1020f"), "HELLO bytes");
    uint8_t hh[32];
    SHA256_CTX c; sha256_init(&c); sha256_update(&c, hello, hl); sha256_final(&c, hh);
    CHECK(hex_eq(hh, 32, "6c96f061289bab91bf5fd637e4a1220deafbe2efb728e115f6f749965b9c4e7e"), "hello_hash");

    bb_welcome_t w = { .roles = 0x03, .ts = 1792000001u, .sid = 0x1a2b3c4du,
                       .keepalive_s = 25, .status_s = 60, .neighbours_s = 300 };
    memcpy(w.eph_pub, h_pub, 32);
    uint8_t wel[BB_WELCOME_LEN];
    size_t wl = bb_build_welcome(wel, sizeof(wel), &hub, &w, hh);
    CHECK(wl == 148 && hex_eq(wel, wl,
          "4d420102030001c0cf6a4d3c2b1a675dd574ed7789310b3d2e7681f3790b466c"
          "773b1521fecf36577958371ea52f6c96f061289bab91bf5fd637e4a1220deafb"
          "e2efb728e115f6f749965b9c4e7e19003c002c01b611bef646242ce91a5de9ae"
          "16c95aeefb334cf94e8dab058e8c35062fad386758ee6d8ef90d3006e2199afd"
          "eb1316dd522ae4ac8948d0b6f6cf6c4c507b8001"), "WELCOME bytes");

    bb_welcome_t got;
    CHECK(bb_check_welcome(wel, wl, hub.pub, hh, 0x03, &got) == 0 && got.sid == 0x1a2b3c4du &&
          got.roles == 3 && got.keepalive_s == 25 && got.status_s == 60 && got.neighbours_s == 300,
          "WELCOME accepted, fields decoded");
    CHECK(bb_check_welcome(wel, wl, rep.pub, hh, 0x03, &got) != 0, "WELCOME rejected: not the pinned hub key");
    uint8_t hh2[32]; memcpy(hh2, hh, 32); hh2[0] ^= 1;
    CHECK(bb_check_welcome(wel, wl, hub.pub, hh2, 0x03, &got) != 0, "WELCOME rejected: answers another HELLO");
    uint8_t welx[BB_WELCOME_LEN]; memcpy(welx, wel, wl); welx[79] ^= 1;
    CHECK(bb_check_welcome(welx, wl, hub.pub, hh, 0x03, &got) != 0, "WELCOME rejected: tampered byte");
    CHECK(bb_check_welcome(wel, wl, hub.pub, hh, 0x01, &got) != 0, "WELCOME rejected: grants a role not asked for");

    uint8_t s1[32], s2[32], ku[32], kd[32];
    crypto_scalarmult(s1, r_sec, h_pub);
    crypto_scalarmult(s2, h_sec, r_pub);
    CHECK(memcmp(s1, s2, 32) == 0 &&
          hex_eq(s1, 32, "d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e"),
          "X25519 shared secret (both sides agree)");
    CHECK(bb_derive_keys(s1, hello, hl, wel, wl, ku, kd) == 0 &&
          hex_eq(ku, 32, "141922284ac65dafe1f28d9af212229728a9a949d3d6301bd83ae2cb73455ce5") &&
          hex_eq(kd, 32, "be484977837de2e5315ff41d3bf7b7cd3d4b7bb1af1dde564c29849822df7fae"),
          "k_up / k_down");
    uint8_t zero[32] = {0};
    uint8_t zu[32], zd[32];
    CHECK(bb_derive_keys(zero, hello, hl, wel, wl, zu, zd) == -1, "all-zero shared secret refused");

    uint8_t d[BB_MAX_DGRAM]; size_t n;
    n = bb_seal(d, sizeof(d), BB_T_KEEPALIVE, 0x1a2b3c4du, 1, NULL, 0, ku);
    CHECK(n == 28 && hex_eq(d, n, "4d4201104d3c2b1a0100000095909f12cd7628661a2ba746b8a8e276"), "KEEPALIVE bytes");
    n = bb_seal(d, sizeof(d), BB_T_KEEPALIVE_ACK, 0x1a2b3c4du, 1, NULL, 0, kd);
    CHECK(n == 28 && hex_eq(d, n, "4d4201204d3c2b1a0100000008b340d0bfeb875470dd700794c28f87"), "KEEPALIVE_ACK bytes");

    uint8_t frame[7] = { 0x15, 0x00, 0xb0, 0x01, 0x02, 0x03, 0x04 };
    mc_packet_t fp; pkt_parse(&fp, frame, sizeof(frame));
    uint8_t body[64];
    body[0] = 0; body[1] = BB_DISP_FORWARDED;
    wr_u16le(&body[2], (uint16_t)(int16_t)-107); body[4] = 21; body[5] = 7;
    pkt_calc_hash(&fp, &body[6]);
    memcpy(&body[14], frame, 7);
    n = bb_seal(d, sizeof(d), BB_T_OBSERVE, 0x1a2b3c4du, 2, body, 21, ku);
    CHECK(n == 49 && hex_eq(d, n,
          "4d4201114d3c2b1a02000000000095ff150795bb58de03d4fb371500b0010203"
          "04789982ea2e4f120a35a9e324ab0c46b7"), "OBSERVE bytes (pkt_hash = MeshCore dedup hash)");

    uint8_t t; uint32_t sid, seq; const uint8_t *b; size_t blen;
    CHECK(bb_open(d, n, ku, &t, &sid, &seq, &b, &blen) == 0 && t == BB_T_OBSERVE && sid == 0x1a2b3c4du &&
          seq == 2 && blen == 21 && memcmp(b, body, 21) == 0, "session datagram opens with k_up");
    CHECK(bb_open(d, n, kd, &t, &sid, &seq, &b, &blen) != 0, "...but not with the other direction's key");
    d[20] ^= 1;
    CHECK(bb_open(d, n, ku, &t, &sid, &seq, &b, &blen) != 0, "tampered body fails the MAC");

    uint8_t rs[BB_RESET_LEN];
    n = bb_build_reset(rs, sizeof(rs), &hub, 0x1a2b3c4du, 7, 1792000100u);
    CHECK(n == 80 && hex_eq(rs, n,
          "4d4201034d3c2b1a0700000064c0cf6ad0b442eaf3ddd0afa74708d9026a7eae"
          "4305e0026173c660ec68a875ccfa60912ed4a62aaa9b5cd3240240bfdd930a0f"
          "f8cb58c032415be8666c6764abc8040a"), "RESET bytes");
    uint32_t rts;
    CHECK(bb_check_reset(rs, n, hub.pub, &sid, &seq, &rts) == 0 && sid == 0x1a2b3c4du && seq == 7 &&
          rts == 1792000100u, "RESET verifies");
    CHECK(bb_check_reset(rs, n, rep.pub, &sid, &seq, &rts) != 0, "RESET from the wrong key rejected");

    bb_replay_t rw = {0};
    CHECK(!bb_replay_check(&rw, 0), "replay: seq 0 never valid");
    CHECK(bb_replay_check(&rw, 1) && !bb_replay_check(&rw, 1), "replay: seq 1 once, then rejected");
    CHECK(bb_replay_check(&rw, 3) && bb_replay_check(&rw, 2) && !bb_replay_check(&rw, 2),
          "replay: out of order inside the window accepted once");
    CHECK(bb_replay_check(&rw, 100) && !bb_replay_check(&rw, 36) && bb_replay_check(&rw, 37),
          "replay: 64 behind is too old, 63 behind still ok");
}

/* ---- end to end: the test plays the hub on 127.0.0.1 ---- */

typedef struct {
    int fd;
    struct sockaddr_in peer;           /* the repeater, from its last datagram */
    uint8_t k_up[32], k_down[32];
    uint32_t sid, seq_down;
} fake_hub_t;

/* Run the repeater's backbone service until the hub has a datagram (or timeout). */
static ssize_t hub_wait(fake_hub_t *h, mc_backbone *bb, uint8_t *d, size_t cap, int ms)
{
    for (int i = 0; i < ms; i++) {
        backbone_service(bb, hal_millis());
        socklen_t al = sizeof(h->peer);
        ssize_t r = recvfrom(h->fd, d, cap, MSG_DONTWAIT, (struct sockaddr *)&h->peer, &al);
        if (r > 0) return r;
        usleep(1000);
    }
    return -1;
}

/* Next session datagram of a given type from the repeater (others are skipped). */
static ssize_t hub_wait_type(fake_hub_t *h, mc_backbone *bb, uint8_t type,
                             const uint8_t **body, size_t *blen, uint8_t *d, size_t cap)
{
    for (int k = 0; k < 40; k++) {
        ssize_t r = hub_wait(h, bb, d, cap, 200);
        if (r < 0) return -1;
        uint8_t t; uint32_t sid, seq;
        if (bb_open(d, (size_t)r, h->k_up, &t, &sid, &seq, body, blen) == 0 && t == type)
            return r;
    }
    return -1;
}

static void hub_send(fake_hub_t *h, uint8_t type, const uint8_t *body, size_t blen, uint8_t *out, size_t *outlen)
{
    uint8_t d[BB_MAX_DGRAM];
    size_t n = bb_seal(d, sizeof(d), type, h->sid, ++h->seq_down, body, blen, h->k_down);
    sendto(h->fd, d, n, 0, (struct sockaddr *)&h->peer, sizeof(h->peer));
    if (out) { memcpy(out, d, n); *outlen = n; }
}

static void hub_send_frame(fake_hub_t *h, const mc_packet_t *p, uint8_t *out, size_t *outlen)
{
    uint8_t raw[MC_MAX_TRANS_UNIT], body[10 + MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(p, raw, sizeof(raw));
    memset(body, 0, 10);
    body[1] = (uint8_t)n;
    memcpy(&body[10], raw, (size_t)n);
    hub_send(h, BB_T_FRAME, body, 10 + (size_t)n, out, outlen);
}

static void pump(mc_backbone *bb, int ms)
{
    for (int i = 0; i < ms; i++) { backbone_service(bb, hal_millis()); usleep(1000); }
}

static int txq_used(const mc_mesh_t *m) { return MESH_TXQ_SIZE - mesh_txq_free(m); }

static void test_backbone_session(void)
{
    printf("[backbone: config, handshake, observe, bridge, policy, rate limit, reset]\n");
    mc_identity_t id, hub, other;
    mc_identity_generate(&id); mc_identity_generate(&hub); mc_identity_generate(&other);

    mc_config_t cfg; config_defaults(&cfg);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    mc_backbone bb;
    CHECK(!cfg.backbone_enable && backbone_init(&bb, &cfg, &id, &mesh) == 0 && bb.state == BB_OFF &&
          backbone_pollfd(&bb) == -1, "off by default: no socket, no traffic");
    config_set(&cfg, "backbone", "true");
    CHECK(backbone_init(&bb, &cfg, &id, &mesh) == -1 && bb.state == BB_OFF,
          "enabled without backbone_hub_key: refused, stays off");
    CHECK(config_set(&cfg, "backbone_hub_key", "abcd") == -2, "a short hub key is invalid");
    char hex[65]; bin2hex(hub.pub, 32, hex, sizeof(hex));
    char out[128];
    CHECK(config_set(&cfg, "backbone_hub_key", hex) == 0 && config_get(&cfg, "backbone_hub_key", out, sizeof(out)) == 0 &&
          !strcmp(out, hex), "hub key set + read back as hex");
    CHECK(cfg.backbone_port == 4405 && cfg.backbone_observe && !cfg.backbone_bridge && cfg.backbone_rate == 30 &&
          !strcmp(cfg.backbone_host, "be.mesh73.net"), "defaults: be.mesh73.net:4405, observe on, bridge off, 30/min");

    fake_hub_t h; memset(&h, 0, sizeof(h));
    uint16_t port = (uint16_t)(45600 + (getpid() % 120));
    h.fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(port);
    bind(h.fd, (struct sockaddr *)&a, sizeof(a));
    char ps[8]; snprintf(ps, sizeof(ps), "%u", port);
    config_set(&cfg, "backbone_host", "127.0.0.1");
    config_set(&cfg, "backbone_port", ps);
    config_set(&cfg, "backbone_bridge", "true");
    config_set(&cfg, "public_channel", "izOH6cXN6mrJ5e26oRXNcg==");
    cfg.ping_channel[0] = '\0';                     /* ping on any channel */
    snprintf(cfg.name, sizeof(cfg.name), "%s", "ON0TST");
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mesh_init(&mesh, &id, &cfg);
    CHECK(backbone_init(&bb, &cfg, &id, &mesh) == 0 && bb.state == BB_IDLE, "enabled with a hub key");
    mesh.bb = &bb;

    /* HELLO: signed by the node key, as the doc says */
    uint8_t d[BB_MAX_DGRAM + 8], hello[200];
    ssize_t r = hub_wait(&h, &bb, d, sizeof(d), 3000);
    bool hello_ok = r == 75 + 6 + 64 && d[3] == BB_T_HELLO && d[4] == 3 && memcmp(&d[10], id.pub, 32) == 0 &&
                    d[74] == 6 && !memcmp(&d[75], "ON0TST", 6);
    if (hello_ok) {
        uint8_t m[200]; memcpy(m, "MCBB1 HELLO", 11); memcpy(m + 11, d, 81);
        hello_ok = mc_identity_verify(id.pub, &d[81], m, 11 + 81);
    }
    CHECK(hello_ok, "hub got a valid signed HELLO (roles observe+bridge, name, node key)");
    size_t hl = r > 0 ? (size_t)r : 0;
    memcpy(hello, d, hl);
    uint32_t hello_ts = rd_u32le(&hello[6]);

    /* WELCOME */
    uint8_t h_sec[32], h_pub[32], hh[32], wel[BB_WELCOME_LEN], shared[32];
    randombytes(h_sec, 32); crypto_scalarmult_base(h_pub, h_sec);
    SHA256_CTX c; sha256_init(&c); sha256_update(&c, hello, hl); sha256_final(&c, hh);
    bb_welcome_t w = { .roles = 3, .ts = (uint32_t)time(NULL), .sid = 0x11223344u,
                       .keepalive_s = 25, .status_s = 60, .neighbours_s = 300 };
    memcpy(w.eph_pub, h_pub, 32);
    size_t wl = bb_build_welcome(wel, sizeof(wel), &hub, &w, hh);
    crypto_scalarmult(shared, h_sec, &hello[42]);
    bb_derive_keys(shared, hello, hl, wel, wl, h.k_up, h.k_down);
    h.sid = w.sid;
    sendto(h.fd, wel, wl, 0, (struct sockaddr *)&h.peer, sizeof(h.peer));

    const uint8_t *body; size_t blen;
    r = hub_wait_type(&h, &bb, BB_T_KEEPALIVE, &body, &blen, d, sizeof(d));
    CHECK(bb.state == BB_UP && bb.sid == 0x11223344u && bb.roles == 3 && r > 0,
          "WELCOME -> session up, KEEPALIVE confirms it");
    CHECK(memcmp(bb.k_up, h.k_up, 32) == 0 && memcmp(bb.k_down, h.k_down, 32) == 0, "both sides derived the same keys");
    r = hub_wait_type(&h, &bb, BB_T_STATUS, &body, &blen, d, sizeof(d));
    char js[BB_MAX_DGRAM + 1] = "";
    if (r > 0) { memcpy(js, body, blen); js[blen] = 0; }
    CHECK(r > 0 && blen <= 1100 && js[0] == '{' && js[blen - 1] == '}' && strstr(js, "\"name\":\"ON0TST\"") &&
          strstr(js, "\"fw\":\"") && strstr(js, "\"airtime_ms\":{\"tx\":") && strstr(js, "\"backbone\":{"),
          "STATUS sent right away (JSON: %.60s...)", js);

    /* NEIGHBOURS: empty table = one page, empty list; names are JSON-escaped */
    bb.next_neighbours_ms = 0;
    r = hub_wait_type(&h, &bb, BB_T_NEIGHBOURS, &body, &blen, d, sizeof(d));
    if (r > 0) { memcpy(js, body, blen); js[blen] = 0; }
    CHECK(r > 0 && !strcmp(js, "{\"page\":1,\"pages\":1,\"list\":[]}"), "NEIGHBOURS: empty table -> %s", js);
    for (int i = 0; i < 20; i++) {
        mesh.neighbors[i].used = true;
        mesh.neighbors[i].pub[0] = (uint8_t)i;
        snprintf(mesh.neighbors[i].name, sizeof(mesh.neighbors[i].name), "N%02d-a\"b\\c\xff", i);
        mesh.neighbors[i].last_seen = (uint32_t)time(NULL);
    }
    bb.next_neighbours_ms = 0;
    int pages = 0, entries = 0; bool esc_ok = false, sizes_ok = true;
    for (int k = 0; k < 10; k++) {
        r = hub_wait_type(&h, &bb, BB_T_NEIGHBOURS, &body, &blen, d, sizeof(d));
        if (r <= 0) break;
        memcpy(js, body, blen); js[blen] = 0;
        if (blen > 1100) sizes_ok = false;
        int pg = 0, pgs = 0; sscanf(js, "{\"page\":%d,\"pages\":%d", &pg, &pgs);
        for (const char *q = js; (q = strstr(q, "\"pub\":")); q++) entries++;
        if (strstr(js, "N00-a\\\"b\\\\c?\"")) esc_ok = true;
        pages++;
        if (pg == pgs) break;
    }
    CHECK(pages >= 2 && entries == 20 && sizes_ok, "NEIGHBOURS paged: %d entries over %d pages, each <= 1100 bytes", entries, pages);
    CHECK(esc_ok, "neighbour names JSON-escaped, invalid UTF-8 -> '?'");
    memset(mesh.neighbors, 0, sizeof(mesh.neighbors));

    /* FRAME with a signed advert -> relayed with our hash, reported, never offered back */
    mc_advert_info_t info = { .type = ADV_TYPE_REPEATER, .name = "ON0FAR" };
    mc_packet_t adv; mc_advert_build(&adv, &other, &info, (uint32_t)time(NULL));
    uint8_t frame_dg[BB_MAX_DGRAM]; size_t frame_len = 0;
    uint64_t offered0 = bb.offered;
    hub_send_frame(&h, &adv, frame_dg, &frame_len);
    r = hub_wait_type(&h, &bb, BB_T_OBSERVE, &body, &blen, d, sizeof(d));
    CHECK(r > 0 && body[0] == BB_OBS_FROM_BACKBONE && body[1] == BB_DISP_FORWARDED && rd_u16le(&body[2]) == 0,
          "FRAME advert -> OBSERVE (from backbone, forwarded)");
    int adv_q = -1;
    for (int i = 0; i < MESH_TXQ_SIZE; i++)
        if (mesh.txq[i].used && pkt_payload_type(&mesh.txq[i].pkt) == PAYLOAD_TYPE_ADVERT) adv_q = i;
    CHECK(adv_q >= 0 && pkt_path_hash_count(&mesh.txq[adv_q].pkt) == 1 && mesh.txq[adv_q].pkt.path[0] == id.pub[0],
          "bridged advert queued for RF with our hash appended");
    CHECK(bb.offered == offered0 && bb.injected == 1, "a frame from the hub is never offered back as BRIDGE");
    CHECK(mesh.stats.rx_total == 0 && mesh_neighbor_count(&mesh) == 0,
          "no RF counters, no neighbour entry for a backbone frame");

    /* replayed FRAME datagram */
    uint64_t rej0 = bb.rejected;
    sendto(h.fd, frame_dg, frame_len, 0, (struct sockaddr *)&h.peer, sizeof(h.peer));
    pump(&bb, 50);
    CHECK(bb.rejected == rej0 + 1 && bb.injected == 1, "replayed FRAME rejected (sequence window)");

    /* a ping from the hub is relayed but not answered (no local services) */
    mc_packet_t ping; build_public_text(&cfg, "Far: ping", &ping);
    int q0 = txq_used(&mesh);
    hub_send_frame(&h, &ping, NULL, NULL);
    r = hub_wait_type(&h, &bb, BB_T_OBSERVE, &body, &blen, d, sizeof(d));
    CHECK(r > 0 && body[1] == BB_DISP_FORWARDED && mesh.stats.pong_sent == 0 && mesh.stats.ping_seen == 0 &&
          txq_used(&mesh) == q0 + 1, "backbone 'ping' relayed, no pong");

    /* a private message from the hub is refused by the content policy */
    mc_packet_t dm; memset(&dm, 0, sizeof(dm));
    dm.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD);
    dm.payload_len = 20; for (int i = 0; i < 20; i++) dm.payload[i] = (uint8_t)(0x30 + i);
    q0 = txq_used(&mesh);
    hub_send_frame(&h, &dm, NULL, NULL);
    r = hub_wait_type(&h, &bb, BB_T_OBSERVE, &body, &blen, d, sizeof(d));
    CHECK(r > 0 && body[0] == BB_OBS_FROM_BACKBONE && body[1] == BB_DISP_POLICY && txq_used(&mesh) == q0,
          "backbone DM -> OBSERVE disposition policy, nothing queued");

    /* an RF flood we relay is offered up with our hash; OBSERVE carries its rssi/snr */
    mc_packet_t grp; make_public_grp(&cfg, ROUTE_TYPE_FLOOD, &grp);
    grp.path_len = 0x01; grp.path[0] = 0x42;
    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&grp, raw, sizeof(raw));
    int disp = mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    backbone_observe(&bb, raw, (size_t)n, -80, 40, 0, disp);
    r = hub_wait_type(&h, &bb, BB_T_BRIDGE, &body, &blen, d, sizeof(d));
    mc_packet_t up;
    bool up_ok = r > 0 && body[0] == 0 && body[1] == blen - 10 && pkt_parse(&up, &body[10], body[1]) == 0 &&
                 pkt_path_hash_count(&up) == 2 && up.path[0] == 0x42 && up.path[1] == id.pub[0];
    if (up_ok) { uint8_t hsh[8]; pkt_calc_hash(&up, hsh); up_ok = memcmp(hsh, &body[2], 8) == 0; }
    CHECK(disp == MESH_RX_FORWARDED && up_ok, "RF flood relayed -> BRIDGE with our hash appended + pkt_hash");
    r = hub_wait_type(&h, &bb, BB_T_OBSERVE, &body, &blen, d, sizeof(d));
    CHECK(r > 0 && body[0] == 0 && body[1] == BB_DISP_FORWARDED && (int16_t)rd_u16le(&body[2]) == -80 &&
          (int8_t)body[4] == 40 && body[5] == n && !memcmp(&body[14], raw, (size_t)n),
          "RF frame -> OBSERVE with rssi/snr and the frame as heard");
    disp = mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(disp == MESH_RX_DUPLICATE, "its RF echo is a duplicate (disposition 1)");

    /* rate limit: 30/min holds 10; three used so far (advert, ping, DM) */
    uint64_t lim0 = bb.limited;
    for (int i = 0; i < 12; i++) {
        mc_packet_t x = dm; x.payload[0] = (uint8_t)(0x80 + i);
        hub_send_frame(&h, &x, NULL, NULL);
    }
    pump(&bb, 100);
    bool saw_limited = false;
    for (int k = 0; k < 14; k++) {
        if (hub_wait_type(&h, &bb, BB_T_OBSERVE, &body, &blen, d, sizeof(d)) <= 0) break;
        if (body[1] == BB_DISP_LIMITED) saw_limited = true;
    }
    CHECK(bb.limited > lim0 && saw_limited, "rate limit: %llu FRAMEs refused + reported as limited",
          (unsigned long long)(bb.limited - lim0));

    /* RESET: a stale/forged one is ignored; a valid one makes the repeater re-register */
    uint8_t rs[BB_RESET_LEN];
    rej0 = bb.rejected;
    size_t rn = bb_build_reset(rs, sizeof(rs), &hub, bb.sid, bb.seq_out + 5, (uint32_t)time(NULL));
    sendto(h.fd, rs, rn, 0, (struct sockaddr *)&h.peer, sizeof(h.peer));
    pump(&bb, 30);
    CHECK(bb.state == BB_UP && bb.rejected == rej0 + 1, "RESET for a seq we never sent: ignored");
    rn = bb_build_reset(rs, sizeof(rs), &other, bb.sid, bb.seq_out, (uint32_t)time(NULL));
    sendto(h.fd, rs, rn, 0, (struct sockaddr *)&h.peer, sizeof(h.peer));
    pump(&bb, 30);
    CHECK(bb.state == BB_UP, "RESET signed by another key: ignored");
    rn = bb_build_reset(rs, sizeof(rs), &hub, bb.sid, bb.seq_out, (uint32_t)time(NULL));
    sendto(h.fd, rs, rn, 0, (struct sockaddr *)&h.peer, sizeof(h.peer));
    bool rehello = false;
    for (int k = 0; k < 40 && !rehello; k++) {
        r = hub_wait(&h, &bb, d, sizeof(d), 100);
        if (r > 0 && d[3] == BB_T_HELLO && rd_u32le(&d[6]) > hello_ts) rehello = true;
    }
    CHECK(rehello && bb.state == BB_HELLO_SENT, "valid RESET -> new HELLO (later ts)");

    backbone_close(&bb);
    CHECK(bb.state == BB_OFF && bb.fd < 0, "close");
    close(h.fd);
}

int main(void)
{
    test_header();
    test_pathlen();
    test_serialize();
    test_transport_codes();
    test_identity();
    test_advert();
    test_mesh_flood();
    test_mesh_direct();
    test_mesh_policy();
    test_ping_pong();
    test_tx_failure_resets_radio();
    test_rx_errors();
    test_ping_channel();
    test_probe();
    test_mbox();
    test_timeofday();
    test_link();
    test_blacklist();
    test_aprs();
    test_hotspot();
    test_crypto();
    test_airtime();
    test_config();
    test_node_name();
    test_rooms();
    test_monitor();
    test_backbone_codec();
    test_backbone_session();

    printf("\n%s (%d failure%s)\n", g_fail ? "TESTS FAILED" : "ALL TESTS PASSED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
