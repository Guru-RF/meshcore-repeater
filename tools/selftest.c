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

#include <stdio.h>
#include <string.h>

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

static void test_mesh_flood(void)
{
    printf("[mesh flood forwarding + dedup]\n");
    mc_identity_t id;
    mc_identity_generate(&id);
    mc_config_t cfg;
    config_defaults(&cfg);

    /* init radio (mock HAL) so airtime calc works */
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio);
    sx126x_init(&radio);

    mc_mesh_t mesh;
    mesh_init(&mesh, &id, &cfg);

    /* craft an inbound flood TXT_MSG with one hop already in the path */
    mc_packet_t p = {0};
    p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD);
    p.path_len = 0x01;          /* 1 hop, 1-byte hash */
    p.path[0] = 0x42;
    p.payload_len = 8;
    memcpy(p.payload, "abcdefgh", 8);

    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&p, raw, sizeof(raw));

    mesh_on_recv(&mesh, raw, (size_t)n, -80, 40);
    CHECK(mesh.stats.fwd_flood == 1, "first copy forwarded (fwd_flood=%llu)",
          (unsigned long long)mesh.stats.fwd_flood);

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
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);

    /* direct packet whose first path hash is us, then a downstream node */
    mc_packet_t p = {0};
    p.header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_DIRECT);
    p.path_len = 0x02;          /* 2 hops, 1-byte */
    p.path[0] = id.pub[0];      /* us */
    p.path[1] = 0x99;           /* next hop */
    p.payload_len = 4;
    memcpy(p.payload, "ping", 4);

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
    CHECK(cfg.bandwidth == 250 && cfg.spreading_factor == 10 && cfg.coding_rate == 5,
          "default modem params match MeshCore (BW250/SF10/CR4-5)");
    CHECK(config_set(&cfg, "frequency", "434.000") == 0 && cfg.frequency == 434.0,
          "set frequency");
    CHECK(config_set(&cfg, "frequency", "9999") == -2, "reject out-of-range frequency");
    CHECK(config_set(&cfg, "sync_word", "public") == 0 && cfg.sync_word == 0x3444,
          "sync_word public -> 0x3444");
    CHECK(config_set(&cfg, "bogus", "x") == -1, "unknown key rejected");

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
    test_airtime();
    test_config();

    printf("\n%s (%d failure%s)\n", g_fail ? "TESTS FAILED" : "ALL TESTS PASSED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
