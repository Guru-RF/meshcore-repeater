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
#include "../src/crypto/sha256.h"
#include "../src/crypto/aes128.h"

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
    sx126x_cfg_t radio; config_to_sx126x(&cfg, &radio); sx126x_init(&radio);
    mc_mesh_t mesh; mesh_init(&mesh, &id, &cfg);
    uint8_t raw[MC_MAX_TRANS_UNIT];

    /* a "ping" on the public channel triggers a "pong" */
    mc_packet_t ping;
    build_public_text(&cfg, "Alice: ping", &ping);
    int n = pkt_serialize(&ping, raw, sizeof(raw));
    mesh_on_recv(&mesh, raw, (size_t)n, -70, 20);
    CHECK(mesh.stats.ping_seen == 1 && mesh.stats.pong_sent == 1, "ping seen -> pong sent");
    CHECK(mesh.stats.fwd_grp_public == 1, "the ping itself was forwarded (public)");

    /* the enqueued pong must decrypt to '<name>: pong' on the same channel */
    int found = -1;
    for (int k = 0; k < MESH_TXQ_SIZE; k++)
        if (mesh.txq[k].used && pkt_payload_type(&mesh.txq[k].pkt) == PAYLOAD_TYPE_GRP_TXT) { found = k; break; }
    CHECK(found >= 0, "pong enqueued for TX");
    if (found >= 0) {
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
    test_blacklist();
    test_crypto();
    test_airtime();
    test_config();

    printf("\n%s (%d failure%s)\n", g_fail ? "TESTS FAILED" : "ALL TESTS PASSED",
           g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
