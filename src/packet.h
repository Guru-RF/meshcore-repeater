/*
 * packet.h - MeshCore over-the-air packet wire format.
 *
 * Verified against meshcore-dev/MeshCore src/Packet.{h,cpp} and docs/packet_format.md.
 *
 * Wire layout:
 *   [0]            header               (1 byte, 0bVVPPPPRR)
 *   [1..4]         transport_codes      (4 bytes, ONLY if route is a TRANSPORT_* type)
 *   [next]         path_len             (1 byte: bits0-5 hop count, bits6-7 hash_size-1)
 *   [next]         path                 (hop_count * hash_size bytes, 0..64)
 *   [next]         payload              (implicit length, up to 184 bytes)
 *
 * A repeater forwards by route type and never needs to decrypt payloads.  The
 * only payload it interprets is PAYLOAD_TYPE_ADVERT (to verify the Ed25519
 * signature before re-flooding it).
 */
#ifndef MC_PACKET_H
#define MC_PACKET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ---- sizes (from MeshCore.h / Packet.h) ---- */
#define MC_MAX_PACKET_PAYLOAD 184
#define MC_MAX_PATH_SIZE       64
#define MC_MAX_TRANS_UNIT     255
#define MC_PATH_HASH_SIZE       1   /* payload version 1 */
#define MC_PUB_KEY_SIZE        32
#define MC_PRV_KEY_SIZE        64
#define MC_SIGNATURE_SIZE      64
#define MC_MAX_HASH_SIZE        8   /* dedup hash length */
#define MC_MAX_ADVERT_DATA      32

/* ---- header bit field (0bVVPPPPRR) ---- */
#define PH_ROUTE_MASK 0x03
#define PH_TYPE_SHIFT 2
#define PH_TYPE_MASK  0x0F
#define PH_VER_SHIFT  6
#define PH_VER_MASK   0x03

/* ---- route types (bits 0-1) ---- */
#define ROUTE_TYPE_TRANSPORT_FLOOD  0x00
#define ROUTE_TYPE_FLOOD            0x01
#define ROUTE_TYPE_DIRECT           0x02
#define ROUTE_TYPE_TRANSPORT_DIRECT 0x03

/* ---- payload types (bits 2-5) ---- */
#define PAYLOAD_TYPE_REQ        0x00
#define PAYLOAD_TYPE_RESPONSE   0x01
#define PAYLOAD_TYPE_TXT_MSG    0x02
#define PAYLOAD_TYPE_ACK        0x03
#define PAYLOAD_TYPE_ADVERT     0x04
#define PAYLOAD_TYPE_GRP_TXT    0x05
#define PAYLOAD_TYPE_GRP_DATA   0x06
#define PAYLOAD_TYPE_ANON_REQ   0x07
#define PAYLOAD_TYPE_PATH       0x08
#define PAYLOAD_TYPE_TRACE      0x09
#define PAYLOAD_TYPE_MULTIPART  0x0A
#define PAYLOAD_TYPE_CONTROL    0x0B
#define PAYLOAD_TYPE_RAW_CUSTOM 0x0F

/* ---- payload versions (bits 6-7) ---- */
#define PAYLOAD_VER_1 0x00

/* in-memory packet representation */
typedef struct {
    uint8_t  header;
    uint16_t transport_codes[2];
    uint8_t  path_len;                          /* encoded byte (count|size), 1 byte on wire */
    uint8_t  path[MC_MAX_PATH_SIZE];
    uint16_t payload_len;
    uint8_t  payload[MC_MAX_PACKET_PAYLOAD];
    /* receive metadata (not transmitted) */
    int16_t  rssi_dbm;
    int8_t   snr_q;                             /* SNR in quarter-dB (snr*4), as MeshCore stores it */
    bool     marked_dnr;                        /* "do not retransmit" sentinel (header==0xFF) */
} mc_packet_t;

/* ---- header helpers ---- */
static inline uint8_t pkt_route_type(const mc_packet_t *p) { return p->header & PH_ROUTE_MASK; }
static inline uint8_t pkt_payload_type(const mc_packet_t *p) { return (uint8_t)((p->header >> PH_TYPE_SHIFT) & PH_TYPE_MASK); }
static inline uint8_t pkt_payload_ver(const mc_packet_t *p) { return (uint8_t)((p->header >> PH_VER_SHIFT) & PH_VER_MASK); }

static inline uint8_t pkt_make_header(uint8_t ver, uint8_t type, uint8_t route)
{
    return (uint8_t)((route & PH_ROUTE_MASK) |
                     ((type & PH_TYPE_MASK) << PH_TYPE_SHIFT) |
                     ((ver & PH_VER_MASK) << PH_VER_SHIFT));
}

static inline bool pkt_is_route_flood(const mc_packet_t *p)
{
    /* TRANSPORT_FLOOD(0) and FLOOD(1) -> bit1 clear */
    return (pkt_route_type(p) & 0x02) == 0;
}
static inline bool pkt_is_route_direct(const mc_packet_t *p)
{
    return (pkt_route_type(p) & 0x02) != 0;
}
static inline bool pkt_has_transport_codes(const mc_packet_t *p)
{
    uint8_t rt = pkt_route_type(p);
    return rt == ROUTE_TYPE_TRANSPORT_FLOOD || rt == ROUTE_TYPE_TRANSPORT_DIRECT;
}

/* ---- path helpers ---- */
static inline uint8_t pkt_path_hash_count(const mc_packet_t *p) { return p->path_len & 0x3F; }
static inline uint8_t pkt_path_hash_size(const mc_packet_t *p)  { return (uint8_t)((p->path_len >> 6) + 1); }
static inline uint16_t pkt_path_byte_len(const mc_packet_t *p)
{
    return (uint16_t)(pkt_path_hash_count(p) * pkt_path_hash_size(p));
}
static inline void pkt_set_path_hash_count(mc_packet_t *p, uint8_t n)
{
    p->path_len = (uint8_t)((p->path_len & 0xC0) | (n & 0x3F));
}

/* ---- serialisation ---- */

/* Parse raw wire bytes into pkt. Returns 0 on success, <0 on malformed packet. */
int  pkt_parse(mc_packet_t *pkt, const uint8_t *src, size_t len);

/* Serialise pkt into dest (must be >= MC_MAX_TRANS_UNIT). Returns wire length, or <0. */
int  pkt_serialize(const mc_packet_t *pkt, uint8_t *dest, size_t destsz);

/* Total wire length without serialising. */
int  pkt_raw_length(const mc_packet_t *pkt);

/* Validate an encoded path_len byte (matches MeshCore Packet::isValidPathLen). */
bool pkt_valid_path_len(uint8_t path_len);

/*
 * MeshCore dedup hash: SHA256 over [payload_type][TRACE-only: path_len(2 LE)][payload],
 * truncated to MC_MAX_HASH_SIZE (8) bytes. out must hold 8 bytes.
 */
void pkt_calc_hash(const mc_packet_t *pkt, uint8_t out[MC_MAX_HASH_SIZE]);

#endif /* MC_PACKET_H */
