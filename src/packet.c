/* packet.c - MeshCore wire format (de)serialisation and dedup hash. */
#include "packet.h"
#include "util.h"
#include "crypto/sha256.h"

#include <string.h>

bool pkt_valid_path_len(uint8_t path_len)
{
    uint8_t hash_count = path_len & 0x3F;
    uint8_t hash_size  = (uint8_t)((path_len >> 6) + 1);
    if (hash_size == 4)               /* top bits 0b11 reserved/invalid */
        return false;
    return (hash_count * hash_size) <= MC_MAX_PATH_SIZE;
}

int pkt_parse(mc_packet_t *pkt, const uint8_t *src, size_t len)
{
    if (len < 2 || len > MC_MAX_TRANS_UNIT)
        return -1;

    memset(pkt, 0, sizeof(*pkt));

    size_t i = 0;
    pkt->header = src[i++];
    pkt->marked_dnr = (pkt->header == 0xFF);

    if (pkt_has_transport_codes(pkt)) {
        if (i + 4 > len)
            return -2;
        pkt->transport_codes[0] = rd_u16le(&src[i]); i += 2;
        pkt->transport_codes[1] = rd_u16le(&src[i]); i += 2;
    }

    if (i >= len)
        return -3;
    pkt->path_len = src[i++];
    if (!pkt_valid_path_len(pkt->path_len))
        return -4;

    uint16_t pbl = pkt_path_byte_len(pkt);
    if (i + pbl > len)
        return -5;
    memcpy(pkt->path, &src[i], pbl);
    i += pbl;

    size_t payload_len = len - i;
    if (payload_len > MC_MAX_PACKET_PAYLOAD)
        return -6;
    pkt->payload_len = (uint16_t)payload_len;
    memcpy(pkt->payload, &src[i], payload_len);

    return 0;
}

int pkt_raw_length(const mc_packet_t *pkt)
{
    return 2 + pkt_path_byte_len(pkt) + pkt->payload_len +
           (pkt_has_transport_codes(pkt) ? 4 : 0);
}

int pkt_serialize(const mc_packet_t *pkt, uint8_t *dest, size_t destsz)
{
    int raw = pkt_raw_length(pkt);
    if (raw < 0 || (size_t)raw > destsz || raw > MC_MAX_TRANS_UNIT)
        return -1;
    if (pkt->payload_len > MC_MAX_PACKET_PAYLOAD)
        return -2;
    if (!pkt_valid_path_len(pkt->path_len))
        return -3;

    size_t i = 0;
    dest[i++] = pkt->header;
    if (pkt_has_transport_codes(pkt)) {
        wr_u16le(&dest[i], pkt->transport_codes[0]); i += 2;
        wr_u16le(&dest[i], pkt->transport_codes[1]); i += 2;
    }
    dest[i++] = pkt->path_len;

    uint16_t pbl = pkt_path_byte_len(pkt);
    memcpy(&dest[i], pkt->path, pbl); i += pbl;

    memcpy(&dest[i], pkt->payload, pkt->payload_len); i += pkt->payload_len;

    return (int)i;
}

void pkt_calc_hash(const mc_packet_t *pkt, uint8_t out[MC_MAX_HASH_SIZE])
{
    SHA256_CTX ctx;
    uint8_t digest[SHA256_BLOCK_SIZE];
    uint8_t t = pkt_payload_type(pkt);

    sha256_init(&ctx);
    sha256_update(&ctx, &t, 1);
    if (t == PAYLOAD_TYPE_TRACE) {
        /* MeshCore hashes the (uint16_t) path_len for TRACE so it may revisit
         * nodes on the return path. We replicate the 2-byte little-endian field. */
        uint8_t pl[2];
        wr_u16le(pl, pkt->path_len);
        sha256_update(&ctx, pl, 2);
    }
    sha256_update(&ctx, pkt->payload, pkt->payload_len);
    sha256_final(&ctx, digest);

    memcpy(out, digest, MC_MAX_HASH_SIZE);
}
