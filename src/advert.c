/* advert.c - build / verify MeshCore advertisement packets. */
#include "advert.h"
#include "util.h"

#include <string.h>
#include <math.h>

#define ADV_PUB_OFF  0
#define ADV_TS_OFF   (MC_PUB_KEY_SIZE)              /* 32 */
#define ADV_SIG_OFF  (MC_PUB_KEY_SIZE + 4)          /* 36 */
#define ADV_DATA_OFF (MC_PUB_KEY_SIZE + 4 + MC_SIGNATURE_SIZE) /* 100 */

/* Encode app_data into buf (>= MC_MAX_ADVERT_DATA). Returns app_data length. */
static size_t encode_app_data(const mc_advert_info_t *info, uint8_t *buf)
{
    size_t i = 1;
    uint8_t flags = (uint8_t)(info->type & 0x0F);

    if (info->has_location) {
        flags |= ADV_LATLON_MASK;
        int32_t lat = (int32_t)lround(info->latitude * 1e6);
        int32_t lon = (int32_t)lround(info->longitude * 1e6);
        if (i + 8 <= MC_MAX_ADVERT_DATA) {
            wr_i32le(&buf[i], lat); i += 4;
            wr_i32le(&buf[i], lon); i += 4;
        }
    }

    if (info->name && info->name[0]) {
        size_t namelen = strlen(info->name);
        size_t room = MC_MAX_ADVERT_DATA - i;
        if (namelen > room)
            namelen = room;
        if (namelen > 0) {
            flags |= ADV_NAME_MASK;
            memcpy(&buf[i], info->name, namelen);
            i += namelen;
        }
    }

    buf[0] = flags;
    return i;
}

int mc_advert_build(mc_packet_t *pkt, const mc_identity_t *id,
                    const mc_advert_info_t *info, uint32_t timestamp)
{
    if (!id->has_secret)
        return -1;

    uint8_t app_data[MC_MAX_ADVERT_DATA];
    size_t app_len = encode_app_data(info, app_data);

    memset(pkt, 0, sizeof(*pkt));
    pkt->header = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_ADVERT, ROUTE_TYPE_FLOOD);
    pkt->path_len = 0; /* 0 hops, hash size 1 */

    /* signed message = pub || timestamp(LE) || app_data */
    uint8_t msg[MC_PUB_KEY_SIZE + 4 + MC_MAX_ADVERT_DATA];
    size_t mlen = 0;
    memcpy(&msg[mlen], id->pub, MC_PUB_KEY_SIZE); mlen += MC_PUB_KEY_SIZE;
    wr_u32le(&msg[mlen], timestamp);              mlen += 4;
    memcpy(&msg[mlen], app_data, app_len);        mlen += app_len;

    uint8_t sig[MC_SIGNATURE_SIZE];
    if (mc_identity_sign(id, sig, msg, mlen) != 0)
        return -2;

    /* assemble payload */
    memcpy(&pkt->payload[ADV_PUB_OFF], id->pub, MC_PUB_KEY_SIZE);
    wr_u32le(&pkt->payload[ADV_TS_OFF], timestamp);
    memcpy(&pkt->payload[ADV_SIG_OFF], sig, MC_SIGNATURE_SIZE);
    memcpy(&pkt->payload[ADV_DATA_OFF], app_data, app_len);
    pkt->payload_len = (uint16_t)(ADV_DATA_OFF + app_len);

    return 0;
}

int mc_advert_extract(const mc_packet_t *pkt, uint8_t *type, char *name, size_t namesz)
{
    if (name && namesz)
        name[0] = '\0';
    if (pkt->payload_len < ADV_DATA_OFF)
        return -1;

    const uint8_t *app = &pkt->payload[ADV_DATA_OFF];
    size_t app_len = pkt->payload_len - ADV_DATA_OFF;
    if (app_len == 0)
        return -1;

    uint8_t flags = app[0];
    if (type)
        *type = (uint8_t)(flags & 0x0F);

    size_t i = 1;
    if (flags & ADV_LATLON_MASK) i += 8;
    if (flags & ADV_FEAT1_MASK)  i += 2;
    if (flags & ADV_FEAT2_MASK)  i += 2;

    if ((flags & ADV_NAME_MASK) && name && namesz && i < app_len) {
        size_t nlen = app_len - i;
        if (nlen > namesz - 1)
            nlen = namesz - 1;
        memcpy(name, &app[i], nlen);
        name[nlen] = '\0';
    }
    return 0;
}

bool mc_advert_verify(const mc_packet_t *pkt, uint8_t out_pub[MC_PUB_KEY_SIZE])
{
    if (pkt_payload_type(pkt) != PAYLOAD_TYPE_ADVERT)
        return false;
    if (pkt->payload_len < ADV_DATA_OFF) /* must contain at least pub+ts+sig */
        return false;

    const uint8_t *pub = &pkt->payload[ADV_PUB_OFF];
    uint32_t timestamp = rd_u32le(&pkt->payload[ADV_TS_OFF]);
    const uint8_t *sig = &pkt->payload[ADV_SIG_OFF];
    const uint8_t *app_data = &pkt->payload[ADV_DATA_OFF];
    size_t app_len = pkt->payload_len - ADV_DATA_OFF;

    uint8_t msg[MC_PUB_KEY_SIZE + 4 + MC_MAX_ADVERT_DATA];
    if (app_len > MC_MAX_ADVERT_DATA)
        app_len = MC_MAX_ADVERT_DATA; /* defensive: ignore overflow tail */
    size_t mlen = 0;
    memcpy(&msg[mlen], pub, MC_PUB_KEY_SIZE);     mlen += MC_PUB_KEY_SIZE;
    wr_u32le(&msg[mlen], timestamp);              mlen += 4;
    memcpy(&msg[mlen], app_data, app_len);        mlen += app_len;

    if (!mc_identity_verify(pub, sig, msg, mlen))
        return false;

    if (out_pub)
        memcpy(out_pub, pub, MC_PUB_KEY_SIZE);
    return true;
}
