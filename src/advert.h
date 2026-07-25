/*
 * advert.h - build a signed self-advertisement for this repeater.
 *
 * ADVERT payload layout (verified against Mesh::createAdvert / AdvertDataHelpers):
 *   [0..31]   pub_key      (32 bytes)
 *   [32..35]  timestamp     (uint32 little-endian, UNIX seconds)
 *   [36..99]  signature     (64 bytes, Ed25519)
 *   [100..]   app_data      (0..32 bytes)
 *
 * Signed message = pub_key(32) || timestamp(4 LE) || app_data(N).
 *
 * app_data:
 *   [0]       flags = type(bits0-3) | ADV_LATLON_MASK | ADV_FEAT1/2_MASK | ADV_NAME_MASK
 *   then, in order, the present optional fields:
 *     lat int32 LE (degrees*1e6), lon int32 LE, feat1 u16 LE, feat2 u16 LE, name (raw bytes)
 *
 * The advert is route FLOOD so neighbours re-flood it across the mesh.
 */
#ifndef MC_ADVERT_H
#define MC_ADVERT_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"
#include "identity.h"

/* advert node types */
#define ADV_TYPE_NONE     0
#define ADV_TYPE_CHAT     1
#define ADV_TYPE_REPEATER 2
#define ADV_TYPE_ROOM     3
#define ADV_TYPE_SENSOR   4

/* app_data flag bits */
#define ADV_LATLON_MASK 0x10
#define ADV_FEAT1_MASK  0x20
#define ADV_FEAT2_MASK  0x40
#define ADV_NAME_MASK   0x80

typedef struct {
    uint8_t     type;        /* ADV_TYPE_* */
    bool        has_location;
    double      latitude;    /* degrees */
    double      longitude;   /* degrees */
    const char *name;        /* may be NULL */
} mc_advert_info_t;

/*
 * Build a signed advert packet for this node.
 * timestamp = current UNIX time (seconds). Returns 0 on success.
 */
int mc_advert_build(mc_packet_t *pkt, const mc_identity_t *id,
                    const mc_advert_info_t *info, uint32_t timestamp);

/*
 * Verify a received ADVERT packet's signature.
 * On success returns true and (if non-NULL) copies the advertiser's 32-byte
 * public key to out_pub.
 */
bool mc_advert_verify(const mc_packet_t *pkt, uint8_t out_pub[MC_PUB_KEY_SIZE]);

/*
 * Extract the node type and name from a received ADVERT's app_data.
 * name is always null-terminated (empty if none). Returns 0 on success.
 */
int  mc_advert_extract(const mc_packet_t *pkt, uint8_t *type, char *name, size_t namesz);

/* Extract the advertised GPS position, if present. Returns true and fills
 * lat/lon (degrees) when the advert carries a location, false otherwise. */
bool mc_advert_extract_location(const mc_packet_t *pkt, double *lat, double *lon);

#endif /* MC_ADVERT_H */
