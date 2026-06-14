/*
 * identity.h - the repeater's Ed25519 identity.
 *
 * MeshCore node identities are Ed25519 keypairs (32-byte public key, 64-byte
 * private key, 64-byte signatures).  A node's 1-byte path hash is simply the
 * first byte of its public key (no hashing - see Identity::copyHashTo).
 *
 * We use TweetNaCl for Ed25519; its signatures are RFC 8032 standard and
 * therefore verify against real MeshCore nodes (and vice versa).  The 64-byte
 * secret key we store is TweetNaCl's seed||pubkey form; it never goes on air.
 */
#ifndef MC_IDENTITY_H
#define MC_IDENTITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "packet.h"

typedef struct {
    uint8_t pub[MC_PUB_KEY_SIZE];   /* 32 bytes, on-air identity */
    uint8_t sec[MC_PRV_KEY_SIZE];   /* 64 bytes (TweetNaCl seed||pub), local only */
    bool    has_secret;
} mc_identity_t;

/* Generate a fresh keypair. */
void mc_identity_generate(mc_identity_t *id);

/* Detached sign: writes MC_SIGNATURE_SIZE bytes into sig. Returns 0 on success. */
int  mc_identity_sign(const mc_identity_t *id, uint8_t sig[MC_SIGNATURE_SIZE],
                      const uint8_t *msg, size_t msglen);

/* Verify a detached signature against a 32-byte public key. Returns true if valid. */
bool mc_identity_verify(const uint8_t pub[MC_PUB_KEY_SIZE],
                        const uint8_t sig[MC_SIGNATURE_SIZE],
                        const uint8_t *msg, size_t msglen);

/* Copy this node's path hash (first len bytes of pub) to dest. */
static inline void mc_identity_copy_hash(const mc_identity_t *id, uint8_t *dest, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++)
        dest[i] = id->pub[i];
}

/* Does hash[0..len-1] match the first len bytes of our public key? */
bool mc_identity_hash_match(const mc_identity_t *id, const uint8_t *hash, uint8_t len);

/* Persistence: simple text file ("pub=<hex>\nsec=<hex>\n"). Returns 0 on success. */
int  mc_identity_load(mc_identity_t *id, const char *path);
int  mc_identity_save(const mc_identity_t *id, const char *path);

#endif /* MC_IDENTITY_H */
