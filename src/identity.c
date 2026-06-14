/* identity.c - Ed25519 identity via TweetNaCl. */
#include "identity.h"
#include "util.h"
#include "crypto/tweetnacl.h"

#include <string.h>
#include <stdio.h>

/* Largest message we ever sign/verify: pub(32)+timestamp(4)+app_data(32) = 68.
 * TweetNaCl's signed-message buffer needs msglen + 64. Size generously. */
#define SIGN_SCRATCH (MC_SIGNATURE_SIZE + 128)

void mc_identity_generate(mc_identity_t *id)
{
    memset(id, 0, sizeof(*id));
    crypto_sign_keypair(id->pub, id->sec); /* sec = seed(32) || pub(32) */
    id->has_secret = true;
}

int mc_identity_sign(const mc_identity_t *id, uint8_t sig[MC_SIGNATURE_SIZE],
                     const uint8_t *msg, size_t msglen)
{
    if (!id->has_secret || msglen + MC_SIGNATURE_SIZE > SIGN_SCRATCH)
        return -1;

    uint8_t sm[SIGN_SCRATCH];
    unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, msg, (unsigned long long)msglen, id->sec);
    /* signed message = 64-byte signature || message; take the detached sig */
    memcpy(sig, sm, MC_SIGNATURE_SIZE);
    return 0;
}

bool mc_identity_verify(const uint8_t pub[MC_PUB_KEY_SIZE],
                        const uint8_t sig[MC_SIGNATURE_SIZE],
                        const uint8_t *msg, size_t msglen)
{
    if (msglen + MC_SIGNATURE_SIZE > SIGN_SCRATCH)
        return false;

    uint8_t sm[SIGN_SCRATCH];
    uint8_t out[SIGN_SCRATCH];
    unsigned long long mlen = 0;

    memcpy(sm, sig, MC_SIGNATURE_SIZE);
    memcpy(sm + MC_SIGNATURE_SIZE, msg, msglen);

    int rc = crypto_sign_open(out, &mlen, sm,
                              (unsigned long long)(msglen + MC_SIGNATURE_SIZE), pub);
    return rc == 0 && mlen == msglen;
}

bool mc_identity_hash_match(const mc_identity_t *id, const uint8_t *hash, uint8_t len)
{
    return memcmp(id->pub, hash, len) == 0;
}

int mc_identity_save(const mc_identity_t *id, const char *path)
{
    char pubhex[MC_PUB_KEY_SIZE * 2 + 1];
    char sechex[MC_PRV_KEY_SIZE * 2 + 1];
    bin2hex(id->pub, MC_PUB_KEY_SIZE, pubhex, sizeof(pubhex));
    bin2hex(id->sec, MC_PRV_KEY_SIZE, sechex, sizeof(sechex));

    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fprintf(f, "# MeshCore repeater identity - keep this file private!\n");
    fprintf(f, "pub=%s\n", pubhex);
    fprintf(f, "sec=%s\n", sechex);
    fclose(f);
    return 0;
}

int mc_identity_load(mc_identity_t *id, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    memset(id, 0, sizeof(*id));
    char line[512];
    bool have_pub = false, have_sec = false;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *val = eq + 1;
        /* strip trailing whitespace/newline */
        char *end = val + strlen(val);
        while (end > val && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
            *--end = '\0';

        if (strcmp(line, "pub") == 0) {
            if (hex2bin(val, id->pub, MC_PUB_KEY_SIZE) == MC_PUB_KEY_SIZE)
                have_pub = true;
        } else if (strcmp(line, "sec") == 0) {
            if (hex2bin(val, id->sec, MC_PRV_KEY_SIZE) == MC_PRV_KEY_SIZE)
                have_sec = true;
        }
    }
    fclose(f);

    if (!have_pub || !have_sec)
        return -2;
    id->has_secret = true;
    return 0;
}
