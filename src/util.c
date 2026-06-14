/* util.c - hex helpers */
#include "util.h"
#include <string.h>

static const char HEXD[] = "0123456789abcdef";

size_t bin2hex(const uint8_t *in, size_t n, char *out, size_t outsz)
{
    if (outsz < n * 2 + 1)
        return 0;
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = HEXD[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = HEXD[in[i] & 0xF];
    }
    out[n * 2] = '\0';
    return n * 2;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string into out; returns number of bytes decoded, or -1 on error. */
int hex2bin(const char *in, uint8_t *out, size_t outsz)
{
    size_t len = strlen(in);
    if (len % 2 != 0)
        return -1;
    size_t nbytes = len / 2;
    if (nbytes > outsz)
        return -1;
    for (size_t i = 0; i < nbytes; i++) {
        int hi = hexval(in[i * 2]);
        int lo = hexval(in[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)nbytes;
}
