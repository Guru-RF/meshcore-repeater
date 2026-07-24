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

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *in, uint8_t *out, size_t outsz)
{
    size_t len = strlen(in);
    if (len == 0 || len % 4 != 0)      /* padded base64 is a multiple of 4 */
        return -1;
    size_t outn = 0;
    for (size_t i = 0; i < len; i += 4) {
        int v[4], pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* '=' only in the final quartet, in the last one or two slots */
                if (i + 4 != len || j < 2)
                    return -1;
                v[j] = 0; pad++;
            } else {
                if (pad)               /* data after padding is invalid */
                    return -1;
                v[j] = b64val(c);
                if (v[j] < 0)
                    return -1;
            }
        }
        uint32_t trip = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                        ((uint32_t)v[2] << 6)  |  (uint32_t)v[3];
        int nbytes = 3 - pad;          /* 3, 2 or 1 output bytes per quartet */
        for (int b = 0; b < nbytes; b++) {
            if (outn >= outsz)
                return -1;
            out[outn++] = (uint8_t)((trip >> (16 - 8 * b)) & 0xFF);
        }
    }
    return (int)outn;
}
