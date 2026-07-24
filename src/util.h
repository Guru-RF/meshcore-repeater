/*
 * util.h - small endian / byte helpers used across the repeater.
 *
 * MeshCore serialises multi-byte integers with a raw memcpy, i.e. in the
 * native (little-endian) byte order of the AVR/ARM nodes it runs on.  To stay
 * portable (and correct on a big-endian host) we encode/decode explicitly as
 * little-endian here rather than relying on the host layout.
 */
#ifndef MC_UTIL_H
#define MC_UTIL_H

#include <stdint.h>
#include <stddef.h>

static inline uint16_t rd_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t rd_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline int32_t rd_i32le(const uint8_t *p)
{
    return (int32_t)rd_u32le(p);
}

static inline void wr_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void wr_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline void wr_i32le(uint8_t *p, int32_t v)
{
    wr_u32le(p, (uint32_t)v);
}

/* hex helpers for logging / key files (return bytes written, or <0 on error) */
size_t bin2hex(const uint8_t *in, size_t n, char *out, size_t outsz);
int    hex2bin(const char *in, uint8_t *out, size_t outsz);

/* Decode standard base64 (with '=' padding) into out.
 * Returns bytes decoded, or -1 on invalid input / overflow.  Used for channel
 * PSKs, which MeshCore shares in base64 (e.g. "izOH6cXN6mrJ5e26oRXNcg=="). */
int    base64_decode(const char *in, uint8_t *out, size_t outsz);

#endif /* MC_UTIL_H */
