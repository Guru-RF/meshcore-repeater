/*
 * aprs.h - APRS position/timestamp formatting (base-91 compressed).
 *
 * Ported from the RF.Guru PiLoRa433APRSiGate (aprs.c), the operator's working
 * LoRa-APRS iGate, so the meshcore repeater emits identical APRS position
 * strings when it gates MeshCore node positions to APRS-IS.
 */
#ifndef MC_APRS_H
#define MC_APRS_H

#include <stddef.h>

/* Write a zulu timestamp "DDHHMMz" into out (needs >= 8 bytes). */
void aprs_make_timestamp_z(char *out, size_t outsize, int day, int hour, int minute);

/* Write a base-91 compressed position string into out.
 * symbol is a 2-char "table+code" string (e.g. "R&").
 * speed/course < 0 produce a stationary position ("  A").
 * Returns 0 on success, -1 if lat/lon/symbol are out of range (out untouched). */
int aprs_make_position(char *out, size_t outsize, double lat, double lon,
                       int speed, int course, const char *symbol);

#endif /* MC_APRS_H */
