/* aprs.c - APRS base-91 compressed position + timestamp.
 * Ported from RF.Guru PiLoRa433APRSiGate (the operator's working iGate). */
#include "aprs.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

void aprs_make_timestamp_z(char *out, size_t outsize, int day, int hour, int minute)
{
    snprintf(out, outsize, "%02d%02d%02dz", day, hour, minute);
}

/* Validate the 2-char symbol against ^([\/\\A-Z0-9])([\x21-\x7b\x7d])$ */
static int symbol_valid(const char *symbol)
{
    if (strlen(symbol) != 2)
        return 0;
    unsigned char t = (unsigned char)symbol[0];
    unsigned char c = (unsigned char)symbol[1];

    int t_ok = (t == '/' || t == '\\' ||
                (t >= 'A' && t <= 'Z') || (t >= '0' && t <= '9'));
    int c_ok = ((c >= 0x21 && c <= 0x7b) || c == 0x7d);
    return t_ok && c_ok;
}

int aprs_make_position(char *out, size_t outsize, double lat, double lon,
                       int speed, int course, const char *symbol)
{
    if (lat < -89.99999 || lat > 89.99999 ||
        lon < -179.99999 || lon > 179.99999)
        return -1;

    char symboltable;
    char symbolcode;
    if (symbol == NULL || symbol[0] == '\0') {
        symboltable = '/';
        symbolcode = '/';
    } else if (symbol_valid(symbol)) {
        symboltable = symbol[0];
        symbolcode = symbol[1];
    } else {
        return -1;
    }

    double latval = 380926.0 * (90.0 - lat);
    double lonval = 190463.0 * (180.0 + lon);
    char latstring[5];
    char lonstring[5];

    /* powers 91^3, 91^2, 91^1, 91^0 */
    long pw = 91L * 91L * 91L; /* i = 3 */
    for (int k = 0; k < 4; k++) {
        int v = (int)(latval / (double)pw);
        latval -= (double)v * (double)pw;
        latstring[k] = (char)(v + 33);

        v = (int)(lonval / (double)pw);
        lonval -= (double)v * (double)pw;
        lonstring[k] = (char)(v + 33);

        pw /= 91L;
    }
    latstring[4] = '\0';
    lonstring[4] = '\0';

    /* Overlay digit -> a..j substitution on the table char. */
    if (symboltable >= '0' && symboltable <= '9')
        symboltable = (char)(symboltable - '0' + 'a');

    char tail[8];
    if (speed >= 0 && course > 0 && course <= 360) {
        int cval = (int)((course + 2) / 4);
        if (cval > 89)
            cval = 0;
        int speednum = (int)((log((speed / 1.852) + 1) / log(1.08)) + 0.5);
        if (speednum > 89)
            speednum = 89;
        snprintf(tail, sizeof(tail), "%c%cA", (char)(cval + 33), (char)(speednum + 33));
    } else {
        snprintf(tail, sizeof(tail), "  A");
    }

    snprintf(out, outsize, "%c%s%s%c%s",
             symboltable, latstring, lonstring, symbolcode, tail);
    return 0;
}
