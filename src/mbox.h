/*
 * mbox.h - the #mbox mailbox room: store @mentions, deliver on "fetch".
 *
 * The mailbox lives on the REPEATER (a hotspot just forwards #mbox up to it). On
 * the #mbox channel a message "@CALL text" is stored (indexed by CALL) and also
 * flooded normally; "fetch" makes the repeater reply with the messages left for
 * the fetcher's call; anything else gets a one-line help reply. Fetch/help
 * replies are routed back along the reverse of the path the command took (through
 * any hotspot) instead of flooding the mesh. This module is the store + parse +
 * format; the mesh layer wires it to the channel and routes the replies.
 */
#ifndef MC_MBOX_H
#define MC_MBOX_H

#include <stdint.h>
#include <stddef.h>

#define MC_MBOX_MAX   32     /* stored messages (ring; oldest dropped when full) */
#define MC_MBOX_CALL  24     /* call / mention length */
#define MC_MBOX_MSG   96     /* stored message body length */

typedef struct {
    char     to[MC_MBOX_CALL];    /* mentioned call (@who) */
    char     from[MC_MBOX_CALL];  /* sender */
    char     msg[MC_MBOX_MSG];    /* message body */
    uint32_t ts;
} mc_mbox_entry_t;

typedef struct mc_mbox {
    mc_mbox_entry_t e[MC_MBOX_MAX];
    int head;      /* next write slot (ring) */
    int count;     /* stored (<= MC_MBOX_MAX) */
} mc_mbox;

typedef enum { MBOX_OTHER = 0, MBOX_MENTION, MBOX_FETCH } mbox_cmd_t;

void mbox_init(mc_mbox *mb);

/* Classify a decrypted message body. MBOX_MENTION: `mention` gets the @call and
 * `*msg` points at the text (needs both a call and non-empty text). MBOX_FETCH:
 * exactly "fetch". Otherwise MBOX_OTHER. */
mbox_cmd_t mbox_classify(const char *body, char *mention, size_t msz, const char **msg);

void mbox_store(mc_mbox *mb, const char *to, const char *from, const char *msg, uint32_t ts);

/* Format the messages addressed to `call` (matched on the base call, SSID- and
 * case-insensitive) into `out`, oldest first, appending only whole entries that
 * fit (a partial last entry is backed out, never truncated mid-message). Returns
 * the number of entries actually written to `out`; if `total` is non-NULL it gets
 * the total number of matches (>= the return value when `out` filled up). */
int  mbox_format_fetch(const mc_mbox *mb, const char *call, char *out, size_t outsz, int *total);

const char *mbox_help_text(void);

#endif /* MC_MBOX_H */
