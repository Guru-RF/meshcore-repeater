/* mbox.c - the #mbox mailbox store + parse + format (see mbox.h). */
#include "mbox.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

void mbox_init(mc_mbox *mb)
{
    mb->head = 0;
    mb->count = 0;
}

/* Copy the base call (up to the first '-') of s into out. */
static void base_call(const char *s, char *out, size_t sz)
{
    size_t i = 0;
    while (s && s[i] && s[i] != '-' && i + 1 < sz) { out[i] = s[i]; i++; }
    out[i] = '\0';
}

mbox_cmd_t mbox_classify(const char *body, char *mention, size_t msz, const char **msg)
{
    if (msg) *msg = "";
    if (mention && msz) mention[0] = '\0';
    if (!body) return MBOX_OTHER;
    while (*body == ' ' || *body == '\t') body++;

    if (*body == '@') {                     /* "@CALL text" -> store */
        const char *p = body + 1;
        size_t i = 0;
        while (*p && *p != ' ' && *p != '\t') { if (mention && i + 1 < msz) mention[i++] = *p; p++; }
        if (mention && msz) mention[i] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (i == 0 || *p == '\0') return MBOX_OTHER;   /* need a call AND a message */
        if (msg) *msg = p;
        return MBOX_MENTION;
    }
    if (!strncasecmp(body, "fetch", 5)) {   /* exactly "fetch" (trailing ws ok) */
        const char *p = body + 5;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == '\0') return MBOX_FETCH;
    }
    return MBOX_OTHER;
}

void mbox_store(mc_mbox *mb, const char *to, const char *from, const char *msg, uint32_t ts)
{
    mc_mbox_entry_t *e = &mb->e[mb->head];
    snprintf(e->to,   sizeof(e->to),   "%s", to   ? to   : "");
    snprintf(e->from, sizeof(e->from), "%s", from ? from : "");
    snprintf(e->msg,  sizeof(e->msg),  "%s", msg  ? msg  : "");
    e->ts = ts;
    mb->head = (mb->head + 1) % MC_MBOX_MAX;
    if (mb->count < MC_MBOX_MAX) mb->count++;
}

int mbox_format_fetch(const mc_mbox *mb, const char *call, char *out, size_t outsz, int *total)
{
    if (outsz) out[0] = '\0';
    if (total) *total = 0;
    char want[MC_MBOX_CALL];
    base_call(call, want, sizeof(want));

    int matches = 0;      /* total matching entries (whether or not they fit) */
    int shown = 0;        /* entries actually written to `out` */
    size_t off = 0;
    bool full = false;
    int oldest = (mb->head - mb->count + MC_MBOX_MAX) % MC_MBOX_MAX;
    for (int k = 0; k < mb->count; k++) {
        const mc_mbox_entry_t *e = &mb->e[(oldest + k) % MC_MBOX_MAX];
        char eb[MC_MBOX_CALL];
        base_call(e->to, eb, sizeof(eb));
        if (strcasecmp(eb, want) != 0)
            continue;
        matches++;
        if (full)                                       /* still count matches, stop writing */
            continue;
        size_t room = off < outsz ? outsz - off : 0;
        int n = snprintf(out + off, room, "%s[%s] %s", off ? " | " : "", e->from, e->msg);
        if (n < 0 || (size_t)n >= room) {               /* would not fit whole -> back it out */
            out[off] = '\0';
            full = true;
            continue;
        }
        off += (size_t)n;
        shown++;
    }
    if (total) *total = matches;
    return shown;
}

const char *mbox_help_text(void)
{
    return "mbox: leave a message with '@CALL text' (also flooded); send 'fetch' for yours";
}
