/*
 * monitor.c - live message monitors for the local control interface.
 *
 * Persistent control-socket clients that stream filtered message events. The
 * daemon is single-threaded and non-blocking: monitor fds are O_NONBLOCK, writes
 * are best-effort (a slow client drops events, never stalls forwarding), and a
 * closed client is reaped either on a failed write or via poll() hang-up.
 */
#include "monitor.h"

#include <string.h>
#include <strings.h>     /* strcasecmp */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

void monitor_init(mc_monitor *mon) { mon->n = 0; }
int  monitor_count(const mc_monitor *mon) { return mon->n; }

/* Remove entry idx, compacting the last entry into its slot. */
static void mon_drop(mc_monitor *mon, int idx)
{
    close(mon->conn[idx].fd);
    mon->conn[idx] = mon->conn[mon->n - 1];
    mon->n--;
}

/* Best-effort non-blocking write; reap the monitor on a hard error. */
static void mon_write(mc_monitor *mon, int idx, const char *s, size_t len)
{
    ssize_t w = write(mon->conn[idx].fd, s, len);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        mon_drop(mon, idx);
}

static void stamp(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(out, n, "%H:%M:%S", &tmv);
}

bool monitor_add(mc_monitor *mon, int fd, const char *cmdline)
{
    /* cmdline is "monitor" or "monitor <target>" - skip the command word */
    const char *p = cmdline;
    while (*p && *p != ' ' && *p != '\t') p++;
    while (*p == ' ' || *p == '\t')       p++;

    char hdr[160];
    if (mon->n >= MC_MAX_MONITORS) {
        int len = snprintf(hdr, sizeof(hdr),
                           "monitor: too many active monitors (max %d)\n", MC_MAX_MONITORS);
        (void)!write(fd, hdr, (size_t)len);
        return false;
    }

    mc_mon_conn_t c;
    memset(&c, 0, sizeof(c));
    c.fd = fd;
    if (*p == '\0' || !strcasecmp(p, "all"))    c.kind = MON_ALL;
    else if (p[0] == '#')                     { c.kind = MON_ROOM;    snprintf(c.target, sizeof(c.target), "%s", p); }
    else if (!strcasecmp(p, "public"))          c.kind = MON_PUBLIC;
    else                                      { c.kind = MON_CHANNEL; snprintf(c.target, sizeof(c.target), "%s", p); }

    fcntl(fd, F_SETFL, O_NONBLOCK);
    mon->conn[mon->n++] = c;

    const char *what = c.kind == MON_ALL     ? "all activity (public msgs, region hits, drops)"
                     : c.kind == MON_PUBLIC  ? "all public channels"
                     : c.kind == MON_ROOM    ? c.target
                     :                         c.target;
    int len = snprintf(hdr, sizeof(hdr), "# monitoring %s%s - Ctrl-C to stop\n",
                       what, c.kind == MON_ROOM ? " (region: opaque, metadata only)" : "");
    (void)!write(fd, hdr, (size_t)len);
    return true;
}

bool monitor_wants_public(const mc_mon_conn_t *c, const char *chan)
{
    switch (c->kind) {
    case MON_ALL:     return true;
    case MON_PUBLIC:  return true;
    case MON_CHANNEL: return chan && *chan && strcasecmp(c->target, chan) == 0;
    /* MON_ROOM "#name" also matches the derived channel of the same name, so
     * `monitor #sysop` shows the decrypted #sysop channel text. Rooms/hashtag
     * channels are CASE-SENSITIVE (hashed verbatim -> distinct keys), so match
     * the channel name case-sensitively too - matching monitor_wants_room. */
    case MON_ROOM:    return chan && *chan && strcmp(c->target, chan) == 0;
    default:          return false;
    }
}

bool monitor_wants_room(const mc_mon_conn_t *c, const char *room)
{
    if (c->kind == MON_ALL)  return true;
    if (c->kind == MON_ROOM) return room && strcmp(c->target, room) == 0;  /* case-sensitive */
    return false;
}

void monitor_public(mc_monitor *mon, const char *chan, const char *text,
                    int rssi, int8_t snr_q)
{
    if (mon->n == 0) return;
    char t[16]; stamp(t, sizeof(t));
    char line[600];
    int len = snprintf(line, sizeof(line), "%s [public %s] %s  (rssi %d snr %.1f)\n",
                       t, (chan && *chan) ? chan : "-",
                       text ? text : "", rssi, snr_q / 4.0);
    if (len < 0) return;
    if ((size_t)len >= sizeof(line)) len = (int)sizeof(line) - 1;
    for (int i = mon->n - 1; i >= 0; i--)              /* backward: mon_write may compact */
        if (monitor_wants_public(&mon->conn[i], chan))
            mon_write(mon, i, line, (size_t)len);
}

void monitor_region(mc_monitor *mon, const char *room, uint8_t ptype,
                    unsigned len_b, int rssi, int8_t snr_q)
{
    if (mon->n == 0) return;
    char t[16]; stamp(t, sizeof(t));
    char line[256];
    int len = snprintf(line, sizeof(line),
                       "%s [room %s] relayed  type=0x%02X  len=%uB  (rssi %d snr %.1f)\n",
                       t, room ? room : "?", ptype, len_b, rssi, snr_q / 4.0);
    if (len < 0) return;
    if ((size_t)len >= sizeof(line)) len = (int)sizeof(line) - 1;
    for (int i = mon->n - 1; i >= 0; i--)
        if (monitor_wants_room(&mon->conn[i], room))
            mon_write(mon, i, line, (size_t)len);
}

void monitor_drop(mc_monitor *mon, uint8_t ptype, const char *reason, int chan_hash)
{
    if (mon->n == 0) return;
    char t[16]; stamp(t, sizeof(t));
    char line[200];
    int len = (chan_hash >= 0)
        ? snprintf(line, sizeof(line), "%s [drop] type=0x%02X chan=0x%02X  %s\n",
                   t, ptype, (unsigned)chan_hash, reason ? reason : "")
        : snprintf(line, sizeof(line), "%s [drop] type=0x%02X  %s\n",
                   t, ptype, reason ? reason : "");
    if (len < 0) return;
    if ((size_t)len >= sizeof(line)) len = (int)sizeof(line) - 1;
    for (int i = mon->n - 1; i >= 0; i--)
        if (mon->conn[i].kind == MON_ALL)              /* drops only in 'all' view */
            mon_write(mon, i, line, (size_t)len);
}

int monitor_pollfds(mc_monitor *mon, struct pollfd *pfd, int max)
{
    int k = 0;
    for (int i = 0; i < mon->n && k < max; i++, k++) {
        pfd[k].fd      = mon->conn[i].fd;
        pfd[k].events  = POLLIN;   /* the client never sends after the command, so
                                      readable == EOF == it closed (see monitor_reap) */
        pfd[k].revents = 0;
    }
    return k;
}

void monitor_reap(mc_monitor *mon, const struct pollfd *pfd, int count)
{
    /* pfd[0..count-1] were filled from conn[0..count-1] in order this iteration;
     * reap closed clients from the back so compaction never shifts a lower index. */
    if (count > mon->n) count = mon->n;
    for (int i = count - 1; i >= 0; i--) {
        short re = pfd[i].revents;
        if (re & (POLLHUP | POLLERR | POLLNVAL)) { mon_drop(mon, i); continue; }
        if (re & POLLIN) {
            /* the streaming client sends nothing, so readability is EOF (it closed)
             * or, defensively, stray bytes we discard. */
            char junk[64];
            ssize_t r = read(mon->conn[i].fd, junk, sizeof(junk));
            if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                mon_drop(mon, i);
        }
    }
}
