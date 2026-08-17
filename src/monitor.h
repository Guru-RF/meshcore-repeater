/*
 * monitor.h - live message monitors for the local control interface.
 *
 * A "monitor" is a meshcore-cli client that streams filtered message events
 * from the running repeater for debugging, e.g.:
 *
 *   meshcore-cli monitor              # everything (public msgs, region hits, drops)
 *   meshcore-cli monitor public       # decrypted messages on any public channel
 *   meshcore-cli monitor <name>       # decrypted messages on the channel named <name>
 *   meshcore-cli monitor #sysop       # a transport region (opaque: metadata only)
 *
 * The connection is held open and events are pushed as they happen. A public
 * channel's traffic can be decrypted (we hold the key), so its text is shown; a
 * #room region is forwarded WITHOUT the key, so only metadata is available.
 */
#ifndef MC_MONITOR_H
#define MC_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <poll.h>

#define MC_MAX_MONITORS      4
#define MC_MON_TARGET_LEN    40

typedef enum { MON_ALL = 0, MON_PUBLIC, MON_CHANNEL, MON_ROOM } mon_kind_t;

typedef struct {
    int        fd;                        /* client socket (kept open, O_NONBLOCK) */
    mon_kind_t kind;
    char       target[MC_MON_TARGET_LEN]; /* channel name, or "#room" */
} mc_mon_conn_t;

typedef struct mc_monitor {
    mc_mon_conn_t conn[MC_MAX_MONITORS];
    int           n;
} mc_monitor;

void monitor_init(mc_monitor *mon);
int  monitor_count(const mc_monitor *mon);

/* Register a "monitor [target]" client on fd. Writes a header line (or an error)
 * to fd. Returns true if registered (caller KEEPS fd open); false if not
 * (caller closes fd). */
bool monitor_add(mc_monitor *mon, int fd, const char *cmdline);

/* Event emitters - no-ops when no monitor matches. `text` for a public message
 * is the raw decrypted body (typically "sender: message"). */
void monitor_public(mc_monitor *mon, const char *chan, const char *text,
                    int rssi, int8_t snr_q);
void monitor_region(mc_monitor *mon, const char *room, uint8_t ptype,
                    unsigned len, int rssi, int8_t snr_q);
void monitor_drop(mc_monitor *mon, uint8_t ptype, const char *reason);

/* Routing predicates (exposed for testing). */
bool monitor_wants_public(const mc_mon_conn_t *c, const char *chan);
bool monitor_wants_room(const mc_mon_conn_t *c, const char *room);

/* poll(2) integration for the single main loop. monitor_pollfds fills up to
 * `max` pollfds (events=0: we only care about hang-up); monitor_reap drops any
 * that the client closed. */
int  monitor_pollfds(mc_monitor *mon, struct pollfd *pfd, int max);
void monitor_reap(mc_monitor *mon, const struct pollfd *pfd, int count);

#endif /* MC_MONITOR_H */
