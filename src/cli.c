/* cli.c - local operator console. */
#include "cli.h"
#include "sx126x.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static bool is_radio_key(const char *key)
{
    static const char *keys[] = {
        "frequency", "bandwidth", "spreading_factor", "coding_rate",
        "tx_power", "preamble", "crc", "iq_inverted", NULL
    };
    for (int i = 0; keys[i]; i++)
        if (!strcasecmp(key, keys[i]))
            return true;
    return false;
}

static int apply_radio(cli_ctx_t *ctx)
{
    if (!ctx->radio_ready)
        return 0;
    sx126x_cfg_t radio;
    config_to_sx126x(ctx->cfg, &radio);
    int rc = sx126x_set_modem(&radio);          /* sf/bw/cr/preamble/crc/power */
    if (rc != 0) {
        log_err("radio modem reconfig failed (rc=%d)", rc);
        printf("WARNING: radio modem reconfig failed (rc=%d) - radio may be in a bad state\n", rc);
        return rc;
    }
    rc = sx126x_set_frequency(ctx->cfg->frequency); /* re-tune + return to RX */
    if (rc != 0) {
        log_err("radio retune failed (rc=%d)", rc);
        printf("WARNING: radio retune failed (rc=%d) - radio may be in a bad state\n", rc);
        return rc;
    }
    log_info("radio reconfigured: %.3f MHz SF%u BW%g CR4/%u %ddBm",
             ctx->cfg->frequency, ctx->cfg->spreading_factor,
             ctx->cfg->bandwidth, ctx->cfg->coding_rate, ctx->cfg->tx_power);
    return 0;
}

void cli_banner(const cli_ctx_t *ctx)
{
    char hash[16];
    bin2hex(ctx->id->pub, 4, hash, sizeof(hash));
    printf("\nMeshCore repeater  '%s'  node-id %s\n", ctx->cfg->name, hash);
    printf("  %.3f MHz  SF%u  BW%g kHz  CR4/%u  chip %d dBm  sync 0x%04X\n",
           ctx->cfg->frequency, ctx->cfg->spreading_factor, ctx->cfg->bandwidth,
           ctx->cfg->coding_rate, ctx->cfg->tx_power, ctx->cfg->sync_word);
    printf("  policy: forward public-only, %d public channel(s) - adverts always, "
           "private msgs dropped\n", ctx->cfg->n_public_channels);
    printf("  type 'help' for commands.\n\n");
    fflush(stdout);
}

static void cmd_help(void)
{
    printf(
        "commands:\n"
        "  help                 this help\n"
        "  status               uptime, identity, stats, neighbours\n"
        "  stats                packet counters\n"
        "  get <key>            read a config value\n"
        "  set <key> <value>    change a config value (radio keys apply live)\n"
        "  freq <MHz>           shortcut for 'set frequency' (e.g. freq 434.0)\n"
        "  neighbors            list heard nodes\n"
        "  channels             list configured public channels (forwarded)\n"
        "  advert               send a self-advert now\n"
        "  save                 write config back to file\n"
        "  reload               reload config file (hardware keys need restart)\n"
        "  quit                 stop the repeater\n");
    fflush(stdout);
}

static void cmd_status(cli_ctx_t *ctx)
{
    mesh_stats_t *s = &ctx->mesh->stats;
    uint64_t up_s = (hal_millis() - ctx->mesh->start_ms) / 1000;
    char pubhex[16];
    bin2hex(ctx->id->pub, 6, pubhex, sizeof(pubhex));

    printf("node      : '%s'  id %s\n", ctx->cfg->name, pubhex);
    printf("uptime    : %lluh %llum %llus\n",
           (unsigned long long)(up_s / 3600),
           (unsigned long long)((up_s % 3600) / 60),
           (unsigned long long)(up_s % 60));
    printf("radio     : %.3f MHz SF%u BW%g CR4/%u chip %ddBm sync 0x%04X cad %s fwd %s\n",
           ctx->cfg->frequency, ctx->cfg->spreading_factor, ctx->cfg->bandwidth,
           ctx->cfg->coding_rate, ctx->cfg->tx_power, ctx->cfg->sync_word,
           ctx->cfg->use_cad ? "on" : "off", ctx->cfg->forward ? "on" : "off");
    printf("rx        : total %llu  dup %llu  bad %llu  adverts %llu (bad %llu)\n",
           (unsigned long long)s->rx_total, (unsigned long long)s->rx_dup,
           (unsigned long long)s->rx_bad_parse, (unsigned long long)s->rx_advert,
           (unsigned long long)s->rx_advert_bad);
    printf("forward   : flood %llu  direct %llu  dropped %llu  trace %llu\n",
           (unsigned long long)s->fwd_flood, (unsigned long long)s->fwd_direct,
           (unsigned long long)s->fwd_dropped, (unsigned long long)s->trace_seen);
    printf("policy    : grp-public %llu  denied %llu (dm %llu grp %llu other %llu) mac-fail %llu\n",
           (unsigned long long)s->fwd_grp_public, (unsigned long long)s->fwd_denied,
           (unsigned long long)s->fwd_denied_dm, (unsigned long long)s->fwd_denied_grp,
           (unsigned long long)s->fwd_denied_other, (unsigned long long)s->grp_mac_fail);
    printf("tx        : sent %llu  cad-busy %llu  q-full %llu  adverts %llu\n",
           (unsigned long long)s->tx_total, (unsigned long long)s->tx_cad_busy,
           (unsigned long long)s->tx_queue_full, (unsigned long long)s->adverts_sent);
    printf("neighbours: %d\n", mesh_neighbor_count(ctx->mesh));
    fflush(stdout);
}

static void cmd_neighbors(cli_ctx_t *ctx)
{
    static const char *types[] = { "none", "chat", "repeater", "room", "sensor" };
    uint32_t now = (uint32_t)time(NULL);
    int shown = 0;
    printf("%-12s %-18s %-8s %6s %5s %8s\n", "node-id", "name", "type", "rssi", "snr", "age(s)");
    for (int i = 0; i < MESH_MAX_NEIGHBORS; i++) {
        mesh_neighbor_t *n = &ctx->mesh->neighbors[i];
        if (!n->used)
            continue;
        char idhex[16];
        bin2hex(n->pub, 6, idhex, sizeof(idhex));
        const char *t = (n->type < 5) ? types[n->type] : "?";
        printf("%-12s %-18s %-8s %6d %5.2f %8u\n",
               idhex, n->name[0] ? n->name : "-", t,
               n->rssi, n->snr_q / 4.0, now - n->last_seen);
        shown++;
    }
    if (!shown)
        printf("  (none heard yet)\n");
    fflush(stdout);
}

static void cmd_channels(cli_ctx_t *ctx)
{
    const mc_config_t *c = ctx->cfg;
    printf("public channels (%d) - group messages are forwarded ONLY on these:\n",
           c->n_public_channels);
    if (c->n_public_channels == 0)
        printf("  (none - forwarding adverts only; all group + private traffic dropped)\n");
    for (int i = 0; i < c->n_public_channels; i++) {
        const mc_pub_channel_t *ch = &c->public_channels[i];
        printf("  [%d] hash 0x%02X  %u-bit  %s\n", i, ch->hash,
               (unsigned)(ch->secret_len * 8), ch->name[0] ? ch->name : "-");
    }
    fflush(stdout);
}

void cli_handle_line(cli_ctx_t *ctx, const char *line)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", line);

    char *cmd = strtok(buf, " \t\r\n");
    if (!cmd)
        return;

    if (!strcasecmp(cmd, "help") || !strcmp(cmd, "?")) {
        cmd_help();
    } else if (!strcasecmp(cmd, "status")) {
        cmd_status(ctx);
    } else if (!strcasecmp(cmd, "stats")) {
        cmd_status(ctx);
    } else if (!strcasecmp(cmd, "neighbors") || !strcasecmp(cmd, "neighbours")) {
        cmd_neighbors(ctx);
    } else if (!strcasecmp(cmd, "channels")) {
        cmd_channels(ctx);
    } else if (!strcasecmp(cmd, "advert")) {
        mesh_send_advert(ctx->mesh);
    } else if (!strcasecmp(cmd, "get")) {
        char *key = strtok(NULL, " \t\r\n");
        char out[128];
        if (key && config_get(ctx->cfg, key, out, sizeof(out)) == 0)
            printf("%s = %s\n", key, out);
        else
            printf("unknown key\n");
        fflush(stdout);
    } else if (!strcasecmp(cmd, "set")) {
        char *key = strtok(NULL, " \t\r\n");
        char *val = strtok(NULL, "\r\n");
        if (val) { while (*val == ' ' || *val == '\t') val++; }
        if (!key || !val) { printf("usage: set <key> <value>\n"); fflush(stdout); return; }
        int rc = config_set(ctx->cfg, key, val);
        if (rc == 0) {
            printf("ok: %s = %s\n", key, val);
            if (is_radio_key(key))
                apply_radio(ctx);
        } else if (rc == -1) {
            printf("unknown key '%s'\n", key);
        } else {
            printf("invalid value for '%s'\n", key);
        }
        fflush(stdout);
    } else if (!strcasecmp(cmd, "freq")) {
        char *val = strtok(NULL, " \t\r\n");
        if (!val) { printf("usage: freq <MHz>\n"); fflush(stdout); return; }
        if (config_set(ctx->cfg, "frequency", val) == 0) {
            printf("ok: frequency = %s MHz\n", val);
            apply_radio(ctx);
        } else {
            printf("invalid frequency\n");
        }
        fflush(stdout);
    } else if (!strcasecmp(cmd, "save")) {
        if (config_save(ctx->cfg, ctx->config_path) == 0)
            printf("saved to %s\n", ctx->config_path);
        else
            printf("save failed\n");
        fflush(stdout);
    } else if (!strcasecmp(cmd, "reload")) {
        config_load(ctx->cfg, ctx->config_path);
        apply_radio(ctx);
        printf("reloaded %s (hardware/sync/tcxo changes require restart)\n", ctx->config_path);
        fflush(stdout);
    } else if (!strcasecmp(cmd, "quit") || !strcasecmp(cmd, "exit")) {
        if (ctx->running)
            *ctx->running = false;
    } else {
        printf("unknown command '%s' (try 'help')\n", cmd);
        fflush(stdout);
    }
}
