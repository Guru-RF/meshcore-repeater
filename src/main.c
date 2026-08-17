/*
 * main.c - MeshCore repeater daemon for Raspberry Pi + NiceRF LoRa1268F30-433.
 *
 * Event loop: poll the radio for received packets, service the delayed TX
 * queue, emit periodic adverts, and read the local operator CLI from stdin.
 */
#include "config.h"
#include "identity.h"
#include "mesh.h"
#include "sx126x.h"
#include "hal.h"
#include "cli.h"
#include "log.h"
#include "util.h"
#include "aprsis.h"
#include "monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* Open the local control socket on 127.0.0.1:port. Returns the listening fd, or
 * -1 (disabled/failed). One command per connection; output goes back on the
 * socket. Bound to loopback only - never exposed to the network. */
static int control_listen(uint16_t port)
{
    if (port == 0)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 127.0.0.1 only */
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 4) != 0) {
        log_warn("control: could not bind 127.0.0.1:%u (%s)", port, strerror(errno));
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    log_info("control interface on 127.0.0.1:%u", port);
    return fd;
}

/* Accept one client, read a single command line, run it with stdout wired to
 * the client, then close. Logs stay on stderr, so they are unaffected. */
static void control_accept(cli_ctx_t *ctx, int lfd)
{
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0)
        return;
    /* a slow/silent client must not stall packet forwarding */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char line[512];
    size_t n = 0;
    while (n < sizeof(line) - 1) {
        char c;
        ssize_t r = read(cfd, &c, 1);
        if (r <= 0 || c == '\n')
            break;
        if (c != '\r')
            line[n++] = c;
    }
    line[n] = '\0';

    if (n > 0) {
        /* "monitor [target]" streams events: keep the connection open and hand
         * the fd to the monitor table instead of the one-shot response path. */
        if (!strncasecmp(line, "monitor", 7) &&
            (line[7] == '\0' || line[7] == ' ' || line[7] == '\t')) {
            if (ctx->mesh->mon && monitor_add(ctx->mesh->mon, cfd, line))
                return;                       /* fd now owned by the monitor table */
            close(cfd);                       /* not registered (full/disabled) -> done */
            return;
        }
        fflush(stdout);
        int saved = dup(STDOUT_FILENO);
        dup2(cfd, STDOUT_FILENO);
        cli_handle_line(ctx, line);
        fflush(stdout);
        dup2(saved, STDOUT_FILENO);
        close(saved);
    }
    close(cfd);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "MeshCore repeater (plain C, SX1268)\n"
        "usage: %s [options]\n"
        "  -c <file>   config file (default: meshcore-repeater.conf)\n"
        "  -v          verbose: log public messages, adverts and dropped packets\n"
        "  -q          quiet (errors only)\n"
        "  --genkey    generate a new identity key file and exit\n"
        "  -h          this help\n", prog);
}

/* Read whatever is on stdin and dispatch each complete line to the CLI.
 * Returns false when stdin hits EOF (so we stop polling it). */
static bool pump_stdin(cli_ctx_t *ctx, char *acc, size_t accsz, size_t *acclen)
{
    char rb[256];
    ssize_t r = read(STDIN_FILENO, rb, sizeof(rb));
    if (r == 0) {
        log_info("stdin closed; local CLI disabled (running headless)");
        return false; /* EOF (e.g. stdin is /dev/null under systemd) */
    }
    if (r < 0)
        return true;
    for (ssize_t i = 0; i < r; i++) {
        char c = rb[i];
        if (c == '\n') {
            acc[*acclen] = '\0';
            cli_handle_line(ctx, acc);
            *acclen = 0;
        } else if (*acclen + 1 < accsz) {
            acc[(*acclen)++] = c;
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    const char *config_path = "meshcore-repeater.conf";
    bool genkey = false;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) config_path = argv[++i];
        else if (!strcmp(argv[i], "-v")) { log_set_level(LOG_LEVEL_DEBUG); verbose = true; }
        else if (!strcmp(argv[i], "-q")) log_set_level(LOG_LEVEL_ERR);
        else if (!strcmp(argv[i], "--genkey")) genkey = true;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown option: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    mc_config_t cfg;
    config_defaults(&cfg);
    if (config_load(&cfg, config_path) != 0)
        log_info("no config file '%s'; using built-in defaults", config_path);
    cfg.verbose = verbose;   /* -v overrides after the file load */

    /* identity */
    mc_identity_t id;
    if (genkey) {
        mc_identity_generate(&id);
        if (mc_identity_save(&id, cfg.key_file) != 0) {
            log_err("could not write key file '%s'", cfg.key_file);
            return 1;
        }
        char hex[MC_PUB_KEY_SIZE * 2 + 1];
        bin2hex(id.pub, MC_PUB_KEY_SIZE, hex, sizeof(hex));
        printf("generated identity -> %s\npublic key: %s\n", cfg.key_file, hex);
        return 0;
    }

    if (mc_identity_load(&id, cfg.key_file) != 0) {
        log_info("no identity at '%s'; generating a new one", cfg.key_file);
        mc_identity_generate(&id);
        if (mc_identity_save(&id, cfg.key_file) != 0)
            log_warn("could not persist key file '%s' (continuing with in-memory key)", cfg.key_file);
    }

    /* hardware + radio */
    hal_config_t hal;
    config_to_hal(&cfg, &hal);
    if (hal_init(&hal) != 0) {
        log_err("HAL init failed - check SPI/GPIO config and permissions");
        return 1;
    }

    sx126x_cfg_t radio;
    config_to_sx126x(&cfg, &radio);
    if (sx126x_init(&radio) != 0) {
        log_err("radio init failed - check wiring, power (+30dBm needs a strong 4-6V supply), and TCXO");
        hal_close();
        return 1;
    }
    sx126x_start_rx();

    /* mesh */
    mc_mesh_t mesh;
    mesh_init(&mesh, &id, &cfg);

    /* APRS-IS iGate (optional) */
    mc_aprsis aprs;
    if (cfg.aprs_enable && aprsis_init(&aprs, &cfg, id.pub) == 0)
        mesh.aprs = &aprs;

    /* live CLI message monitors (meshcore-cli monitor ...) */
    mc_monitor monitor;
    monitor_init(&monitor);
    mesh.mon = &monitor;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    bool running = true;
    cli_ctx_t ctx = {
        .cfg = &cfg, .mesh = &mesh, .id = &id,
        .config_path = config_path, .radio_ready = true, .running = &running,
    };
    cli_banner(&ctx);

    hal_led_on(true);  /* status LED: solid while running */

    /* fire an initial advert shortly after start */
    uint64_t last_advert = hal_millis();
    if (cfg.advert_interval)
        mesh_send_advert(&mesh);

    int ctrl_fd = control_listen(cfg.control_port);

    char acc[256];
    size_t acclen = 0;
    bool stdin_open = true;
    uint64_t data_led_off = 0;    /* when to extinguish the activity LED */
    uint64_t prev_tx = 0;

    while (running && !g_stop) {
        uint64_t now = hal_millis();
        bool activity = false;

        /* 1. receive */
        uint8_t buf[MC_MAX_TRANS_UNIT];
        size_t rlen = 0;
        int16_t rssi = 0;
        int8_t snr = 0;
        int r = sx126x_poll_rx(buf, sizeof(buf), &rlen, &rssi, &snr);
        if (r == 1) {
            log_debug("rx %zu bytes  rssi=%d snr=%.2f", rlen, rssi, snr / 4.0);
            mesh_on_recv(&mesh, buf, rlen, rssi, snr);
            activity = true;
        }

        /* 2. transmit due packets */
        mesh_service_tx(&mesh, now);
        if (mesh.stats.tx_total != prev_tx) {
            prev_tx = mesh.stats.tx_total;
            activity = true;
        }

        /* 3. periodic advert */
        if (cfg.advert_interval &&
            now - last_advert >= (uint64_t)cfg.advert_interval * 1000ull) {
            mesh_send_advert(&mesh);
            last_advert = now;
        }

        /* activity LED pulse */
        if (activity) {
            hal_led_data(true);
            data_led_off = now + 60;
        } else if (data_led_off && now >= data_led_off) {
            hal_led_data(false);
            data_led_off = 0;
        }

        /* 4. local CLI + control socket + APRS-IS + monitors (all non-blocking) */
        struct pollfd pfd[3 + MC_MAX_MONITORS];
        int nfds = 0;
        int stdin_slot = -1, ctrl_slot = -1, aprs_slot = -1;
        short aprs_ev = 0;
        int aprs_fd = mesh.aprs ? aprsis_pollfd(mesh.aprs, &aprs_ev) : -1;
        if (stdin_open) { stdin_slot = nfds; pfd[nfds].fd = STDIN_FILENO; pfd[nfds].events = POLLIN; nfds++; }
        if (ctrl_fd >= 0) { ctrl_slot = nfds; pfd[nfds].fd = ctrl_fd; pfd[nfds].events = POLLIN; nfds++; }
        if (aprs_fd >= 0) { aprs_slot = nfds; pfd[nfds].fd = aprs_fd; pfd[nfds].events = aprs_ev; nfds++; }
        int mon_slot = nfds;
        int mon_count = monitor_pollfds(&monitor, &pfd[nfds], MC_MAX_MONITORS);
        nfds += mon_count;

        if (nfds > 0) {
            int pr = poll(pfd, nfds, (r == 1) ? 0 : 5);
            if (pr > 0) {
                if (stdin_slot >= 0 && (pfd[stdin_slot].revents & POLLIN))
                    stdin_open = pump_stdin(&ctx, acc, sizeof(acc), &acclen);
                if (ctrl_slot >= 0 && (pfd[ctrl_slot].revents & POLLIN))
                    control_accept(&ctx, ctrl_fd);
                monitor_reap(&monitor, &pfd[mon_slot], mon_count);   /* drop closed monitors */
            }
        } else {
            hal_delay_ms(5);
        }
        /* advance the APRS-IS client every iteration (connect/beacon timers) */
        if (mesh.aprs)
            aprsis_service(mesh.aprs, now, aprs_slot >= 0 ? pfd[aprs_slot].revents : 0);
    }

    if (ctrl_fd >= 0)
        close(ctrl_fd);
    if (mesh.aprs)
        aprsis_close(mesh.aprs);

    log_info("shutting down");
    hal_led_data(false);
    hal_led_on(false);
    sx126x_standby();
    hal_close();
    return 0;
}
