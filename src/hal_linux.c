/*
 * hal_linux.c - Raspberry Pi / Linux HAL: spidev + libgpiod + timing + RNG.
 *
 * Supports BOTH libgpiod major versions, selected by the Makefile via
 * pkg-config (-DUSE_GPIOD_V2 for libgpiod 2.x; otherwise the 1.x API):
 *   - RPi OS Bookworm  -> libgpiod 1.6   (v1 API)
 *   - RPi OS Trixie    -> libgpiod 2.x   (v2 API)
 *
 * The whole file is a no-op off Linux so the self-test can link the mock HAL.
 */
#if defined(__linux__)

#include "hal.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <linux/spi/spidev.h>
#include <gpiod.h>

#define CONSUMER "meshcore-repeater"

/* ------------------------------------------------------------------ */
/* GPIO line abstraction over libgpiod v1 / v2                         */
/* ------------------------------------------------------------------ */
#ifdef USE_GPIOD_V2

typedef struct { struct gpiod_line_request *req; unsigned offset; } gline_t;

static struct gpiod_chip *chip_open(const char *name)
{
    char path[96];
    if (name[0] == '/')
        snprintf(path, sizeof(path), "%s", name);
    else
        snprintf(path, sizeof(path), "/dev/%s", name);
    return gpiod_chip_open(path);
}

static int gline_request(gline_t *l, struct gpiod_chip *chip, unsigned offset,
                         int output, int initial)
{
    l->req = NULL;
    l->offset = offset;

    struct gpiod_line_settings *s = gpiod_line_settings_new();
    if (!s)
        return -1;
    gpiod_line_settings_set_direction(s, output ? GPIOD_LINE_DIRECTION_OUTPUT
                                                 : GPIOD_LINE_DIRECTION_INPUT);
    if (output)
        gpiod_line_settings_set_output_value(s, initial ? GPIOD_LINE_VALUE_ACTIVE
                                                        : GPIOD_LINE_VALUE_INACTIVE);

    int rc = -1;
    struct gpiod_line_config *lc = gpiod_line_config_new();
    if (lc) {
        unsigned int offs[1] = { offset };
        if (gpiod_line_config_add_line_settings(lc, offs, 1, s) == 0) {
            struct gpiod_request_config *rq = gpiod_request_config_new();
            if (rq)
                gpiod_request_config_set_consumer(rq, CONSUMER);
            l->req = gpiod_chip_request_lines(chip, rq, lc);
            if (rq)
                gpiod_request_config_free(rq);
            rc = l->req ? 0 : -1;
        }
        gpiod_line_config_free(lc);
    }
    gpiod_line_settings_free(s);
    return rc;
}

static int gline_get(gline_t *l)
{
    if (!l->req)
        return -1;
    enum gpiod_line_value v = gpiod_line_request_get_value(l->req, l->offset);
    if (v == GPIOD_LINE_VALUE_ACTIVE)   return 1;
    if (v == GPIOD_LINE_VALUE_INACTIVE) return 0;
    return -1;
}

static void gline_set(gline_t *l, int val)
{
    if (l->req)
        gpiod_line_request_set_value(l->req, l->offset,
                                     val ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE);
}

static void gline_release(gline_t *l)
{
    if (l->req) { gpiod_line_request_release(l->req); l->req = NULL; }
}

static int gline_ok(const gline_t *l) { return l->req != NULL; }

#else  /* libgpiod v1 */

typedef struct { struct gpiod_line *line; } gline_t;

static struct gpiod_chip *chip_open(const char *name)
{
    return gpiod_chip_open_lookup(name);
}

static int gline_request(gline_t *l, struct gpiod_chip *chip, unsigned offset,
                         int output, int initial)
{
    l->line = gpiod_chip_get_line(chip, offset);
    if (!l->line)
        return -1;
    int rc = output ? gpiod_line_request_output(l->line, CONSUMER, initial)
                    : gpiod_line_request_input(l->line, CONSUMER);
    if (rc < 0) { l->line = NULL; return -1; }
    return 0;
}

static int  gline_get(gline_t *l)            { return l->line ? gpiod_line_get_value(l->line) : -1; }
static void gline_set(gline_t *l, int val)   { if (l->line) gpiod_line_set_value(l->line, val); }
static void gline_release(gline_t *l)        { if (l->line) { gpiod_line_release(l->line); l->line = NULL; } }
static int  gline_ok(const gline_t *l)       { return l->line != NULL; }

#endif /* USE_GPIOD_V2 */

/* ------------------------------------------------------------------ */
/* module state                                                        */
/* ------------------------------------------------------------------ */
static int               g_spi_fd = -1;
static uint32_t          g_spi_speed = 2000000;
static struct gpiod_chip *g_chip = NULL;
static gline_t           g_reset, g_busy, g_dio1, g_nss, g_rxen, g_txen;
static gline_t           g_led_on, g_led_data;
static uint64_t          g_rng_state = 0;

/* ------------------- timing ------------------- */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

uint64_t hal_millis(void) { return now_ns() / 1000000ull; }

void hal_delay_ms(uint32_t ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

void hal_delay_us(uint32_t us)
{
    struct timespec ts = { us / 1000000, (long)(us % 1000000) * 1000L };
    nanosleep(&ts, NULL);
}

/* ------------------- RNG (xorshift64, OS-seeded) ------------------- */
void hal_rng_init(void)
{
    uint64_t seed = 0;
    if (getrandom(&seed, sizeof(seed), 0) != (ssize_t)sizeof(seed) || seed == 0)
        seed = now_ns() ^ 0x9E3779B97F4A7C15ull;
    g_rng_state = seed ? seed : 1;
}

static uint64_t xorshift64(void)
{
    uint64_t x = g_rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    g_rng_state = x;
    return x;
}

uint32_t hal_rng_int(uint32_t lo, uint32_t hi)
{
    if (hi <= lo)
        return lo;
    uint32_t span = hi - lo + 1; /* inclusive */
    return lo + (uint32_t)(xorshift64() % span);
}

/* ------------------- SPI ------------------- */
/* NSS is a plain GPIO on this board (not the hardware CE), so we frame each
 * command by driving it low before the transfer and high after. */
int hal_spi_xfer(const uint8_t *tx, uint8_t *rx, size_t len)
{
    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof(tr));
    tr.tx_buf = (unsigned long)tx;
    tr.rx_buf = (unsigned long)rx;
    tr.len = (uint32_t)len;
    tr.speed_hz = g_spi_speed;
    tr.bits_per_word = 8;
    tr.cs_change = 0;

    if (gline_ok(&g_nss)) gline_set(&g_nss, 0);   /* assert NSS */
    int rc = ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &tr);
    if (gline_ok(&g_nss)) gline_set(&g_nss, 1);   /* deassert NSS */

    if (rc < 1) {
        log_err("hal: SPI transfer failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------- GPIO ------------------- */
void hal_reset_pin(int level) { gline_set(&g_reset, level ? 1 : 0); }
int  hal_busy_read(void)      { return gline_get(&g_busy); }
int  hal_dio1_read(void)      { return gline_get(&g_dio1); }

void hal_rf_switch(rf_switch_t mode)
{
    /* No-op when the SX126x drives DIO2 as the RF switch (g_rxen/g_txen unset). */
    int rx = 0, tx = 0;
    if (mode == RF_SW_RX) { rx = 1; tx = 0; }
    else if (mode == RF_SW_TX) { rx = 0; tx = 1; }
    if (gline_ok(&g_rxen)) gline_set(&g_rxen, rx);
    if (gline_ok(&g_txen)) gline_set(&g_txen, tx);
}

void hal_led_on(bool on)   { if (gline_ok(&g_led_on))   gline_set(&g_led_on, on ? 1 : 0); }
void hal_led_data(bool on) { if (gline_ok(&g_led_data)) gline_set(&g_led_data, on ? 1 : 0); }

int hal_wait_busy_low(uint32_t timeout_us)
{
    uint64_t deadline = now_ns() + (uint64_t)timeout_us * 1000ull;
    for (;;) {
        int v = hal_busy_read();
        if (v == 0)
            return 0;
        if (v < 0)
            return -1;
        if (now_ns() > deadline)
            return -1;
        struct timespec ts = { 0, 10000 }; /* 10us */
        nanosleep(&ts, NULL);
    }
}

/* ------------------- init / close ------------------- */
int hal_init(const hal_config_t *cfg)
{
    g_spi_speed = cfg->spi_speed_hz;

    /* SPI */
    g_spi_fd = open(cfg->spi_dev, O_RDWR);
    if (g_spi_fd < 0) {
        log_err("hal: cannot open %s: %s (is SPI enabled?)", cfg->spi_dev, strerror(errno));
        return -1;
    }
    /* SPI mode 0, and SPI_NO_CS because we drive NSS manually on a GPIO. */
    uint8_t mode = SPI_MODE_0 | SPI_NO_CS;
    uint8_t bits = 8;
    if (ioctl(g_spi_fd, SPI_IOC_WR_MODE, &mode) < 0 ||
        ioctl(g_spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
        ioctl(g_spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &g_spi_speed) < 0) {
        log_err("hal: SPI configuration failed: %s", strerror(errno));
        close(g_spi_fd);
        g_spi_fd = -1;
        return -2;
    }

    /* GPIO */
    g_chip = chip_open(cfg->gpio_chip);
    if (!g_chip) {
        log_err("hal: cannot open gpio chip '%s': %s", cfg->gpio_chip, strerror(errno));
        close(g_spi_fd);
        g_spi_fd = -1;
        return -3;
    }

    if (gline_request(&g_reset, g_chip, cfg->line_reset, 1, 1) < 0 ||  /* NRST idle high */
        gline_request(&g_nss,   g_chip, cfg->line_nss,   1, 1) < 0 ||  /* NSS idle high */
        gline_request(&g_busy,  g_chip, cfg->line_busy,  0, 0) < 0 ||
        gline_request(&g_dio1,  g_chip, cfg->line_dio1,  0, 0) < 0) {
        log_err("hal: failed to claim core GPIO lines (already in use?)");
        hal_close();
        return -4;
    }

    if (cfg->rf_switch_external) {
        if (gline_request(&g_rxen, g_chip, cfg->line_rxen, 1, 0) < 0 ||
            gline_request(&g_txen, g_chip, cfg->line_txen, 1, 0) < 0) {
            log_err("hal: failed to claim RXEN/TXEN GPIO lines");
            hal_close();
            return -5;
        }
    }

    /* LEDs are best-effort: warn but don't fail startup if they can't be claimed. */
    if (cfg->use_leds) {
        if (gline_request(&g_led_on, g_chip, cfg->line_led_on, 1, 0) < 0)
            log_warn("hal: status LED gpio %u unavailable", cfg->line_led_on);
        if (gline_request(&g_led_data, g_chip, cfg->line_led_data, 1, 0) < 0)
            log_warn("hal: activity LED gpio %u unavailable", cfg->line_led_data);
    }

    hal_rng_init();
    log_info("hal: %s @ %u Hz, gpio %s (rst=%u busy=%u dio1=%u nss=%u, rf-switch=%s)",
             cfg->spi_dev, g_spi_speed, cfg->gpio_chip, cfg->line_reset,
             cfg->line_busy, cfg->line_dio1, cfg->line_nss,
             cfg->rf_switch_external ? "RXEN/TXEN" : "DIO2");
    return 0;
}

void hal_close(void)
{
    gline_release(&g_reset);
    gline_release(&g_nss);
    gline_release(&g_rxen);
    gline_release(&g_txen);
    gline_release(&g_busy);
    gline_release(&g_dio1);
    gline_release(&g_led_on);
    gline_release(&g_led_data);
    if (g_chip)        { gpiod_chip_close(g_chip); g_chip = NULL; }
    if (g_spi_fd >= 0) { close(g_spi_fd); g_spi_fd = -1; }
}

#endif /* __linux__ */
