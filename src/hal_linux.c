/*
 * hal_linux.c - Raspberry Pi / Linux HAL: spidev + libgpiod (v1) + timing + RNG.
 *
 * Build deps: libgpiod-dev (Debian/RPi OS Bookworm ships libgpiod 1.6).
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

static int               g_spi_fd = -1;
static uint32_t          g_spi_speed = 2000000;
static struct gpiod_chip *g_chip = NULL;
static struct gpiod_line *g_reset, *g_busy, *g_dio1, *g_nss, *g_rxen, *g_txen;
static struct gpiod_line *g_led_on, *g_led_data;
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

    if (g_nss) gpiod_line_set_value(g_nss, 0);   /* assert NSS */
    int rc = ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &tr);
    if (g_nss) gpiod_line_set_value(g_nss, 1);   /* deassert NSS */

    if (rc < 1) {
        log_err("hal: SPI transfer failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------- GPIO ------------------- */
void hal_reset_pin(int level)         { if (g_reset) gpiod_line_set_value(g_reset, level ? 1 : 0); }
int  hal_busy_read(void)              { return g_busy ? gpiod_line_get_value(g_busy) : -1; }
int  hal_dio1_read(void)              { return g_dio1 ? gpiod_line_get_value(g_dio1) : -1; }

void hal_rf_switch(rf_switch_t mode)
{
    /* No-op when the SX126x drives DIO2 as the RF switch (g_rxen/g_txen unset). */
    int rx = 0, tx = 0;
    if (mode == RF_SW_RX) { rx = 1; tx = 0; }
    else if (mode == RF_SW_TX) { rx = 0; tx = 1; }
    if (g_rxen) gpiod_line_set_value(g_rxen, rx);
    if (g_txen) gpiod_line_set_value(g_txen, tx);
}

void hal_led_on(bool on)   { if (g_led_on)   gpiod_line_set_value(g_led_on, on ? 1 : 0); }
void hal_led_data(bool on) { if (g_led_data) gpiod_line_set_value(g_led_data, on ? 1 : 0); }

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
static struct gpiod_line *req_output(struct gpiod_chip *chip, unsigned off, int def)
{
    struct gpiod_line *l = gpiod_chip_get_line(chip, off);
    if (!l || gpiod_line_request_output(l, CONSUMER, def) < 0) {
        log_err("hal: cannot request GPIO %u as output: %s", off, strerror(errno));
        return NULL;
    }
    return l;
}

static struct gpiod_line *req_input(struct gpiod_chip *chip, unsigned off)
{
    struct gpiod_line *l = gpiod_chip_get_line(chip, off);
    if (!l || gpiod_line_request_input(l, CONSUMER) < 0) {
        log_err("hal: cannot request GPIO %u as input: %s", off, strerror(errno));
        return NULL;
    }
    return l;
}

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
    g_chip = gpiod_chip_open_lookup(cfg->gpio_chip);
    if (!g_chip) {
        log_err("hal: cannot open gpio chip '%s': %s", cfg->gpio_chip, strerror(errno));
        close(g_spi_fd);
        g_spi_fd = -1;
        return -3;
    }

    g_reset = req_output(g_chip, cfg->line_reset, 1); /* NRST idle high */
    g_nss   = req_output(g_chip, cfg->line_nss, 1);   /* NSS idle high (deasserted) */
    g_busy  = req_input(g_chip, cfg->line_busy);
    g_dio1  = req_input(g_chip, cfg->line_dio1);

    if (!g_reset || !g_nss || !g_busy || !g_dio1) {
        hal_close();
        return -4;
    }

    if (cfg->rf_switch_external) {
        g_rxen = req_output(g_chip, cfg->line_rxen, 0);
        g_txen = req_output(g_chip, cfg->line_txen, 0);
        if (!g_rxen || !g_txen) {
            hal_close();
            return -5;
        }
    }

    /* LEDs are best-effort: warn but don't fail startup if they can't be claimed. */
    if (cfg->use_leds) {
        g_led_on   = req_output(g_chip, cfg->line_led_on, 0);
        g_led_data = req_output(g_chip, cfg->line_led_data, 0);
        if (!g_led_on)   log_warn("hal: status LED gpio %u unavailable", cfg->line_led_on);
        if (!g_led_data) log_warn("hal: activity LED gpio %u unavailable", cfg->line_led_data);
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
    if (g_reset)    { gpiod_line_release(g_reset);    g_reset = NULL; }
    if (g_nss)      { gpiod_line_release(g_nss);      g_nss = NULL; }
    if (g_rxen)     { gpiod_line_release(g_rxen);     g_rxen = NULL; }
    if (g_txen)     { gpiod_line_release(g_txen);     g_txen = NULL; }
    if (g_busy)     { gpiod_line_release(g_busy);     g_busy = NULL; }
    if (g_dio1)     { gpiod_line_release(g_dio1);     g_dio1 = NULL; }
    if (g_led_on)   { gpiod_line_release(g_led_on);   g_led_on = NULL; }
    if (g_led_data) { gpiod_line_release(g_led_data); g_led_data = NULL; }
    if (g_chip)     { gpiod_chip_close(g_chip);       g_chip = NULL; }
    if (g_spi_fd >= 0) { close(g_spi_fd); g_spi_fd = -1; }
}

#endif /* __linux__ */
