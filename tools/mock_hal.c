/*
 * mock_hal.c - a no-hardware HAL so the protocol core can be unit-tested on any
 * host (used by the self-test; never linked into the real daemon).
 */
#include "../src/hal.h"

#include <string.h>
#include <time.h>
#include <stdint.h>

int  hal_init(const hal_config_t *cfg) { (void)cfg; return 0; }
void hal_close(void) {}

int hal_spi_xfer(const uint8_t *tx, uint8_t *rx, size_t len)
{
    (void)tx;
    if (rx)
        memset(rx, 0, len);
    return 0;
}

void hal_reset_pin(int level) { (void)level; }
int  hal_busy_read(void) { return 0; }
int  hal_dio1_read(void) { return 0; }
void hal_rf_switch(rf_switch_t mode) { (void)mode; }
void hal_led_on(bool on) { (void)on; }
void hal_led_data(bool on) { (void)on; }
int  hal_wait_busy_low(uint32_t timeout_us) { (void)timeout_us; return 0; }

uint64_t hal_millis(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

void hal_delay_ms(uint32_t ms) { (void)ms; }
void hal_delay_us(uint32_t us) { (void)us; }

static uint64_t s = 0x123456789abcdef0ull;
void hal_rng_init(void) {}
uint32_t hal_rng_int(uint32_t lo, uint32_t hi)
{
    if (hi <= lo) return lo;
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return lo + (uint32_t)(s % (hi - lo + 1));
}
