/*
 * hal.h - hardware abstraction the radio driver and main loop depend on.
 *
 * The Linux/Raspberry-Pi implementation lives in hal_linux.c (spidev +
 * libgpiod).  A mock implementation (tools/mock_hal.c) lets the protocol core
 * be unit-tested on any host.  Nothing above this layer includes Linux headers.
 */
#ifndef MC_HAL_H
#define MC_HAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Largest single SPI payload (buffer read/write of a 255-byte LoRa packet). */
#define MC_SPI_MAX 256

typedef enum {
    RF_SW_OFF = 0,
    RF_SW_RX,
    RF_SW_TX
} rf_switch_t;

typedef struct {
    const char *spi_dev;          /* e.g. "/dev/spidev0.0" */
    uint32_t    spi_speed_hz;     /* <= 10 MHz for SX126x */
    const char *gpio_chip;        /* e.g. "gpiochip0" (Pi5: "gpiochip4") */
    unsigned    line_reset;       /* NRST  (output) */
    unsigned    line_busy;        /* BUSY  (input)  */
    unsigned    line_dio1;        /* DIO1  (input, RX/TX done irq) */
    unsigned    line_nss;         /* NSS   (output, manual chip-select GPIO) */
    bool        rf_switch_external; /* true: drive RXEN/TXEN; false: DIO2 internal switch */
    unsigned    line_rxen;        /* RXEN  (output) - only if rf_switch_external */
    unsigned    line_txen;        /* TXEN  (output) - only if rf_switch_external */
    bool        use_leds;
    unsigned    line_led_on;      /* status LED (output, solid while running) */
    unsigned    line_led_data;    /* activity LED (output, pulses on RX/TX) */
} hal_config_t;

int  hal_init(const hal_config_t *cfg);  /* 0 on success */
void hal_close(void);

/* Full-duplex SPI transfer; rx may be NULL (write-only). 0 on success. */
int  hal_spi_xfer(const uint8_t *tx, uint8_t *rx, size_t len);

/* GPIO */
void hal_reset_pin(int level);            /* drive NRST */
int  hal_busy_read(void);                 /* 0/1, <0 error */
int  hal_dio1_read(void);                 /* 0/1, <0 error */
void hal_rf_switch(rf_switch_t mode);     /* drive RXEN/TXEN (no-op when DIO2 switch is used) */

/* LEDs (no-op if not configured) */
void hal_led_on(bool on);                 /* status / power LED */
void hal_led_data(bool on);               /* RX/TX activity LED */

/* Spin until BUSY is low. Returns 0, or -1 on timeout. */
int  hal_wait_busy_low(uint32_t timeout_us);

/* Timing */
uint64_t hal_millis(void);
void     hal_delay_ms(uint32_t ms);
void     hal_delay_us(uint32_t us);

/* RNG (seeded from OS entropy); inclusive [lo,hi]. Matches MeshCore rng->nextInt. */
void     hal_rng_init(void);
uint32_t hal_rng_int(uint32_t lo, uint32_t hi);

#endif /* MC_HAL_H */
