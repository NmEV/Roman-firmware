#include "led.h"

typedef enum {
    LED_READY,
    LED_ACTIVITY,
    LED_SIGNING,
    LED_ERROR,
} led_pattern_t;

static led_pattern_t current_pattern = LED_READY;
static int pattern_step = 0;
static absolute_time_t next_toggle;

static void schedule_ms(uint32_t ms) {
    next_toggle = make_timeout_time_ms(ms);
}

void led_init(void) {
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    gpio_put(LED_PIN, 0);
    pattern_step = 0;
    current_pattern = LED_READY;
    schedule_ms(100);
}

void led_set_ready(void) {
    current_pattern = LED_READY;
    pattern_step = 0;
    gpio_put(LED_PIN, 1);
    schedule_ms(100);
}

void led_signal_activity(void) {
    current_pattern = LED_ACTIVITY;
    pattern_step = 0;
    gpio_put(LED_PIN, 0);
    schedule_ms(50);
}

void led_signal_signing(void) {
    current_pattern = LED_SIGNING;
    pattern_step = 0;
    gpio_put(LED_PIN, 0);
    schedule_ms(150);
}

void led_signal_error(void) {
    current_pattern = LED_ERROR;
    pattern_step = 0;
    gpio_put(LED_PIN, 0);
    schedule_ms(500);
}

void led_tick(void) {
    if (!time_reached(next_toggle)) {
        return;
    }

    switch (current_pattern) {
        case LED_READY:
            gpio_put(LED_PIN, 1);
            schedule_ms(100);
            break;

        case LED_ACTIVITY:
            pattern_step++;
            if (pattern_step >= 1) {
                gpio_put(LED_PIN, 1);
                current_pattern = LED_READY;
            } else {
                gpio_put(LED_PIN, 0);
                schedule_ms(50);
            }
            break;

        case LED_SIGNING:
            pattern_step++;
            switch (pattern_step) {
                case 1: gpio_put(LED_PIN, 0); schedule_ms(150); break;
                case 2: gpio_put(LED_PIN, 1); schedule_ms(150); break;
                case 3: gpio_put(LED_PIN, 0); schedule_ms(150); break;
                case 4: gpio_put(LED_PIN, 1); schedule_ms(1000); break;
                default:
                    current_pattern = LED_READY;
                    gpio_put(LED_PIN, 1);
                    schedule_ms(100);
                    break;
            }
            break;

        case LED_ERROR:
            gpio_put(LED_PIN, !gpio_get(LED_PIN));
            schedule_ms(500);
            break;
    }
}
