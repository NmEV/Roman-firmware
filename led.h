#ifndef LED_H
#define LED_H

#include <pico/stdlib.h>

#define LED_PIN 25

void led_init(void);
void led_set_ready(void);
void led_signal_activity(void);
void led_signal_signing(void);
void led_signal_error(void);
void led_tick(void);

#endif
