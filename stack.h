// The stack the firmware actually runs on.
//
// PICO_STACK_SIZE (0x1000 in pico_config.h) only covers the SDK's boot stack: the
// pico-sdk linker places .stack_dummy in the 4 KB SCRATCH_Y region and pins
// __StackTop to the top of it, so it cannot grow. TweetNaCl needs more than that -
// crypto_sign -> scalarbase -> scalarmult -> add peaks around 4.4 KB together with
// the USB/lwIP receive chain - so main() switches MSP into the 16 KB region below
// before any application code runs. See the Stack budget section in README.md.

#ifndef ROMAN_STACK_H
#define ROMAN_STACK_H

#include <stddef.h>
#include <stdint.h>

// Size of the run time stack. main() hardcodes this offset in its assembly, so
// stack.c asserts that the array below really is this big.
#define STACK_RAM_BYTES (16u * 1024u)

// The stack storage itself. main() loads its address and its end straight from
// this symbol, and stack_init() references it from C so that
// -ffunction-sections/--gc-sections can never drop it.
extern uint32_t stack_ram[STACK_RAM_BYTES / 4];

// Paints the unused part of the stack and takes the first watermark sample.
// Call once, as the first statement of app_main().
void stack_init(void);

// Rescans the stack and updates the deepest usage seen so far. Cheap enough to
// call from the main loop and before building the POST /debug snapshot.
void stack_check(void);

// Total size of the run time stack in bytes.
uint32_t stack_total(void);

// Bytes in use right now, measured from the current stack pointer.
uint32_t stack_used_now(void);

// Deepest usage seen since stack_init(), from the paint watermark.
uint32_t stack_used_max(void);

// stack_total() - stack_used_max(): the smallest headroom seen so far. A new
// deep call chain has to leave this comfortably positive, otherwise it can hit
// the MSPLIM guard - which on Armv8-M is a UsageFault whose exception entry
// cannot push, i.e. a silent lockup only the watchdog recovers.
uint32_t stack_free_min(void);

// Pure helper behind the watermark scan: the offset of the first byte that no
// longer holds the paint value, i.e. how deep the stack has reached. A fully
// painted region returns size. Host tested in tools/stack_test.c.
size_t stack_watermark(const uint8_t *bottom, size_t size, uint8_t paint);

#endif // ROMAN_STACK_H
