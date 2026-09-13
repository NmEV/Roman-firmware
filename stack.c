// See stack.h.

#include <stdbool.h>

#include "stack.h"

// Value the unused stack is filled with. A running call chain leaves bytes
// behind that are not this value, so the lowest such byte is how deep the stack
// ever went.
#define STACK_PAINT 0xC5u

// Bytes above the current stack pointer that stack_init() leaves alone: its own
// frame and anything an interrupt may push while the paint loop runs.
#define STACK_PAINT_SLACK 64u

// Non static on purpose: the assembly in main() derives the initial stack
// pointer from this symbol.
uint32_t stack_ram[STACK_RAM_BYTES / 4] __attribute__((aligned(8)));

// Compile time guard: main() adds exactly 16384 to the address of stack_ram to
// find the initial stack pointer.
_Static_assert(sizeof(stack_ram) == 16384,
               "stack_ram must stay 16 KB: main() hardcodes that offset");

static uint32_t used_max; // deepest usage seen since stack_init()
static bool painted;      // false until stack_init() has run

size_t stack_watermark(const uint8_t *bottom, size_t size, uint8_t paint) {
    size_t offset = 0;
    if (bottom == NULL) {
        return 0;
    }
    while (offset < size && bottom[offset] == paint) {
        ++offset;
    }
    return offset;
}

void stack_init(void) {
    // The paint runs on the stack it paints: everything below the current frame
    // is free by definition, but leave a little room for the loop itself.
    uint8_t *bottom = (uint8_t *)stack_ram;
    uint8_t *limit = (uint8_t *)((uintptr_t)__builtin_frame_address(0) - STACK_PAINT_SLACK);

    for (uint8_t *p = bottom; p < limit; ++p) {
        *p = (uint8_t)STACK_PAINT;
    }
    used_max = 0;
    painted = true;
    stack_check();
}

void stack_check(void) {
    if (!painted) {
        return;
    }
    size_t untouched = stack_watermark((const uint8_t *)stack_ram, sizeof(stack_ram),
                                       (uint8_t)STACK_PAINT);
    uint32_t used = (uint32_t)(sizeof(stack_ram) - untouched);
    if (used > used_max) {
        used_max = used;
    }
}

uint32_t stack_total(void) {
    return (uint32_t)sizeof(stack_ram);
}

uint32_t stack_used_now(void) {
    uintptr_t bottom = (uintptr_t)stack_ram;
    uintptr_t top = bottom + sizeof(stack_ram);
    uintptr_t sp = (uintptr_t)__builtin_frame_address(0);
    // The host test runs on a stack that is nowhere near this array, and on
    // the board nothing must be able to report a value outside the region
    // either: sp == bottom means the stack is exactly full, everything else
    // outside the range means "not running on this stack".
    if (sp < bottom || sp >= top) {
        return 0;
    }
    return (uint32_t)(top - sp);
}

uint32_t stack_used_max(void) {
    return used_max;
}

uint32_t stack_free_min(void) {
    uint32_t total = stack_total();
    return (used_max >= total) ? 0u : (total - used_max);
}
