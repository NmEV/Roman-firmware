// Host unit test for stack.c (no Pico SDK involved).
//
//   gcc -std=c11 -Wall -Wextra -I.. stack_test.c ../stack.c -o stack_test && ./stack_test
//
// stack.c is deliberately SDK free: the paint watermark is what reports how much
// headroom the deep tweetnacl chains leave, so the scan is worth testing without
// a board - and the numbers it produces are what the Stack budget section of the
// README is based on.

#include <stdio.h>
#include <string.h>

#include "stack.h"

static int failures = 0;
static int checks = 0;

static void check(const char *name, int cond) {
    ++checks;
    if (!cond) {
        ++failures;
        printf("FAIL  %s\n", name);
    } else {
        printf("PASS  %s\n", name);
    }
}

#define PAINT ((uint8_t)0xC5u)

static void test_watermark(void) {
    uint8_t region[128];

    memset(region, PAINT, sizeof region);
    check("untouched region reports its full size",
          stack_watermark(region, sizeof region, PAINT) == sizeof region);

    region[0] = 0x00;
    check("written bottom byte reports zero",
          stack_watermark(region, sizeof region, PAINT) == 0);

    memset(region, PAINT, sizeof region);
    region[40] = 0x00;
    check("first written byte bounds the unused part",
          stack_watermark(region, sizeof region, PAINT) == 40);

    memset(region, PAINT, sizeof region);
    region[sizeof region - 1] = 0x11;
    check("byte just above the bottom is found",
          stack_watermark(region, sizeof region, PAINT) == sizeof region - 1);

    // The scan cannot tell paint from data that happens to equal the paint
    // value: such a byte pushes the result deeper, i.e. it reports slightly
    // LESS usage. Bounded by the number of leading paint valued bytes and
    // normally zero, but the direction has to be documented.
    memset(region, PAINT, sizeof region);
    region[8] = 0x00;
    check("paint valued data below the real watermark reads as untouched",
          stack_watermark(region, sizeof region, PAINT) == 8);

    memset(region, PAINT, sizeof region);
    region[sizeof region / 2] = PAINT; // a data byte that looks like paint
    region[sizeof region / 2 + 1] = 0x00;
    check("a paint valued data byte only shifts the result",
          stack_watermark(region, sizeof region, PAINT) == sizeof region / 2 + 1);

    check("empty region reports zero", stack_watermark(region, 0, PAINT) == 0);
    check("single painted byte reports one", stack_watermark(region, 1, PAINT) == 1);

    region[0] = 0x00;
    check("single written byte reports zero", stack_watermark(region, 1, PAINT) == 0);

    check("null region reports zero", stack_watermark(NULL, sizeof region, PAINT) == 0);
}

static void test_stack_api(void) {
    // stack_total() comes straight from the array main() switches to.
    check("total is the 16 KB region", stack_total() == 16384u);

    // The host never runs on stack_ram, so used_now() must not underflow.
    check("used_now stays within the region", stack_used_now() <= stack_total());

    // Before stack_init() nothing is painted, so the watermark reads as fully
    // used - stack_check() must not report free space it never measured.
    stack_check();
    check("used_now and used_max are both consistent",
          stack_used_now() <= stack_total() && stack_used_max() <= stack_total());
    check("free_min never exceeds the region", stack_free_min() <= stack_total());

    uint32_t first = stack_used_max();
    stack_check();
    check("the watermark never shrinks", stack_used_max() >= first);
    check("used_max plus free_min add up",
          stack_used_max() + stack_free_min() == stack_total());
}

int main(void) {
    test_watermark();
    test_stack_api();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
