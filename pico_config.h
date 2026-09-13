// Project-wide pico-sdk configuration header.
//
// This file is referenced by CMakeLists.txt via the SDK's
// PICO_CONFIG_HEADER_FILES variable: the SDK appends an #include of this file
// to its generated pico/config_autogen.h, so it is reached from pico.h by
// EVERY translation unit - including assembly (crt0.S), which defines the
// stack size from PICO_STACK_SIZE. Therefore this file may only contain
// preprocessor directives.
#ifndef ROMAN_PICO_CONFIG_H
#define ROMAN_PICO_CONFIG_H

// Size of the SDK boot stack: crt0 runs on this one until main() relocates the
// stack. It is deliberately left at the ceiling rather than tuned.
//
// NOTE: the pico-sdk linker places the core-0 stack (.stack_dummy) in the 4 KB
// SCRATCH_Y region and pins __StackTop to the top of it, so PICO_STACK_SIZE
// cannot exceed 0x1000 with the default memmap (an 8 KB setting fails to link
// with "section `.stack_dummy' will not fit in region `SCRATCH_Y'"). That
// ceiling is exactly why this is NOT the stack the firmware runs on: the
// tweetnacl chains alone need more than 4 KB (crypto_sign -> scalarbase ->
// scalarmult -> add peaks around 3.8 KB with the receive chain below it), so
// main() switches MSP to the 16 KB stack in stack.c before any C code runs.
// See the Stack budget section in README.md.
#ifndef PICO_STACK_SIZE
#define PICO_STACK_SIZE 0x1000
#endif

// Hardware-enforced stack overflow protection.
//
// On RP2350-ARM the SDK's runtime init sets the Armv8-M MSPLIM register to the
// boot stack bottom, and main() re-points it at the 16 KB SRAM stack it
// switches to, so every push below the real stack bottom raises a UsageFault
// instead of silently corrupting adjacent SRAM - which is how the POST /sign
// overflow showed up (silent lockup, recovered only by the watchdog).
// On RP2040 the SDK uses the Armv6-M MPU,
// on RISC-V the PMP. Any stack overflow now traps immediately at runtime.
#ifndef PICO_USE_STACK_GUARDS
#define PICO_USE_STACK_GUARDS 1
#endif

// Roman never starts core 1, so flash_safe_execute() must not try to synchronise
// with it. With this set the SDK takes its documented "no use of core 1" path
// (disable interrupts on core 0 and call the callback) instead of entering the
// multicore lockout handshake - which is both pointless here and a hang risk if
// some library ever pulls pico_multicore into the link.
#ifndef PICO_FLASH_ASSUME_CORE1_SAFE
#define PICO_FLASH_ASSUME_CORE1_SAFE 1
#endif

#endif // ROMAN_PICO_CONFIG_H
