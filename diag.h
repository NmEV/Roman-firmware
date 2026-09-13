// Post-mortem progress markers for the provisioning path.
//
// POST /write is the only code path in Roman that runs the deep crypto chain
// and the flash erase, and a fault or a stall in there used to leave the board
// dead until it was unplugged. The stage markers below go into the watchdog
// scratch registers, which survive a watchdog reset, so the *next* boot can
// report how far the previous one got - in the boot log and in the POST /debug
// snapshot, without needing a UART adapter.

#ifndef ROMAN_DIAG_H
#define ROMAN_DIAG_H

#include <stdint.h>

typedef enum {
    DIAG_STAGE_IDLE = 0,     // nothing recorded (power cycle or clean run)
    DIAG_STAGE_RECEIVED,     // POST /write received and writen == 0
    DIAG_STAGE_FIELDS_OK,    // pk/sk/device_id parsed and validated
    DIAG_STAGE_PAIR_CHECK,   // inside the sign/verify key pair check
    DIAG_STAGE_PAIR_OK,      // key pair accepted, entering the storage path
    DIAG_STAGE_ENTROPY,      // generating the X25519 key pair (entropy)
    DIAG_STAGE_BOXING,       // boxing the payload section by section
    DIAG_STAGE_ERASE,        // erasing the flash sector
    DIAG_STAGE_PROGRAM,      // programming the record
    DIAG_STAGE_DONE,         // committed, writen == 1
    DIAG_STAGE_CLEAR,        // erasing the record for POST /clear
    DIAG_STAGE_MAX = DIAG_STAGE_CLEAR, // keep this last: bounds the range check
} diag_stage_t;

// Records the stage currently being executed.
void diag_stage(diag_stage_t stage);

// The stage the previous boot died in, or DIAG_STAGE_IDLE when the last reset
// was not a watchdog reset (power cycle, flashing, /debug reset).
diag_stage_t diag_previous_stage(void);

// Captures the previous boot's stage into RAM and clears the marker for this
// run. Call once, as early as possible in main(): the captured value is what
// POST /debug reports, so the evidence is not wiped before it can be read.
void diag_capture_boot_stage(void);

// The stage captured at boot, i.e. how far the previous run got before it died.
diag_stage_t diag_boot_stage(void);

// Short human readable name for the boot log and the debug snapshot.
const char *diag_stage_name(diag_stage_t stage);

#endif // ROMAN_DIAG_H
