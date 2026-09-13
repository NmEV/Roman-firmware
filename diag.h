// Post-mortem progress markers for the two deep paths: provisioning and signing.
//
// POST /write runs the crypto and the flash erase, POST /sign runs the single
// deepest tweetnacl chain in the firmware (crypto_sign -> scalarbase ->
// scalarmult -> add); a fault or a stall in either used to leave the board dead
// until it was unplugged. The stage markers below go into the watchdog
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
    DIAG_STAGE_SIGN_ENTER,   // POST /sign received
    DIAG_STAGE_SIGN_KEY,     // signing key and device id decrypted
    DIAG_STAGE_SIGN_PARSE,   // challenge/context/timestamp parsed
    DIAG_STAGE_SIGN_CRYPTO,  // inside crypto_sign (the deepest chain there is)
    DIAG_STAGE_SIGN_REPLY,   // signature computed, building the reply
    DIAG_STAGE_SIGN_DONE,    // 200 answered
    DIAG_STAGE_MAX = DIAG_STAGE_SIGN_DONE, // keep this last: bounds the range check
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
