// See diag.h.

#include "hardware/structs/watchdog.h"
#include "hardware/watchdog.h"

#include "diag.h"

// Marker so a scratch register that was never written (or holds junk after a
// power cycle) is not mistaken for a stage number.
#define DIAG_MARKER 0x524F4D41u // "ROMA"

static diag_stage_t boot_stage;

void diag_stage(diag_stage_t stage) {
    // scratch[0..3] are ours: watchdog_reboot() only uses scratch[4..7].
    watchdog_hw->scratch[0] = DIAG_MARKER ^ (uint32_t)stage;
}

diag_stage_t diag_previous_stage(void) {
    if (!watchdog_caused_reboot()) {
        return DIAG_STAGE_IDLE;
    }
    uint32_t value = watchdog_hw->scratch[0] ^ DIAG_MARKER;
    if (value > (uint32_t)DIAG_STAGE_MAX) {
        return DIAG_STAGE_IDLE;
    }
    return (diag_stage_t)value;
}

void diag_capture_boot_stage(void) {
    boot_stage = diag_previous_stage();
    diag_stage(DIAG_STAGE_IDLE); // this run starts clean
}

diag_stage_t diag_boot_stage(void) {
    return boot_stage;
}

const char *diag_stage_name(diag_stage_t stage) {
    switch (stage) {
        case DIAG_STAGE_RECEIVED:   return "write-received";
        case DIAG_STAGE_FIELDS_OK:  return "fields-ok";
        case DIAG_STAGE_PAIR_CHECK: return "pair-check";
        case DIAG_STAGE_PAIR_OK:    return "pair-ok";
        case DIAG_STAGE_ENTROPY:    return "entropy";
        case DIAG_STAGE_BOXING:     return "boxing";
        case DIAG_STAGE_ERASE:      return "erase";
        case DIAG_STAGE_PROGRAM:    return "program";
        case DIAG_STAGE_DONE:       return "done";
        case DIAG_STAGE_CLEAR:      return "clear";
        case DIAG_STAGE_IDLE:
        default:                    return "none";
    }
}
