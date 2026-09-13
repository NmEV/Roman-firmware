// See keystore.h.

#include <stdio.h>
#include <string.h>

#include "diag.h"
#include "keystore.h"
#include "record.h"
#include "storage.h"
#include "tweetnacl.h"

// The record can only change through keystore_provision() or a /debug clear,
// both of which invalidate this cache.
static uint8_t cached_pk[32];
static uint8_t cached_sk[64];
static char cached_id[RECORD_MAX_DEVICE_ID + 1];
static bool cache_valid;

// NOTE - do not call crypto_sign_open() in this firmware.
//
// Provisioning used to prove that pk really belongs to sk by signing a probe and
// verifying it. That path does not fit the 4 KB core-0 stack: crypto_sign_open()
// has a 1904 byte frame and its add() call adds another 1200 bytes, so the pair
// check alone peaks at 3104 bytes, and with the lwIP receive chain and an
// interrupt frame on top it exceeded PICO_STACK_SIZE (4096). The stack guard
// fired, the exception entry could not push either (lockup), and only the
// watchdog recovered the board - reported as last_stage=pair-check.
//
// See the "Stack budget" section in README.md for the measured numbers. The
// cheap structural check in keystore_provision() (crypto_verify_32) is all that
// is left here; whether pk matches the seed is verified by the *client* after
// provisioning, by checking one signature from POST /sign.

static bool keystore_load(void) {
    if (cache_valid) {
        return true;
    }

    uint8_t payload[STORAGE_MAX_PAYLOAD];
    size_t len = storage_read(payload, sizeof(payload));
    if (len == 0) {
        return false;
    }
    if (!record_decode(payload, len, cached_pk, cached_sk, cached_id,
                       sizeof(cached_id))) {
        return false;
    }
    cache_valid = true;
    return true;
}

void keystore_invalidate(void) {
    cache_valid = false;
    memset(cached_sk, 0, sizeof(cached_sk));
}

bool keystore_writen(void) {
    return storage_writen();
}

keystore_state_t keystore_state(void) {
    if (!storage_writen()) {
        return KEYSTORE_STATE_EMPTY;
    }
    return keystore_load() ? KEYSTORE_STATE_PROVISIONED : KEYSTORE_STATE_CORRUPT;
}

keystore_status_t keystore_provision(const char *pk_b64, const char *sk_b64,
                                     const char *device_id) {
    // The stored flag is checked before anything else is even parsed, so a
    // second POST /write never touches flash.
    if (storage_writen()) {
        return KEYSTORE_ERR_ALREADY;
    }
    if (pk_b64 == NULL || sk_b64 == NULL || !record_device_id_valid(device_id)) {
        return KEYSTORE_ERR_ARG;
    }
    // Breadcrumbs: provisioning runs once per board and is the only path that
    // touches the TRNG and flash, so it logs where it is (see README).
    diag_stage(DIAG_STAGE_FIELDS_OK);
    printf("keystore: fields accepted, device_id=%s\n", device_id);

    // Static, not on the stack: provisioning funnels into the crypto_box chain
    // (see the Stack budget section in README.md).
    static uint8_t pk[32];
    if (record_b64_decode(pk_b64, pk, sizeof(pk)) != 32) {
        return KEYSTORE_ERR_ARG;
    }

    static uint8_t sk[64];
    int sk_len = record_b64_decode(sk_b64, sk, sizeof(sk));
    if (sk_len == 32) {
        memcpy(sk + 32, pk, 32); // a bare seed: the public half is appended
    } else if (sk_len != 64) {
        return KEYSTORE_ERR_ARG;
    }

    // Cheap structural check only (no crypto, no extra stack): when the client
    // sends a full 64 byte sk, its embedded public key must be the one it also
    // sent. Whether pk really is derived from the seed is NOT checked here - see
    // the note above and the acceptance test in README.md.
    diag_stage(DIAG_STAGE_PAIR_CHECK);
    printf("keystore: checking the key pair\n");
    if (crypto_verify_32(sk + 32, pk) != 0) {
        printf("keystore: key pair rejected\n");
        return KEYSTORE_ERR_MISMATCH;
    }
    diag_stage(DIAG_STAGE_PAIR_OK);
    printf("keystore: key pair ok, entering the storage path\n");

    static uint8_t payload[RECORD_MAX];
    size_t len = record_encode(payload, sizeof(payload), pk, sk, device_id);
    if (len == 0) {
        return KEYSTORE_ERR_ARG;
    }
    if (!storage_write(payload, len)) {
        printf("keystore: flash write failed\n");
        return KEYSTORE_ERR_FLASH;
    }
    diag_stage(DIAG_STAGE_DONE);
    printf("keystore: committed, writen=1\n");

    keystore_invalidate();
    return KEYSTORE_OK;
}

keystore_clear_status_t keystore_clear(const char *ed25519_sk_b64) {
    // Nothing stored: the goal state already holds, so this is not an error (a
    // client may always call /clear first).
    if (!storage_writen()) {
        return KEYSTORE_CLEAR_EMPTY;
    }
    if (ed25519_sk_b64 == NULL) {
        return KEYSTORE_CLEAR_ERR_ARG;
    }

    diag_stage(DIAG_STAGE_CLEAR);
    printf("keystore: /clear, checking the key\n");

    // The stored record has to decrypt before anything can be compared with it.
    if (!keystore_load()) {
        return KEYSTORE_CLEAR_ERR_DENIED;
    }

    static uint8_t given[64];
    int len = record_b64_decode(ed25519_sk_b64, given, sizeof(given));
    if (len != 32 && len != 64) {
        return KEYSTORE_CLEAR_ERR_ARG;
    }

    // Constant time comparison of the seed half, plus the public half when the
    // caller sent the full 64 byte form.
    if (crypto_verify_32(given, cached_sk) != 0) {
        return KEYSTORE_CLEAR_ERR_DENIED;
    }
    if (len == 64 && crypto_verify_32(given + 32, cached_sk + 32) != 0) {
        return KEYSTORE_CLEAR_ERR_DENIED;
    }

    if (!storage_clear()) {
        printf("keystore: /clear erase failed\n");
        return KEYSTORE_CLEAR_ERR_FLASH;
    }
    keystore_invalidate();
    printf("keystore: /clear done, writen=0\n");
    return KEYSTORE_CLEAR_OK;
}

bool keystore_signing_key(uint8_t sk64[64]) {
    if (sk64 == NULL || !keystore_load()) {
        return false;
    }
    memcpy(sk64, cached_sk, sizeof(cached_sk));
    return true;
}

bool keystore_device_id(char *out, size_t cap) {
    if (out == NULL || !keystore_load()) {
        return false;
    }
    size_t len = strlen(cached_id);
    if (cap < len + 1) {
        return false;
    }
    memcpy(out, cached_id, len + 1);
    return true;
}

bool keystore_public_key(uint8_t pk[32]) {
    if (pk == NULL || !keystore_load()) {
        return false;
    }
    memcpy(pk, cached_pk, sizeof(cached_pk));
    return true;
}
