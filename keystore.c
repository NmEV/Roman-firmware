// See keystore.h.

#include <string.h>

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

// crypto_sign() never checks that sk[32..63] really is the public key belonging
// to sk[0..31]: a mismatched pair would silently produce signatures nobody can
// verify. /write only ever succeeds once, so the pair is proven here - sign a
// fixed probe and verify it with the supplied public key - before it is
// committed to flash.
static bool pair_works(const uint8_t pk[32], const uint8_t sk[64]) {
    static const char probe[] = "roman-provision-check";
    // static: crypto_sign() writes mlen + 64 bytes and this must not sit on the
    // stack of the deepest call path.
    static unsigned char signed_msg[sizeof(probe) + 64];
    unsigned char recovered[sizeof(probe)];
    unsigned long long signed_len = 0;
    unsigned long long recovered_len = 0;

    if (crypto_sign(signed_msg, &signed_len, (const unsigned char *)probe,
                    sizeof(probe) - 1, sk) != 0) {
        return false;
    }
    if (crypto_sign_open(recovered, &recovered_len, signed_msg, signed_len, pk) != 0) {
        return false;
    }
    return recovered_len == sizeof(probe) - 1 &&
           memcmp(recovered, probe, sizeof(probe) - 1) == 0;
}

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

    uint8_t pk[32];
    if (record_b64_decode(pk_b64, pk, sizeof(pk)) != 32) {
        return KEYSTORE_ERR_ARG;
    }

    uint8_t sk[64];
    int sk_len = record_b64_decode(sk_b64, sk, sizeof(sk));
    if (sk_len == 32) {
        memcpy(sk + 32, pk, 32); // a bare seed: the public half is appended
    } else if (sk_len != 64) {
        return KEYSTORE_ERR_ARG;
    }

    if (crypto_verify_32(sk + 32, pk) != 0 || !pair_works(pk, sk)) {
        return KEYSTORE_ERR_MISMATCH;
    }

    uint8_t payload[RECORD_MAX];
    size_t len = record_encode(payload, sizeof(payload), pk, sk, device_id);
    if (len == 0) {
        return KEYSTORE_ERR_ARG;
    }
    if (!storage_write(payload, len)) {
        return KEYSTORE_ERR_FLASH;
    }

    keystore_invalidate();
    return KEYSTORE_OK;
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
