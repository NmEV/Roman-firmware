// Roman's provisioning policy layer: it validates what POST /write supplies,
// commits it through storage.c and hands the decrypted material to the HTTP
// handlers (with a small RAM cache so a signature request does not pay for one
// X25519 scalarmult every time).

#ifndef ROMAN_KEYSTORE_H
#define ROMAN_KEYSTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    KEYSTORE_OK = 0,
    KEYSTORE_ERR_ARG,      // malformed base64, wrong length, bad device id
    KEYSTORE_ERR_MISMATCH, // the public key does not belong to the secret key
    KEYSTORE_ERR_ALREADY,  // writen is already set (one shot provisioning)
    KEYSTORE_ERR_FLASH,    // erase or program failed
} keystore_status_t;

typedef enum {
    KEYSTORE_STATE_EMPTY = 0,   // never provisioned, or cleared
    KEYSTORE_STATE_PROVISIONED, // writen and the record decrypts
    KEYSTORE_STATE_CORRUPT,     // writen but the record does not decrypt
} keystore_state_t;

// Storage state, used by /info and POST /debug. May decrypt the record once.
keystore_state_t keystore_state(void);

// The stored boolean, straight from flash (cheap, no crypto).
bool keystore_writen(void);

// One shot provisioning: checks writen first, then validates pk/sk/device_id,
// then writes the record. device_id must be 1..32 chars of [A-Za-z0-9._-];
// sk_b64 may be a 32 byte seed or a 64 byte seed||public key.
keystore_status_t keystore_provision(const char *pk_b64, const char *sk_b64,
                                     const char *device_id);

// Decrypted copies of the stored material. Return false when the record is
// missing, corrupt or (for the signing key) authentication failed.
bool keystore_signing_key(uint8_t sk64[64]);
bool keystore_device_id(char *out, size_t cap);
bool keystore_public_key(uint8_t pk[32]);

typedef enum {
    KEYSTORE_CLEAR_OK = 0,     // erased: the board can be provisioned again
    KEYSTORE_CLEAR_EMPTY,      // nothing was stored, nothing to do (idempotent)
    KEYSTORE_CLEAR_ERR_ARG,    // missing or malformed key      -> 400
    KEYSTORE_CLEAR_ERR_DENIED, // not the provisioned key       -> 403
    KEYSTORE_CLEAR_ERR_FLASH,  // erase failed                  -> 500
} keystore_clear_status_t;

// Erases the stored record so the board can be provisioned again, but only for a
// caller that proves it holds the provisioning secret: ed25519_sk_b64 must be
// the Ed25519 secret key that POST /write installed (32 byte seed, or the full
// 64 byte seed||public key, base64). That key is the client's own - the board
// only saw it once, at provisioning time - so this does not expose the X25519
// secret the payload is boxed with.
keystore_clear_status_t keystore_clear(const char *ed25519_sk_b64);

// Drops the RAM cache (after provisioning, or after a clear).
void keystore_invalidate(void);

#endif // ROMAN_KEYSTORE_H
