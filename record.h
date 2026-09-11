// Pure (hardware independent) record codec for the Roman store.
//
// Kept free of every Pico SDK dependency so the format and the input validation
// can be unit tested on a host compiler - see tools/record_test.c.
//
// Payload layout produced by record_encode():
//
//   0      1    format version = 1
//   1      1    device id length n (1..RECORD_MAX_DEVICE_ID)
//   2..33       Ed25519 public key (32 bytes)
//   34..97      Ed25519 secret key (64 bytes = seed(32) || public key(32))
//   98..        device id (ASCII, no NUL)

#ifndef ROMAN_RECORD_H
#define ROMAN_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RECORD_FORMAT_VERSION 1
#define RECORD_MAX_DEVICE_ID 32
#define RECORD_FIXED_LEN 98
#define RECORD_MAX (RECORD_FIXED_LEN + RECORD_MAX_DEVICE_ID) // 130

// Strict base64 decode: canonical alphabet only, length a multiple of 4,
// padding required and checked, no whitespace, unused pad bits must be zero.
// Returns the number of decoded bytes, or -1 when the input is not valid
// base64 or does not fit in out[cap].
int record_b64_decode(const char *in, uint8_t *out, size_t cap);

// Device ids end up unescaped inside the /info and /sign JSON replies, so they
// are restricted to [A-Za-z0-9._-] and 1..RECORD_MAX_DEVICE_ID characters.
bool record_device_id_valid(const char *device_id);

// Serialises pk, sk and device_id into dst. Returns the payload length, or 0
// when an argument is invalid or cap is too small.
size_t record_encode(uint8_t *dst, size_t cap, const uint8_t pk[32],
                     const uint8_t sk[64], const char *device_id);

// Parses a payload produced by record_encode(). Any of the outputs may be NULL
// to skip it. Returns false (leaving the outputs untouched) on a bad version,
// a bad length or an invalid device id.
bool record_decode(const uint8_t *src, size_t len, uint8_t pk[32], uint8_t sk[64],
                   char *device_id, size_t device_id_cap);

#endif // ROMAN_RECORD_H
