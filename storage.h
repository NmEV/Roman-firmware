// Roman's encrypted flash store (see storage.c for the on-flash layout).
//
// Same construction as the firmware-with-storage module: a fresh X25519 key
// pair and a fresh 24-byte nonce per write, crypto_box in 256 byte sections,
// the payload never reaching flash in the clear. Roman has its own layout
// (magic "ROMN") because it also carries the stored writen flag.

#ifndef ROMAN_STORAGE_H
#define ROMAN_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORAGE_KEY_LEN 32

// Encrypted payload capacity: one section (256 bytes) minus its Poly1305 MAC.
#define STORAGE_MAX_PAYLOAD 232

// The stored boolean: true once a record has been committed successfully.
bool storage_writen(void);

// True when the magic and a sane length are present; the record may still fail
// to decrypt (storage_read() returns 0 then).
bool storage_available(void);

// Decrypts the stored payload into dst. Returns the number of plaintext bytes,
// or 0 when nothing usable is stored or authentication failed.
size_t storage_read(uint8_t *dst, size_t cap);

// Generates a fresh X25519 key pair and nonce, boxes len bytes of src and
// programs the whole record. On success storage_writen() becomes true.
bool storage_write(const uint8_t *src, size_t len);

// Erases the record: writen goes back to false and the slot can be written
// again.
bool storage_clear(void);

// The stored (plaintext) X25519 public key, for POST /debug.
bool storage_x25519_pk(uint8_t pk[STORAGE_KEY_LEN]);

// Probes the hardware TRNG once, with a bounded wait. Returns true when it
// answered. randombytes() degrades to a TRNG-seeded software generator when it
// does not, so the firmware can never hang on its entropy source; this is used
// to report which path is in use at boot.
bool storage_trng_probe(void);

#endif // ROMAN_STORAGE_H
