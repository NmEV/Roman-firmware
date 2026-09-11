// Roman's encrypted flash store.
//
// On-flash layout (one 4 KB sector at XIP_BASE + STORAGE_FLASH_OFFSET, of which
// 512 bytes - two 256 byte pages - are programmed):
//
//   page 0 (programmed first)
//     0x000   4   magic "ROMN"
//     0x004   4   plaintext payload length (uint32 little endian)
//     0x008   1   format version = 1
//     0x009   3   reserved, 0xFF
//     0x00C  24   crypto_box nonce (fresh on every write)
//     0x024  32   X25519 public key  - plaintext by design: it is the bootstrap
//     0x044  32   X25519 secret key  - plaintext by design, see README.md
//     0x064  28   reserved, 0xFF
//   page 1
//     0x100  16   Poly1305 MAC of section 0
//     0x110 232   ciphertext of section 0 (payload <= STORAGE_MAX_PAYLOAD)
//     0x1F8   4   "DONE" - the stored writen flag, programmed LAST
//     0x1FC   4   reserved, 0xFF
//
// flash_range_program() walks the buffer in ascending address order, so the
// marker can only become valid once everything before it has landed. A power
// cut in the middle of provisioning therefore leaves writen == 0 and the board
// can simply be provisioned again instead of being locked out with a corrupt
// record.

#include <string.h>

#include "hardware/flash.h"
#include "pico/flash.h"
#include "pico/rand.h"
#include "pico/stdlib.h"

#include "storage.h"
#include "tweetnacl.h"

// 1 MB into flash: far above any plausible image size on a 2 MB (Pico) or 4 MB
// (Pico 2) part. CMakeLists.txt enforces the image stays below this offset.
#define STORAGE_FLASH_OFFSET (1024u * 1024u)

#define STORAGE_MAGIC "ROMN"
#define STORAGE_MAGIC_LEN 4
#define STORAGE_FORMAT_VERSION 1
#define STORAGE_NONCE_LEN 24
#define STORAGE_KEY_LEN_LOCAL 32
#define STORAGE_SECTION_SIZE 256
#define STORAGE_BOX_OVERHEAD 16
#define STORAGE_HEADER_SIZE 128
#define STORAGE_SECTION_OFF 256
#define STORAGE_MARKER_OFF 504
#define STORAGE_TOTAL_BYTES 512
#define STORAGE_MARKER "DONE"
#define STORAGE_MARKER_LEN 4

_Static_assert(STORAGE_SECTION_OFF == STORAGE_HEADER_SIZE * 2,
               "section area must start on the second page");
_Static_assert(STORAGE_BOX_OVERHEAD + STORAGE_MAX_PAYLOAD <=
                   STORAGE_MARKER_OFF - STORAGE_SECTION_OFF,
               "one section plus its MAC must fit before the marker");
_Static_assert(STORAGE_TOTAL_BYTES % FLASH_PAGE_SIZE == 0,
               "the programmed region must be a whole number of pages");
_Static_assert(STORAGE_TOTAL_BYTES <= FLASH_SECTOR_SIZE,
               "the record must fit inside the erased sector");
_Static_assert((STORAGE_FLASH_OFFSET % FLASH_SECTOR_SIZE) == 0,
               "the record must start on a sector boundary");

// tweetnacl.c expects this to be provided by the application; it is the only
// definition in the firmware (the crypto_box key pair depends on it).
void randombytes(unsigned char *out, unsigned long long outlen) {
    while (outlen >= sizeof(uint32_t)) {
        uint32_t r = get_rand_32();
        memcpy(out, &r, sizeof(r));
        out += sizeof(r);
        outlen -= sizeof(r);
    }
    if (outlen) {
        uint32_t r = get_rand_32();
        memcpy(out, &r, (size_t)outlen);
    }
}

static const uint8_t *const storage_flash =
    (const uint8_t *)(XIP_BASE + STORAGE_FLASH_OFFSET);

// RAM staging buffer: only the nonce, the keys and ciphertext ever reach flash.
static uint8_t storage_buf[STORAGE_TOTAL_BYTES];

// Handed to flash_safe_execute() exactly as the official flash_program example
// does. Both callbacks must run from RAM: flash is unavailable while erasing or
// programming.
static void __no_inline_not_in_flash_func(storage_erase_cb)(void *param) {
    (void)param;
    flash_range_erase(STORAGE_FLASH_OFFSET, FLASH_SECTOR_SIZE);
}

static void __no_inline_not_in_flash_func(storage_program_cb)(void *param) {
    uintptr_t *p = (uintptr_t *)param;
    uint32_t count = (uint32_t)p[0];
    const uint8_t *data = (const uint8_t *)(uintptr_t)p[1];
    flash_range_program(STORAGE_FLASH_OFFSET, data, count);
}

// crypto_box nonce layout: bytes [0..15] feed HSalsa20 (the sub key), bytes
// [16..23] are the Salsa20 nonce. XORing the section index into the last eight
// bytes gives every section an independent keystream while only one base nonce
// has to be stored.
static void storage_section_nonce(const uint8_t base[STORAGE_NONCE_LEN],
                                  uint32_t idx,
                                  uint8_t out[STORAGE_NONCE_LEN]) {
    memcpy(out, base, STORAGE_NONCE_LEN);
    for (int b = 0; b < 8; ++b) {
        out[STORAGE_NONCE_LEN - 8 + b] ^= (uint8_t)(idx >> (b * 8));
    }
}

bool storage_writen(void) {
    return memcmp(storage_flash + STORAGE_MARKER_OFF, STORAGE_MARKER,
                  STORAGE_MARKER_LEN) == 0;
}

bool storage_available(void) {
    if (memcmp(storage_flash, STORAGE_MAGIC, STORAGE_MAGIC_LEN) != 0) {
        return false;
    }
    uint32_t len;
    memcpy(&len, storage_flash + STORAGE_MAGIC_LEN, sizeof(len));
    return len > 0 && len <= STORAGE_MAX_PAYLOAD;
}

bool storage_x25519_pk(uint8_t pk[STORAGE_KEY_LEN]) {
    if (!storage_available()) {
        return false;
    }
    memcpy(pk, storage_flash + 0x24, STORAGE_KEY_LEN);
    return true;
}

size_t storage_read(uint8_t *dst, size_t cap) {
    if (dst == NULL || !storage_available()) {
        return 0;
    }

    uint32_t len;
    memcpy(&len, storage_flash + STORAGE_MAGIC_LEN, sizeof(len));
    if (len > cap) {
        len = (uint32_t)cap;
    }

    const uint8_t *nonce = storage_flash + 0x0C;
    const uint8_t *pk = storage_flash + 0x24;
    const uint8_t *sk = storage_flash + 0x44;

    // Section by section: each one is opened in a stack buffer (zero padding +
    // MAC + ciphertext) and the plaintext is appended to the caller's buffer.
    size_t pos = STORAGE_SECTION_OFF;
    for (uint32_t i = 0; (size_t)i * STORAGE_SECTION_SIZE < len; ++i) {
        size_t off = (size_t)i * STORAGE_SECTION_SIZE;
        size_t chunk = len - off;
        if (chunk > STORAGE_SECTION_SIZE) {
            chunk = STORAGE_SECTION_SIZE;
        }

        uint8_t sec_nonce[STORAGE_NONCE_LEN];
        storage_section_nonce(nonce, i, sec_nonce);

        uint8_t box[32 + STORAGE_SECTION_SIZE];
        memset(box, 0, 32);
        memcpy(box + 16, storage_flash + pos, STORAGE_BOX_OVERHEAD);
        memcpy(box + 32, storage_flash + pos + STORAGE_BOX_OVERHEAD, chunk);

        // In place is safe: crypto_secretbox_open() verifies the MAC over the
        // ciphertext before the keystream XOR overwrites it.
        if (crypto_box_open(box, box, 32 + chunk, sec_nonce, pk, sk) != 0) {
            return 0; // authentication failed: treat the record as unusable
        }
        memcpy(dst + off, box + 32, chunk);
        pos += STORAGE_BOX_OVERHEAD + chunk;
    }
    return len;
}

bool storage_write(const uint8_t *src, size_t len) {
    if (src == NULL || len == 0 || len > STORAGE_MAX_PAYLOAD) {
        return false;
    }

    // Fresh key pair and fresh nonce for this write.
    uint8_t pk[STORAGE_KEY_LEN_LOCAL], sk[STORAGE_KEY_LEN_LOCAL];
    if (crypto_box_keypair(pk, sk) != 0) {
        return false;
    }
    uint8_t nonce[STORAGE_NONCE_LEN];
    randombytes(nonce, STORAGE_NONCE_LEN);

    // Stage the whole programmed region; the erased (0xFF) fill is what an
    // untouched part of the sector looks like.
    memset(storage_buf, 0xFF, sizeof(storage_buf));
    memcpy(storage_buf, STORAGE_MAGIC, STORAGE_MAGIC_LEN);
    uint32_t len_le = (uint32_t)len;
    memcpy(storage_buf + 4, &len_le, sizeof(len_le));
    storage_buf[8] = STORAGE_FORMAT_VERSION;
    memcpy(storage_buf + 0x0C, nonce, STORAGE_NONCE_LEN);
    memcpy(storage_buf + 0x24, pk, STORAGE_KEY_LEN_LOCAL);
    memcpy(storage_buf + 0x44, sk, STORAGE_KEY_LEN_LOCAL);

    size_t pos = STORAGE_SECTION_OFF;
    for (uint32_t i = 0; (size_t)i * STORAGE_SECTION_SIZE < len; ++i) {
        size_t off = (size_t)i * STORAGE_SECTION_SIZE;
        size_t chunk = len - off;
        if (chunk > STORAGE_SECTION_SIZE) {
            chunk = STORAGE_SECTION_SIZE;
        }

        uint8_t sec_nonce[STORAGE_NONCE_LEN];
        storage_section_nonce(nonce, i, sec_nonce);

        uint8_t box[32 + STORAGE_SECTION_SIZE];
        memset(box, 0, 32);
        memcpy(box + 32, src + off, chunk);
        if (crypto_box(box, box, 32 + chunk, sec_nonce, pk, sk) != 0) {
            return false;
        }
        memcpy(storage_buf + pos, box + 16, STORAGE_BOX_OVERHEAD + chunk);
        pos += STORAGE_BOX_OVERHEAD + chunk;
    }

    // The marker goes in last (highest address): see the layout comment above.
    memcpy(storage_buf + STORAGE_MARKER_OFF, STORAGE_MARKER, STORAGE_MARKER_LEN);

    int rc = flash_safe_execute(storage_erase_cb, NULL, UINT32_MAX);
    if (rc != PICO_OK) {
        return false;
    }
    uintptr_t params[2] = {STORAGE_TOTAL_BYTES, (uintptr_t)storage_buf};
    rc = flash_safe_execute(storage_program_cb, params, UINT32_MAX);
    return rc == PICO_OK;
}

bool storage_clear(void) {
    int rc = flash_safe_execute(storage_erase_cb, NULL, UINT32_MAX);
    return rc == PICO_OK;
}
