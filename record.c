// See record.h. Pure logic: no Pico SDK, no crypto, no globals.

#include <string.h>

#include "record.h"

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int record_b64_decode(const char *in, uint8_t *out, size_t cap) {
    if (in == NULL || out == NULL) {
        return -1;
    }
    size_t in_len = strlen(in);
    if (in_len == 0 || (in_len % 4) != 0) {
        return -1;
    }

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            char c = in[i + k];
            if (c == '=') {
                // Padding is only allowed in the final quartet, and only in the
                // last two positions of it.
                if (k < 2 || i + 4 != in_len) {
                    return -1;
                }
                v[k] = 0;
                ++pad;
            } else {
                if (pad != 0) { // data after padding
                    return -1;
                }
                v[k] = b64_value(c);
                if (v[k] < 0) { // character outside the alphabet
                    return -1;
                }
            }
        }
        // Canonical form: the bits that do not belong to a decoded byte must be
        // zero, otherwise "QQ==" and "QR==" would both decode to 'A'.
        if (pad == 1 && (v[2] & 0x03) != 0) {
            return -1;
        }
        if (pad == 2 && (v[1] & 0x0F) != 0) {
            return -1;
        }

        uint32_t triple = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                          ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        uint8_t bytes[3];
        bytes[0] = (uint8_t)(triple >> 16);
        bytes[1] = (uint8_t)(triple >> 8);
        bytes[2] = (uint8_t)triple;

        int take = 3 - pad;
        if (o + (size_t)take > cap) {
            return -1;
        }
        for (int k = 0; k < take; ++k) {
            out[o++] = bytes[k];
        }
    }
    return (int)o;
}

bool record_device_id_valid(const char *device_id) {
    if (device_id == NULL) {
        return false;
    }
    size_t n = strlen(device_id);
    if (n == 0 || n > RECORD_MAX_DEVICE_ID) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        char c = device_id[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

size_t record_encode(uint8_t *dst, size_t cap, const uint8_t pk[32],
                     const uint8_t sk[64], const char *device_id) {
    if (dst == NULL || pk == NULL || sk == NULL ||
        !record_device_id_valid(device_id)) {
        return 0;
    }
    size_t id_len = strlen(device_id);
    size_t total = RECORD_FIXED_LEN + id_len;
    if (total > cap || total > RECORD_MAX) {
        return 0;
    }

    dst[0] = (uint8_t)RECORD_FORMAT_VERSION;
    dst[1] = (uint8_t)id_len;
    memcpy(dst + 2, pk, 32);
    memcpy(dst + 34, sk, 64);
    memcpy(dst + RECORD_FIXED_LEN, device_id, id_len);
    return total;
}

bool record_decode(const uint8_t *src, size_t len, uint8_t pk[32], uint8_t sk[64],
                   char *device_id, size_t device_id_cap) {
    if (src == NULL || len < RECORD_FIXED_LEN || len > RECORD_MAX) {
        return false;
    }
    if (src[0] != (uint8_t)RECORD_FORMAT_VERSION) {
        return false;
    }
    size_t id_len = src[1];
    if (id_len == 0 || id_len > RECORD_MAX_DEVICE_ID) {
        return false;
    }
    if (len != RECORD_FIXED_LEN + id_len) {
        return false;
    }

    char id[RECORD_MAX_DEVICE_ID + 1];
    memcpy(id, src + RECORD_FIXED_LEN, id_len);
    id[id_len] = '\0';
    if (!record_device_id_valid(id)) {
        return false;
    }

    if (pk != NULL) {
        memcpy(pk, src + 2, 32);
    }
    if (sk != NULL) {
        memcpy(sk, src + 34, 64);
    }
    if (device_id != NULL) {
        if (device_id_cap < id_len + 1) {
            return false;
        }
        memcpy(device_id, id, id_len + 1);
    }
    return true;
}
