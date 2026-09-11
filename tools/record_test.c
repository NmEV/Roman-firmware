// Host unit test for record.c (no Pico SDK involved).
//
//   gcc -std=c11 -Wall -Wextra -I.. record_test.c ../record.c -o record_test && ./record_test
//
// Covers the strict base64 decoder, the device id rules and the payload codec.

#include <stdio.h>
#include <string.h>

#include "record.h"

static int failures = 0;
static int checks = 0;

static void check(const char *name, int cond) {
    ++checks;
    if (!cond) {
        ++failures;
        printf("FAIL  %s\n", name);
    } else {
        printf("PASS  %s\n", name);
    }
}

// Independent reference encoder, so the decoder is not tested against itself
// for the long vectors.
static void b64_encode_ref(const unsigned char *in, size_t n, char *out) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned b = ((unsigned)in[i]) << 16;
        if (i + 1 < n) b |= ((unsigned)in[i + 1]) << 8;
        if (i + 2 < n) b |= (unsigned)in[i + 2];
        out[j++] = tbl[(b >> 18) & 0x3F];
        out[j++] = tbl[(b >> 12) & 0x3F];
        out[j++] = (i + 1 < n) ? tbl[(b >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < n) ? tbl[b & 0x3F] : '=';
    }
    out[j] = '\0';
}

static void test_b64_vectors(void) {
    unsigned char out[128];
    check("b64 \"\" rejected", record_b64_decode("", out, sizeof out) == -1);
    check("b64 QQ== -> 1 byte", record_b64_decode("QQ==", out, sizeof out) == 1 && out[0] == 'A');
    check("b64 QUI= -> AB", record_b64_decode("QUI=", out, sizeof out) == 2 && out[0] == 'A' && out[1] == 'B');
    check("b64 QUJD -> ABC", record_b64_decode("QUJD", out, sizeof out) == 3 && memcmp(out, "ABC", 3) == 0);
    check("b64 non-canonical pad bits rejected", record_b64_decode("QR==", out, sizeof out) == -1);
    check("b64 length %4 rejected", record_b64_decode("QQ", out, sizeof out) == -1);
    check("b64 'Q===' rejected", record_b64_decode("Q===", out, sizeof out) == -1);
    check("b64 '=QQ=' rejected", record_b64_decode("=QQ=", out, sizeof out) == -1);
    check("b64 data after padding rejected", record_b64_decode("QQ=A", out, sizeof out) == -1);
    check("b64 two quartets w/ padding rejected", record_b64_decode("QQ==QQ==", out, sizeof out) == -1);
    check("b64 whitespace rejected", record_b64_decode("QUJD\n", out, sizeof out) == -1);
    check("b64 url-safe alphabet rejected", record_b64_decode("QU-D", out, sizeof out) == -1);
    check("b64 capacity respected", record_b64_decode("QUJD", out, 2) == -1);
}

static void test_b64_roundtrip(void) {
    unsigned char raw[96], back[96];
    char enc[160];
    for (size_t n = 1; n <= sizeof raw; ++n) {
        for (size_t i = 0; i < n; ++i) raw[i] = (unsigned char)(i * 7 + n);
        b64_encode_ref(raw, n, enc);
        int got = record_b64_decode(enc, back, sizeof back);
        if (got != (int)n || memcmp(raw, back, n) != 0) {
            printf("FAIL  b64 roundtrip n=%u (got %d)\n", (unsigned)n, got);
            ++failures;
            ++checks;
            return;
        }
    }
    ++checks;
    printf("PASS  b64 roundtrip n=1..%u\n", (unsigned)sizeof raw);
}

static void test_device_id(void) {
    check("id ok simple", record_device_id_valid("dev-01"));
    check("id ok full charset", record_device_id_valid("aZ0._-"));
    check("id ok 32 chars", record_device_id_valid("0123456789abcdef0123456789abcdef"));
    check("id empty rejected", !record_device_id_valid(""));
    check("id 33 chars rejected", !record_device_id_valid("0123456789abcdef0123456789abcdefg"));
    check("id space rejected", !record_device_id_valid("a b"));
    check("id quote rejected", !record_device_id_valid("a\"b"));
    check("id backslash rejected", !record_device_id_valid("a\\b"));
    check("id newline rejected", !record_device_id_valid("a\nb"));
    check("id colon rejected", !record_device_id_valid("a:b"));
    check("id non-ascii rejected", !record_device_id_valid("\xE8\xAE\xBE\xE5\xA4\x87"));
    check("id NULL rejected", !record_device_id_valid(NULL));
}

static void test_record(void) {
    unsigned char pk[32], sk[64], payload[RECORD_MAX + 8];
    unsigned char pk2[32], sk2[64];
    char id[RECORD_MAX_DEVICE_ID + 1];
    for (int i = 0; i < 32; ++i) pk[i] = (unsigned char)(0x10 + i);
    for (int i = 0; i < 64; ++i) sk[i] = (unsigned char)(0xA0 + i);

    check("RECORD_MAX is 130", RECORD_MAX == 130);
    check("RECORD_FIXED_LEN is 98", RECORD_FIXED_LEN == 98);

    size_t n = record_encode(payload, sizeof payload, pk, sk, "dev-01");
    check("encode length = 98 + id", n == RECORD_FIXED_LEN + 6);
    check("encode version byte", payload[0] == RECORD_FORMAT_VERSION);
    check("encode id length byte", payload[1] == 6);
    check("decode roundtrip", record_decode(payload, n, pk2, sk2, id, sizeof id));
    check("decode pk matches", memcmp(pk, pk2, 32) == 0);
    check("decode sk matches", memcmp(sk, sk2, 64) == 0);
    check("decode id matches", strcmp(id, "dev-01") == 0);

    // longest allowed device id
    char id32[33];
    memset(id32, 'x', 32);
    id32[32] = '\0';
    n = record_encode(payload, sizeof payload, pk, sk, id32);
    check("encode 32 char id -> 130", n == RECORD_MAX);
    check("decode 32 char id", record_decode(payload, n, NULL, NULL, id, sizeof id) && strcmp(id, id32) == 0);

    // rejections
    check("encode rejects bad id", record_encode(payload, sizeof payload, pk, sk, "a b") == 0);
    check("encode rejects small cap", record_encode(payload, 40, pk, sk, "dev-01") == 0);
    check("decode rejects short buffer", !record_decode(payload, RECORD_FIXED_LEN - 1, NULL, NULL, NULL, 0));
    check("decode rejects long buffer", !record_decode(payload, RECORD_MAX + 1, NULL, NULL, NULL, 0));
    check("decode rejects len mismatch", !record_decode(payload, n - 1, NULL, NULL, NULL, 0));

    unsigned char bad[RECORD_MAX];
    memcpy(bad, payload, n);
    bad[0] = 2;
    check("decode rejects bad version", !record_decode(bad, n, NULL, NULL, NULL, 0));
    memcpy(bad, payload, n);
    bad[1] = 0;
    check("decode rejects zero id length", !record_decode(bad, n, NULL, NULL, NULL, 0));
    memcpy(bad, payload, n);
    bad[1] = 33;
    check("decode rejects id length 33", !record_decode(bad, n, NULL, NULL, NULL, 0));
    memcpy(bad, payload, n);
    bad[RECORD_FIXED_LEN] = ' '; // invalid character inside the id
    check("decode rejects bad id charset", !record_decode(bad, n, NULL, NULL, NULL, 0));
    check("decode rejects tiny id buffer", record_decode(payload, n, NULL, NULL, id, 3) == false);
}

int main(void) {
    test_b64_vectors();
    test_b64_roundtrip();
    test_device_id();
    test_record();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
