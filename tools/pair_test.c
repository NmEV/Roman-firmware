// Host regression test for the key pair check in keystore.c.
//
//   gcc -std=c11 -Wall -Wextra -I.. pair_test.c ../tweetnacl.c -o pair_test && ./pair_test
//
// It mirrors the buffer layout of keystore.c's pair_works() and guards it with a
// canary, because the original crash was a stack overwrite: crypto_sign_open()
// was handed a buffer sized for the plaintext (22 bytes) while it copies the
// whole signed message (85 bytes) into it first. The build time _Static_assert
// in keystore.c is the real guard for the firmware; this test proves the round
// trip works with those sizes and that a mismatch is still rejected.

#include <stdio.h>
#include <string.h>

#include "tweetnacl.h"

// deterministic stub: tweetnacl only needs some bytes for the key pair
void randombytes(unsigned char *out, unsigned long long outlen) {
    for (unsigned long long i = 0; i < outlen; ++i) {
        out[i] = (unsigned char)(i * 7 + 1);
    }
}

static const char probe[] = "roman-provision-check";

// Same sizes as keystore.c, with a canary immediately after the output buffer.
typedef struct {
    unsigned char out[sizeof(probe) + 64];
    unsigned char canary[32];
} outbuf_t;

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

// Exactly the sequence pair_works() runs.
static int pair_ok(const unsigned char pk[32], const unsigned char sk[64], outbuf_t *b) {
    static unsigned char signed_msg[sizeof(probe) + 64];
    unsigned long long signed_len = 0;
    unsigned long long recovered_len = 0;

    _Static_assert(sizeof(b->out) >= sizeof(probe) - 1 + 64,
                   "output buffer must hold the whole signed message");

    memset(b->canary, 0xAB, sizeof(b->canary));
    if (crypto_sign(signed_msg, &signed_len, (const unsigned char *)probe,
                    sizeof(probe) - 1, sk) != 0) {
        return -1;
    }
    if (crypto_sign_open(b->out, &recovered_len, signed_msg, signed_len, pk) != 0) {
        return 0;
    }
    return recovered_len == sizeof(probe) - 1 &&
           memcmp(b->out, probe, sizeof(probe) - 1) == 0;
}

static int canary_intact(const outbuf_t *b) {
    for (unsigned i = 0; i < sizeof(b->canary); ++i) {
        if (b->canary[i] != 0xAB) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    unsigned char pk[32], sk[64];
    if (crypto_sign_keypair(pk, sk) != 0) {
        printf("FAIL  crypto_sign_keypair\n");
        return 1;
    }

    outbuf_t b;
    check("generated key pair signs and verifies", pair_ok(pk, sk, &b) == 1);
    check("no overflow past the output buffer", canary_intact(&b));

    // A public key that does not belong to the secret key must be rejected.
    unsigned char wrong_pk[32];
    memcpy(wrong_pk, pk, sizeof(wrong_pk));
    wrong_pk[0] ^= 0x01;
    check("mismatched public key is rejected", pair_ok(wrong_pk, sk, &b) == 0);
    check("no overflow on the rejected path", canary_intact(&b));

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
