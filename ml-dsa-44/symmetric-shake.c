#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stdint.h>

void PQCLEAN_MLDSA44_CLEAN_dilithium_shake128_stream_init(shake128incctx *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    mldsa44_shake128_inc_init(state);
    mldsa44_shake128_inc_absorb(state, seed, SEEDBYTES);
    mldsa44_shake128_inc_absorb(state, t, 2);
    mldsa44_shake128_inc_finalize(state);
}

void PQCLEAN_MLDSA44_CLEAN_dilithium_shake256_stream_init(shake256incctx *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    mldsa44_shake256_inc_init(state);
    mldsa44_shake256_inc_absorb(state, seed, CRHBYTES);
    mldsa44_shake256_inc_absorb(state, t, 2);
    mldsa44_shake256_inc_finalize(state);
}
