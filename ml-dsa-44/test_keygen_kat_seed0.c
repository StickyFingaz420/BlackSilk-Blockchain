#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

int main() {
    uint8_t seed[32] = {0}; // All-zero seed
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(pk, sk, seed);
    if (ret != 0) {
        printf("Keypair generation failed: %d\n", ret);
        return 1;
    }

    printf("Seed: ");
    for (size_t i = 0; i < sizeof(seed); i++) printf("%02x", seed[i]);
    printf("\n");

    printf("Public Key: ");
    for (size_t i = 0; i < PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", pk[i]);
    printf("\n");

    printf("Secret Key: ");
    for (size_t i = 0; i < PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES; i++) printf("%02x", sk[i]);
    printf("\n");

    return 0;
}
