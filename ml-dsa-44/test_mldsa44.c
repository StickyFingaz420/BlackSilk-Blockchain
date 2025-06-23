#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    printf("  ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n\n");
}

static void print_separator(const char* title) {
    printf("\n");
    printf("========================================\n");
    printf("%s\n", title);
    printf("========================================\n");
}

static int test_signature_with_keys(const uint8_t* pk, const uint8_t* sk, const char* test_name) {
    printf("\n--- Testing signature with %s ---\n", test_name);
    
    // Test message
    const char* test_msg = "Test message for ML-DSA-44";
    uint8_t message[64];
    size_t msg_len = strlen(test_msg);
    memcpy(message, test_msg, msg_len);
    
    printf("Message: \"%s\" (%zu bytes)\n", test_msg, msg_len);
    
    // Sign the message
    uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t sig_len;
    
    printf("Signing message...\n");
    int sign_ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(signature, &sig_len, message, msg_len, sk);
    if (sign_ret != 0) {
        printf("ERROR: Signing failed with code %d\n", sign_ret);
        return 1;
    }
    printf("✓ Message signed successfully (signature length: %zu bytes)\n", sig_len);
    
    // Print first 32 bytes of signature for verification
    printf("Signature (first 32 bytes): ");
    for (int i = 0; i < 32 && i < (int)sig_len; i++) {
        printf("%02x", signature[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("...\n");
    
    // Verify the signature
    printf("Verifying signature...\n");
    int verify_ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, sig_len, message, msg_len, pk);
    if (verify_ret == 0) {
        printf("✓ Signature verification successful\n");
    } else {
        printf("✗ Signature verification failed with code %d\n", verify_ret);
        return 1;
    }
    
    // Test with wrong message
    printf("Testing with modified message...\n");
    uint8_t wrong_message[64];
    memcpy(wrong_message, message, msg_len);
    wrong_message[0] ^= 0x01; // Flip one bit
    
    int wrong_verify_ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, sig_len, wrong_message, msg_len, pk);
    if (wrong_verify_ret != 0) {
        printf("✓ Verification correctly rejected modified message\n");
    } else {
        printf("✗ ERROR: Verification should have failed for modified message!\n");
        return 1;
    }
    
    return 0;
}

int main() {
    printf("ML-DSA-44 Comprehensive Test Suite\n");
    printf("Algorithm: %s\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_ALGNAME);
    printf("Public Key Size: %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("Secret Key Size: %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("Signature Size: %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES);
    
    print_separator("STEP 1: Generate Random Keypair");
    
    uint8_t pk_random[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_random[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    printf("Generating random keypair...\n");
    int ret_random = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk_random, sk_random);
    if (ret_random != 0) {
        printf("ERROR: Random keypair generation failed with code %d\n", ret_random);
        return 1;
    }
    printf("✓ Random keypair generated successfully\n\n");
    
    // Print the keys
    print_hex("Random Public Key", pk_random, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Random Secret Key", sk_random, PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    
    // Test signature with random keys
    if (test_signature_with_keys(pk_random, sk_random, "random keys") != 0) {
        return 1;
    }
    
    print_separator("STEP 2: Test Deterministic Generation");
    
    // Fixed test seed (32 bytes)
    uint8_t seed[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    
    print_hex("Fixed Test Seed", seed, sizeof(seed));
    
    uint8_t pk1[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk1[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t pk2[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk2[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    // Generate first keypair from seed
    printf("Generating first keypair from fixed seed...\n");
    int ret1 = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(pk1, sk1, seed);
    if (ret1 != 0) {
        printf("ERROR: First keypair generation failed with code %d\n", ret1);
        return 1;
    }
    printf("✓ First keypair generated successfully\n\n");
    
    print_hex("First Public Key (from seed)", pk1, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("First Secret Key (from seed)", sk1, PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    
    // Test signature with first deterministic keys
    if (test_signature_with_keys(pk1, sk1, "first deterministic keys") != 0) {
        return 1;
    }
    
    print_separator("STEP 3: Verify Deterministic Behavior");
    
    // Generate second keypair from same seed
    printf("Generating second keypair from same seed...\n");
    int ret2 = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(pk2, sk2, seed);
    if (ret2 != 0) {
        printf("ERROR: Second keypair generation failed with code %d\n", ret2);
        return 1;
    }
    printf("✓ Second keypair generated successfully\n\n");
    
    print_hex("Second Public Key (from seed)", pk2, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    print_hex("Second Secret Key (from seed)", sk2, PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    
    // Compare public keys
    printf("Comparing public keys...\n");
    if (memcmp(pk1, pk2, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES) == 0) {
        printf("✓ Public keys are IDENTICAL (deterministic generation confirmed)\n");
    } else {
        printf("✗ ERROR: Public keys DIFFER (deterministic generation failed!)\n");
        return 1;
    }
    
    // Compare secret keys
    printf("Comparing secret keys...\n");
    if (memcmp(sk1, sk2, PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES) == 0) {
        printf("✓ Secret keys are IDENTICAL (deterministic generation confirmed)\n");
    } else {
        printf("✗ ERROR: Secret keys DIFFER (deterministic generation failed!)\n");
        return 1;
    }
    
    // Test signature with second deterministic keys
    if (test_signature_with_keys(pk2, sk2, "second deterministic keys") != 0) {
        return 1;
    }
    
    print_separator("STEP 4: Cross-Verification Test");
    
    // Test that first key can verify signature made with second key (they should be identical)
    printf("Testing cross-verification between deterministic keypairs...\n");
    
    const char* cross_test_msg = "Cross-verification test message";
    uint8_t cross_message[64];
    size_t cross_msg_len = strlen(cross_test_msg);
    memcpy(cross_message, cross_test_msg, cross_msg_len);
    
    uint8_t cross_signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t cross_sig_len;
    
    // Sign with second key
    int cross_sign_ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(cross_signature, &cross_sig_len, cross_message, cross_msg_len, sk2);
    if (cross_sign_ret != 0) {
        printf("ERROR: Cross-test signing failed with code %d\n", cross_sign_ret);
        return 1;
    }
    
    // Verify with first key
    int cross_verify_ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(cross_signature, cross_sig_len, cross_message, cross_msg_len, pk1);
    if (cross_verify_ret == 0) {
        printf("✓ Cross-verification successful (keys are truly identical)\n");
    } else {
        printf("✗ ERROR: Cross-verification failed (keys may not be identical)\n");
        return 1;
    }
    
    print_separator("TEST RESULTS SUMMARY");
    
    printf("✓ Random keypair generation: PASSED\n");
    printf("✓ Random keypair signature test: PASSED\n");
    printf("✓ Deterministic keypair generation: PASSED\n");
    printf("✓ Deterministic keypair consistency: PASSED\n");
    printf("✓ Signature generation and verification: PASSED\n");
    printf("✓ Invalid signature rejection: PASSED\n");
    printf("✓ Cross-verification test: PASSED\n");
    printf("\n🎉 ALL TESTS PASSED! ML-DSA-44 implementation is working correctly.\n");
    
    return 0;
}
