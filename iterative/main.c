#include <stdio.h>
#include <string.h>
#include "api.h"
#include "kem.h"
#include "../FromNIST/rng.h"

int main() {

    printf("\n");
    printf("*********************\n");
    printf("**** BIKE KEM ****\n");
    printf("*********************\n");

    printf("\nParameters:\n");
    printf("Public Key Size: %ld bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("Secret Key Size: %ld bytes\n", CRYPTO_SECRETKEYBYTES);
    printf("Ciphertext Size: %ld bytes\n", CRYPTO_CIPHERTEXTBYTES);
    printf("Shared Secret Size: %ld bytes\n", CRYPTO_BYTES);
    printf("\n");

    // Define the variables for key pair, ciphertext, and shared secrets
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char key1[CRYPTO_BYTES];
    unsigned char key2[CRYPTO_BYTES];

    for (int i = 0; i < 1; i++) {
        crypto_kem_keypair(pk, sk);

        crypto_kem_enc(ct, key1, pk);
        
        crypto_kem_dec(key2, ct, sk);
    }
    
    // Output the shared secrets for comparison
    printf("\nShared Secret 1: ");
    for (int i = 0; i < CRYPTO_BYTES; ++i) printf("%02x", key1[i]);

    printf("\nShared Secret 2: ");
    for (int i = 0; i < CRYPTO_BYTES; ++i) printf("%02x", key2[i]);

    if (memcmp(key1, key2, CRYPTO_BYTES) == 0) {
        printf("\n\nShared secrets match!\n");
    } else {
        printf("\n\nShared secrets do not match!\n");
    }

    return 0;
}