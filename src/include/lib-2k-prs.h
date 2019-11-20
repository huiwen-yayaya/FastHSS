//
// Created by Francesco Di Franco on 08/11/19.
//

#ifndef PRS_H
#define PRS_H

#include <lib-mesg.h>
#include <assert.h>
#include <gmp.h>
#include <stdio.h>
#include <strings.h>

#define PRS_MR_ITERATIONS 12

typedef enum { prs_public_key_type, prs_secret_key_type } prs_key_type_t;

struct prs_keys_struct {
    prs_key_type_t type;
    unsigned int n_bits;
    unsigned int k;
    mpz_t n;
    mpz_t y;

    mpz_t k_2;
    mpz_t p;
    mpz_t q;
    mpz_t *d;
};
typedef struct prs_keys_struct prs_keys_t[1];
struct prs_plaintext_struct {
    mpz_t m;
};
typedef struct prs_plaintext_struct prs_plaintext_t[1];

struct prs_ciphertext_struct {
    mpz_t c;
};
typedef struct prs_ciphertext_struct prs_ciphertext_t[1];

void prs_generate_keys_v1(prs_keys_t keys, unsigned int k, unsigned int n_bits, gmp_randstate_t prng);
void prs_generate_keys_v2(prs_keys_t keys, unsigned int k, unsigned int n_bits, gmp_randstate_t prng);

void prs_plaintext_init(prs_plaintext_t plaintext);
void prs_plaintext_clear(prs_plaintext_t plaintext);
void prs_ciphertext_init(prs_ciphertext_t ciphertext);
void prs_ciphertext_clear(prs_ciphertext_t ciphertext);

void prs_encrypt(prs_ciphertext_t ciphertext, prs_keys_t keys, prs_plaintext_t plaintext, gmp_randstate_t prng);

void prs_decrypt_v1(prs_plaintext_t plaintext, prs_keys_t keys, prs_ciphertext_t ciphertext);
void prs_decrypt_v2(prs_plaintext_t plaintext, prs_keys_t keys, prs_ciphertext_t ciphertext);
#endif //PRS_H
