//
// Created by Francesco Di Franco on 08/11/19.
//



#include <lib-mesg.h>
#include <lib-misc.h>
#include <lib-2k-prs.h>
#include <lib-timing.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>

#define prng_sec_level 128
#define DEFAULT_MOD_BITS 4096

gmp_randstate_t prng;

void test_prs_gen_keys(prs_keys_t keys){

    elapsed_time_t time;
    mpz_t gcd_y_n, mod;
    mpz_inits(gcd_y_n, mod, NULL);
    long k = DEFAULT_MOD_BITS / 4; /* default: max message size 1024 bit */
    printf("Starting prs_generate_keys\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_generate_keys(keys, k, DEFAULT_MOD_BITS, prng);
    });

    printf_et("prs_generate_keys - time elapsed: ", time, tu_millis, "\n");

    assert(mpz_sizeinbase(keys->p, 2) >= (DEFAULT_MOD_BITS >> 1));
    assert(mpz_sizeinbase(keys->q, 2) >= DEFAULT_MOD_BITS - (DEFAULT_MOD_BITS >> 1));
    assert(mpz_probab_prime_p(keys->p, PRS_MR_ITERATIONS));
    assert(mpz_probab_prime_p(keys->q, PRS_MR_ITERATIONS));
    gmp_printf ("p: %Zd\n", keys->p);
    gmp_printf ("q: %Zd\n", keys->q);
    gmp_printf ("n: %Zd\n", keys->n);
    gmp_printf ("y: %Zd\n", keys->y);
    gmp_printf ("k: %Zd\n", keys->k);
    gmp_printf ("2^k: %Zd\n", keys->k_2);

    mpz_mod(mod, keys->p, keys->k_2);
    assert(mpz_get_ui(mod) == 1);
    gmp_printf("p = %Zd mod 2^k ==> ok\n", mod);
    mpz_gcd(gcd_y_n, keys->y, keys->n);
    assert(mpz_cmp_ui(gcd_y_n, 1L) == 0);
    gmp_printf("gcd(y, n) = %Zd\n", mod);

    printf("Test passed!\n\n");

    mpz_clears(gcd_y_n, mod, NULL);

}
/**
 *
 * @param ciphertext target where to save enc result
 * @param keys prs keys
 * @param plaintext plaintext to encrypt
 */
void test_prs_enc(prs_ciphertext_t ciphertext, prs_keys_t keys, prs_plaintext_t plaintext){
    elapsed_time_t time;
    printf("Starting prs_encrypt\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_encrypt(ciphertext, keys, plaintext, prng);
    });
    printf_et("prs_encrypt - time elapsed: ", time, tu_millis, "\n");

}

/**
 *
 * @param plaintext taget plaintext where to save dec result
 * @param keys prs keys
 * @param ciphertext chipertext to decrypt
 */
void test_prs_dec(prs_plaintext_t plaintext, prs_keys_t keys, prs_ciphertext_t ciphertext){
    elapsed_time_t time;
    printf("Starting prs_decrypt\n");
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_decrypt(plaintext, keys, ciphertext);
    });
    printf_et("prs_decrypt - time elapsed: ", time, tu_millis, "\n");

}

int main(int argc, char *argv[]) {
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    set_messaging_level(msg_very_verbose);

    prs_keys_t keys;
    prs_plaintext_t plaintext, dec_plaintext;
    prs_plaintext_init(plaintext);
    prs_plaintext_init(dec_plaintext);

    prs_ciphertext_t ciphertext;
    prs_ciphertext_init(ciphertext);

    printf("Launching tests with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);
    printf("Calibrating timing tools...\n\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    // test
    // prs_generate_keys
    test_prs_gen_keys(keys);

    // test enc
    // genarting random msg
    do {
        mpz_urandomb(plaintext->m, prng, DEFAULT_MOD_BITS / 4);
    } while (mpz_sizeinbase(plaintext->m, 2) < (DEFAULT_MOD_BITS / 4));

    // prs_encrypt
    test_prs_enc(ciphertext, keys, plaintext);

    // test decrypt
    gmp_printf("c: %Zd\n\n", ciphertext->c);

    test_prs_dec(dec_plaintext, keys, ciphertext);

    gmp_printf("m1: %Zd\n\n", plaintext->m);
    gmp_printf("m2: %Zd\n\n", dec_plaintext->m);


    assert(mpz_cmp(plaintext->m, dec_plaintext->m) == 0);
    printf("\n\nAll done!!");
    prs_plaintext_clear(plaintext);
    prs_plaintext_clear(dec_plaintext);
    prs_ciphertext_clear(ciphertext);
    gmp_randclear(prng);

    return 0;
}


