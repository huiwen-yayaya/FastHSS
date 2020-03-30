/*
 *  Copyright 2020 Di Franco Francesco <francescodifranco90@gmail.com>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <lib-mesg.h>
#include <lib-misc.h>
#include <lib-2k-prs.h>
#include <lib-timing.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>

#define prng_sec_level 128
#define DEFAULT_MOD_BITS 4096
#define BENCHMARK_ITERATIONS 10

#define sampling_time 4 /* secondi */
#define max_samples (sampling_time * 50)

gmp_randstate_t prng;

void run_benchmark(){
    set_messaging_level(msg_verbose);
    int k;
    int k_len [] = { 96, 112, 128, 256, 512, 1024 };
    prs_keys_t keys;
    prs_ciphertext_t ciphertext;
    prs_plaintext_t plaintext, dec_plaintext;
    // generate_keys_v1

    stats_t timing_keys1, timing_keys2, timing_enc1, timing_enc2, timing_dec1, timing_dec2;
    printf("Starting benchmark\n");


    for(k = 0; k < 6; k++) {
        printf("K = %d\n", k_len[k]);
        perform_timestamp_sampling_period(
                timing_keys1, sampling_time, max_samples, tu_millis,
                {
                    prs_generate_keys_v1(keys, k_len[k], k_len[k] * 4, prng);
                },
                {});
        pmesg_stats(msg_verbose, "keys v1", timing_keys1);

        //generate_keys_v2
        perform_timestamp_sampling_period(
                timing_keys2, sampling_time, max_samples, tu_millis,
                {
                    prs_generate_keys_v2(keys, k_len[k], k_len[k] * 4, prng);
                },
                {});
        pmesg_stats(msg_verbose, "keys v2", timing_keys2);

        // generating random message
        prs_plaintext_init(plaintext);
        prs_plaintext_init(dec_plaintext);
        prs_ciphertext_init(ciphertext);
        mpz_urandomb(plaintext->m, prng, keys->k);

        //prs_enc
        perform_timestamp_sampling_period(
                timing_enc1, sampling_time, max_samples, tu_millis,
                {
                    prs_encrypt_v1(ciphertext, keys, plaintext, prng);
                },
                {});
        pmesg_stats(msg_verbose, "enc v1", timing_enc1);

        perform_timestamp_sampling_period(
                timing_enc2, sampling_time, max_samples, tu_millis,
                {
                    prs_encrypt_v2(ciphertext, keys, plaintext, prng, k_len[k]);
                },
                {});
        pmesg_stats(msg_verbose, "enc v2", timing_enc2);


        //decrypt_v1
        perform_timestamp_sampling_period(
                timing_dec1, sampling_time, max_samples, tu_millis,
                {
                    prs_decrypt_v1(dec_plaintext, keys, ciphertext);
                },
                {});
        pmesg_stats(msg_verbose, "dec1", timing_dec1);

        //decrypt_v2
        perform_timestamp_sampling_period(
                timing_dec2, sampling_time, max_samples, tu_millis,
                {
                    prs_decrypt_v2(dec_plaintext, keys, ciphertext);
                },
                {});
        pmesg_stats(msg_verbose, "dec2", timing_dec2);
    }
    prs_plaintext_clear(plaintext);
    prs_plaintext_clear(dec_plaintext);
    prs_ciphertext_clear(ciphertext);
}
void test_prs_gen_keys_v1(prs_keys_t keys){
    mpz_t gcd, mod;
    mpz_inits(gcd, mod, NULL);
    long k = DEFAULT_MOD_BITS / 4; /* default: max message size 1024 bit */
    printf("Starting test: prs_generate_keys_v1\n");

    prs_generate_keys_v1(keys, k, DEFAULT_MOD_BITS, prng);


    assert(mpz_sizeinbase(keys->p, 2) >= (DEFAULT_MOD_BITS >> 1));
    assert(mpz_sizeinbase(keys->q, 2) >= DEFAULT_MOD_BITS - (DEFAULT_MOD_BITS >> 1));
    assert(mpz_probab_prime_p(keys->p, PRS_MR_ITERATIONS));
    assert(mpz_probab_prime_p(keys->q, PRS_MR_ITERATIONS));
    gmp_printf ("p: %Zd\n", keys->p);
    gmp_printf ("q: %Zd\n", keys->q);
    gmp_printf ("n: %Zd\n", keys->n);
    gmp_printf ("y: %Zd\n", keys->y);
    printf ("k: %d\n", keys->k);
    gmp_printf ("2^k: %Zd\n", keys->k_2);

    mpz_mod(mod, keys->p, keys->k_2);
    assert(mpz_get_ui(mod) == 1);
    gmp_printf("p = %Zd mod 2^k ==> ok\n", mod);
    mpz_gcd(gcd, keys->y, keys->n);
    assert(mpz_cmp_ui(gcd, 1L) == 0);
    gmp_printf("gcd(y, n) = %Zd ==> ok\n", mod);

    printf("Test passed!\n\n");

    mpz_clears(gcd, mod, NULL);

}
void test_prs_gen_keys_v2(prs_keys_t keys){
    mpz_t gcd, mod;
    mpz_inits(gcd, mod, NULL);
    long k = DEFAULT_MOD_BITS / 4; /* default: max message size 1024 bit */
    printf("Starting test prs_generate_keys_v2\n");

    prs_generate_keys_v2(keys, k, DEFAULT_MOD_BITS, prng);


    assert(mpz_sizeinbase(keys->p, 2) >= (DEFAULT_MOD_BITS >> 1));
    assert(mpz_sizeinbase(keys->q, 2) >= DEFAULT_MOD_BITS - (DEFAULT_MOD_BITS >> 1));
    assert(mpz_probab_prime_p(keys->p, PRS_MR_ITERATIONS));
    assert(mpz_probab_prime_p(keys->q, PRS_MR_ITERATIONS));
    gmp_printf ("p: %Zd\n", keys->p);
    gmp_printf ("q: %Zd\n", keys->q);
    gmp_printf ("n: %Zd\n", keys->n);
    gmp_printf ("y: %Zd\n", keys->y);
    printf ("k: %d\n", keys->k);
    gmp_printf ("2^k: %Zd\n", keys->k_2);

    mpz_mod(mod, keys->p, keys->k_2);
    assert(mpz_get_ui(mod) == 1);
    gmp_printf("p = %Zd mod 2^k ==> ok\n", mod);
    mpz_gcd(gcd, keys->y, keys->n);
    assert(mpz_cmp_ui(gcd, 1L) == 0);
    gmp_printf("gcd(y, n) = %Zd ==> ok\n", mod);
    mpz_mod_ui(mod, keys->q, 4);
    assert(mpz_cmp_ui(mod, 3L) == 0);
    gmp_printf("q = %Zd mod 4 ==> ok\n", mod);

    printf("Test passed!\n\n");

    mpz_clears(gcd, mod, NULL);

}
/**
 *
 * @param ciphertext target where to save enc result
 * @param keys prs keys
 * @param plaintext plaintext to encrypt
 */
void test_prs_enc_v1(prs_ciphertext_t ciphertext, prs_keys_t keys, prs_plaintext_t plaintext){
    elapsed_time_t time;
    printf("Starting prs_encrypt\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_encrypt_v1(ciphertext, keys, plaintext, prng);
    });
    printf_et("prs_encrypt - time elapsed: ", time, tu_millis, "\n");

}
void test_prs_enc_v2(prs_ciphertext_t ciphertext, prs_keys_t keys, prs_plaintext_t plaintext, unsigned int base_size){
    elapsed_time_t time;
    printf("Starting prs_encrypt\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_encrypt_v2(ciphertext, keys, plaintext, prng, base_size);
    });
    printf_et("prs_encrypt - time elapsed: ", time, tu_millis, "\n");

}

/**
 *
 * @param plaintext taget plaintext where to save dec result
 * @param keys prs keys
 * @param ciphertext chipertext to decrypt
 */
void test_prs_dec_v1(prs_plaintext_t plaintext, prs_keys_t keys, prs_ciphertext_t ciphertext){
    elapsed_time_t time;
    printf("Starting test: prs_decrypt_v1\n");
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_decrypt_v1(plaintext, keys, ciphertext);
    });
    printf_et("prs_decrypt - time elapsed: ", time, tu_millis, "\n");

}
void test_prs_dec_v2(prs_plaintext_t plaintext, prs_keys_t keys, prs_ciphertext_t ciphertext){
    elapsed_time_t time;
    printf("Starting test prs_decrypt_v2\n");
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        prs_decrypt_v2(plaintext, keys, ciphertext);
    });
    printf_et("prs_decrypt - time elapsed: ", time, tu_millis, "\n");

}

int main(int argc, char *argv[]) {
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    set_messaging_level(msg_very_verbose);

    prs_keys_t keys_v1, keys_v2;
    prs_plaintext_t plaintext, dec_plaintext_v1, dec_plaintext_v2;
    prs_plaintext_init(plaintext);
    prs_plaintext_init(dec_plaintext_v1);
    prs_plaintext_init(dec_plaintext_v2);

    prs_ciphertext_t ciphertext_v1, ciphertext_v2;
    prs_ciphertext_init(ciphertext_v1);
    prs_ciphertext_init(ciphertext_v2);

    printf("Launching tests with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);
    printf("Calibrating timing tools...\n\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    //benchmark

    run_benchmark();

    // test
    // prs_generate_keys
    test_prs_gen_keys_v1(keys_v1);
    test_prs_gen_keys_v2(keys_v2);

    // test enc
    // genarting random msg
    do {
        mpz_urandomb(plaintext->m, prng, keys_v1->k);
    } while (mpz_sizeinbase(plaintext->m, 2) < keys_v1->k);

    // prs_encrypt
    test_prs_enc_v1(ciphertext_v1, keys_v1, plaintext);
    test_prs_enc_v2(ciphertext_v2, keys_v2, plaintext, 512);

    // test decrypt
    gmp_printf("c_v1: %Zd\n\n", ciphertext_v1->c);
    gmp_printf("c_v2: %Zd\n\n", ciphertext_v2->c);

    test_prs_dec_v1(dec_plaintext_v1, keys_v1, ciphertext_v1);
    gmp_printf("m1_v1: %Zd\n\n", plaintext->m);
    gmp_printf("m2_v2: %Zd\n\n", dec_plaintext_v1->m);
    assert(mpz_cmp(plaintext->m, dec_plaintext_v1->m) == 0);

    test_prs_dec_v2(dec_plaintext_v2, keys_v2, ciphertext_v2);
    gmp_printf("m1_v2: %Zd\n\n", plaintext->m);
    gmp_printf("m2_v2: %Zd\n\n", dec_plaintext_v2->m);
    assert(mpz_cmp(plaintext->m, dec_plaintext_v2->m) == 0);


    printf("All done!!\n");
    prs_plaintext_clear(plaintext);
    prs_plaintext_clear(dec_plaintext_v1);
    prs_plaintext_clear(dec_plaintext_v2);
    prs_ciphertext_clear(ciphertext_v1);
    prs_ciphertext_clear(ciphertext_v2);
    gmp_randclear(prng);

    return 0;
}


