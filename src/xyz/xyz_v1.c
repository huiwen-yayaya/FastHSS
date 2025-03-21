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

#define base_size 512

gmp_randstate_t prng;

// Shamir secret sharing: split input into two shares
void shamir_secret_share(prs_plaintext_t input, prs_plaintext_t share1, prs_plaintext_t share2) {
    mpz_urandomm(share1->m, prng, input->m); // share1 is randomly generated
    mpz_sub(share2->m, input->m, share1->m); // share2 is input - share1
}

// Encrypt shares and distribute to servers
void distribute_shares(prs_plaintext_t x, prs_plaintext_t y, prs_plaintext_t z,
                       prs_keys_t keys, prs_ciphertext_t enc_x1, prs_ciphertext_t enc_y1, prs_ciphertext_t enc_z1,
                       prs_ciphertext_t enc_x2, prs_ciphertext_t enc_y2, prs_ciphertext_t enc_z2,
                       prs_plaintext_t x2, prs_plaintext_t y2, prs_plaintext_t z2,
                       prs_plaintext_t x1, prs_plaintext_t y1, prs_plaintext_t z1) {
    // Generate secret shares
    shamir_secret_share(x, x1, x2);
    shamir_secret_share(y, y1, y2);
    shamir_secret_share(z, z1, z2);

    // Homomorphic encryption of shares (using versioned functions)
    prs_encrypt_v1(enc_x1, keys, x1, prng);
    prs_encrypt_v1(enc_y1, keys, y1, prng);
    prs_encrypt_v1(enc_z1, keys, z1, prng);

    prs_encrypt_v1(enc_x2, keys, x2, prng);
    prs_encrypt_v1(enc_y2, keys, y2, prng);
    prs_encrypt_v1(enc_z2, keys, z2, prng);
}

void cipher_eval(prs_plaintext_t a, prs_plaintext_t b, prs_ciphertext_t e, prs_ciphertext_t res, prs_keys_t keys) {
    prs_ciphertext_t t;
    prs_ciphertext_init(t);

    mpz_mul(t->c, a->m, b->m);
    mpz_mod(t->c, t->c, keys->k_2);

    mpz_powm(t->c, e->c, t->c, keys->n);

    mpz_mul(res->c, res->c, t->c);
    mpz_mod(res->c, res->c, keys->n);

    prs_ciphertext_clear(t);
}

void plain_eval(prs_plaintext_t a, prs_plaintext_t b, prs_plaintext_t c, prs_ciphertext_t res, prs_keys_t keys) {
    prs_plaintext_t t;
    prs_plaintext_init(t);

    mpz_mul(t->m, a->m, b->m);
    mpz_mod(t->m, t->m, keys->k_2);
    mpz_mul(t->m, t->m, c->m);
    mpz_mod(t->m, t->m, keys->k_2);

    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_encrypt_v1(ct, keys, t, prng);

    mpz_mul(res->c, res->c, ct->c);
    mpz_mod(res->c, res->c, keys->n);

    prs_plaintext_clear(t);
    prs_ciphertext_clear(ct);
}

// Function to decrypt the final result
void client_decrypt_result(prs_plaintext_t dec_res, prs_keys_t keys, prs_ciphertext_t s1, prs_ciphertext_t s2) {
    // Multiply s1 and s2, then take modulo n
    prs_ciphertext_t res;
    prs_ciphertext_init(res);
    mpz_mul(res->c, s1->c, s2->c);
    mpz_mod(res->c, res->c, keys->n);

    // Decrypt the result
    prs_decrypt_v1(dec_res, keys, res);

    // Free intermediate resources
    prs_ciphertext_clear(res);
}

// Function to perform direct computation of x * y * z
void direct_computation_result(mpz_t result, prs_plaintext_t x, prs_plaintext_t y, prs_plaintext_t z, prs_keys_t keys) {
    mpz_mul(result, x->m, y->m);
    mpz_mod(result, result, keys->k_2);
    mpz_mul(result, result, z->m);
    mpz_mod(result, result, keys->k_2);
    gmp_printf("Direct Computation Result (x * y * z): %Zd\n\n", result);
}

// Encrypt shares and distribute to servers with timing measurement
elapsed_time_t time_distribute_shares(prs_plaintext_t x, prs_plaintext_t y, prs_plaintext_t z,
                            prs_keys_t keys, prs_ciphertext_t enc_x1, prs_ciphertext_t enc_y1, prs_ciphertext_t enc_z1,
                            prs_ciphertext_t enc_x2, prs_ciphertext_t enc_y2, prs_ciphertext_t enc_z2,
                            prs_plaintext_t x2, prs_plaintext_t y2, prs_plaintext_t z2,
                            prs_plaintext_t x1, prs_plaintext_t y1, prs_plaintext_t z1) {
    elapsed_time_t time;
    printf("Starting distribute_shares\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        distribute_shares(x, y, z, keys, enc_x1, enc_y1, enc_z1, enc_x2, enc_y2, enc_z2, x2, y2, z2, x1, y1, z1);
    });

    return time;
    //printf_et("distribute_shares - time elapsed: ", time, tu_millis, "\n");
}

elapsed_time_t time_cipher_eval(prs_plaintext_t a, prs_plaintext_t b, prs_ciphertext_t e, prs_ciphertext_t res, prs_keys_t keys) {
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        cipher_eval(a, b, e, res, keys);
    });
    return time; 
    //printf_et("cipher_eval - time elapsed: ", time, tu_millis, "\n");
}

elapsed_time_t time_plain_eval(prs_plaintext_t a, prs_plaintext_t b, prs_plaintext_t c, prs_ciphertext_t res, prs_keys_t keys) {
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        plain_eval(a, b, c, res, keys);
    });
    return time; 
    //printf_et("plain_eval - time elapsed: ", time, tu_millis, "\n");
}

// Function to decrypt the final result with timing measurement
elapsed_time_t client_decrypt_with_time(prs_plaintext_t dec_res, prs_keys_t keys, prs_ciphertext_t s1, prs_ciphertext_t s2) {
    elapsed_time_t time;
    printf("Starting decoding\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        // Step 1: Multiply s1 and s2, then take modulo n
        prs_ciphertext_t res;
        prs_ciphertext_init(res);
        mpz_mul(res->c, s1->c, s2->c);
        mpz_mod(res->c, res->c, keys->n);

        // Step 2: Decrypt the result and store it in dec_res
        prs_decrypt_v1(dec_res, keys, res);

        // Free intermediate resources
        prs_ciphertext_clear(res);
    });

    return time; 
}

// Function to perform direct computation of x * y * z with timing measurement
elapsed_time_t direct_computation_with_time(mpz_t result, prs_plaintext_t x, prs_plaintext_t y, prs_plaintext_t z, prs_keys_t keys) {
    elapsed_time_t time;
    printf("Starting direct computation of x * y * z\n");

    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        direct_computation_result(result, x, y, z, keys);
    });

    return time; 
}

int main(int argc, char *argv[]) {
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    set_messaging_level(msg_very_verbose); // Level of detail of input

    prs_keys_t keys;
    prs_plaintext_t x, y, z, x1, x2, y1, y2, z1, z2;
    prs_plaintext_init(x);
    prs_plaintext_init(y);
    prs_plaintext_init(z);
    prs_plaintext_init(x1);
    prs_plaintext_init(x2);
    prs_plaintext_init(y1);
    prs_plaintext_init(y2);
    prs_plaintext_init(z1);
    prs_plaintext_init(z2);

    prs_ciphertext_t cx1, cx2, cy1, cy2, cz1, cz2;
    prs_ciphertext_init(cx1);
    prs_ciphertext_init(cx2);
    prs_ciphertext_init(cy1);
    prs_ciphertext_init(cy2);
    prs_ciphertext_init(cz1);
    prs_ciphertext_init(cz2);

    printf("Launching demo with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);

    printf("calibrating timing tools...\n\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead(); 

    printf("Starting key generation\n");
    //prs_generate_keys_v2(keys, DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS, prng);
    elapsed_time_t time_generate_keys;
    perform_oneshot_clock_cycles_sampling(time_generate_keys, tu_millis, {
        prs_generate_keys_v1(keys, DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS, prng);
    });
    gmp_printf("p: %Zd\n", keys->p);
    gmp_printf("q: %Zd\n", keys->q);
    gmp_printf("n: %Zd\n", keys->n);
    gmp_printf("y: %Zd\n", keys->y);
    printf("k: %d\n", keys->k);
    gmp_printf("2^k: %Zd\n\n", keys->k_2);

    // Randomly generate values for x, y, z
    mpz_urandomb(x->m, prng, keys->k);
    mpz_urandomb(y->m, prng, keys->k);
    mpz_urandomb(z->m, prng, keys->k);

    /*
    // Direct computation of x * y * z
    mpz_t expected_result;
    mpz_init(expected_result);
    mpz_mul(expected_result, x->m, y->m);
    mpz_mod(expected_result, expected_result, keys->k_2);
    mpz_mul(expected_result, expected_result, z->m);
    mpz_mod(expected_result, expected_result, keys->k_2);
    */
    // Direct computation of x * y * z with timing
    mpz_t expected_result;
    mpz_init(expected_result);
    elapsed_time_t computation_time = direct_computation_with_time(expected_result, x, y, z, keys);
    //printf_et("Direct computation time elapsed: ", computation_time, tu_millis, "\n");
    //gmp_printf("Direct Computation Result (x * y * z): %Zd\n\n", expected_result);


    // Distribute secret shares and encrypt parts of the shares
    //distribute_shares(x, y, z, keys, cx1, cy1, cz1, cx2, cy2, cz2, x2, y2, z2, x1, y1, z1);
    elapsed_time_t time_dis_shares = time_distribute_shares(x, y, z, keys, cx1, cy1, cz1, cx2, cy2, cz2, x2, y2, z2, x1, y1, z1);
    printf_et("distribute_shares time elapsed: ", time_dis_shares, tu_millis, "\n");

    gmp_printf("S1 gets: %Zd, %Zd, %Zd, %Zd, %Zd, %Zd\n", cx1->c, cy1->c, cz1->c, x2->m, y2->m, z2->m);
    gmp_printf("S2 gets: %Zd, %Zd, %Zd, %Zd, %Zd, %Zd\n\n", x1->m, y1->m, z1->m, cx2->c, cy2->c, cz2->c);

    // S1's evaluation
    printf("S1 starts evaluation!\n");
    prs_ciphertext_t s1;
    prs_ciphertext_init(s1);
    mpz_set_ui(s1->c, 1);
    //cipher_eval(y2, z2, cx1, s1, keys);
    //cipher_eval(x2, z2, cy1, s1, keys);
    //cipher_eval(x2, y2, cz1, s1, keys);
    //plain_eval(x2, y2, z2, s1, keys);

    elapsed_time_t time_s1_cx1 = time_cipher_eval(y2, z2, cx1, s1, keys);
    printf_et("S1 cipher_eval_cx1 time elapsed: ", time_s1_cx1, tu_millis, "\n");
    elapsed_time_t time_s1_cy1 = time_cipher_eval(x2, z2, cy1, s1, keys);
    printf_et("S1 cipher_eval_cy1 time elapsed: ", time_s1_cy1, tu_millis, "\n");
    elapsed_time_t time_s1_cz1 = time_cipher_eval(x2, y2, cz1, s1, keys);
    printf_et("S1 cipher_eval_cz1 time elapsed: ", time_s1_cz1, tu_millis, "\n");
    elapsed_time_t time_s1_p = time_plain_eval(x2, y2, z2, s1, keys);
    printf_et("S1 plain_eval time elapsed: ", time_s1_p, tu_millis, "\n");
    elapsed_time_t time_s1 = time_s1_cx1 + time_s1_cy1 + time_s1_cz1 + time_s1_p;
    printf_et("S1 total evaluation time elapsed: ", time_s1_p, tu_millis, "\n");

    gmp_printf("S1 outputs: %Zd\n\n", s1->c);

    // S2's evaluation
    printf("S2 starts evaluation!\n");
    prs_ciphertext_t s2;
    prs_ciphertext_init(s2);
    mpz_set_ui(s2->c, 1);
    //cipher_eval(y1, z1, cx2, s2, keys);
    //cipher_eval(x1, z1, cy2, s2, keys);
    //cipher_eval(x1, y1, cz2, s2, keys);
    //plain_eval(x1, y1, z1, s2, keys);

    elapsed_time_t time_s2_cx2 = time_cipher_eval(y1, z1, cx2, s2, keys);
    printf_et("S2 cipher_eval_cx2 time elapsed: ", time_s2_cx2, tu_millis, "\n");
    elapsed_time_t time_s2_cy2 = time_cipher_eval(x1, z1, cy2, s2, keys);
    printf_et("S2 cipher_eval_cy2 time elapsed: ", time_s2_cy2, tu_millis, "\n");
    elapsed_time_t time_s2_cz2 = time_cipher_eval(x1, y1, cz2, s2, keys);
    printf_et("S2 cipher_eval_cz2 time elapsed: ", time_s2_cz2, tu_millis, "\n");
    elapsed_time_t time_s2_p = time_plain_eval(x1, y1, z1, s2, keys);
    printf_et("S2 plain_eval time elapsed: ", time_s2_p, tu_millis, "\n");
    elapsed_time_t time_s2 = time_s2_cx2 + time_s2_cy2 + time_s2_cz2 + time_s2_p;
    printf_et("S2 total evaluation time elapsed: ", time_s2_p, tu_millis, "\n");

    gmp_printf("S2 outputs: %Zd\n\n", s2->c);

    /*
    // Client decrypts the final result
    printf("Starting decoding\n");
    prs_plaintext_t dec_res;
    prs_plaintext_init(dec_res);
    prs_ciphertext_t res;
    prs_ciphertext_init(res);
    mpz_mul(res->c, s1->c, s2->c);
    mpz_mod(res->c, res->c, keys->n);
    prs_decrypt_v1(dec_res, keys, res);
    */
    // Client decrypts the final result and measures time
    prs_plaintext_t dec_res;
    prs_plaintext_init(dec_res);
    elapsed_time_t decryption_time = client_decrypt_with_time(dec_res, keys, s1, s2);
    printf_et("Decryption time elapsed: ", decryption_time, tu_millis, "\n");

    gmp_printf("Original Result: %Zd\n\n", dec_res->m);    

    gmp_printf("Direct Computation Result (x * y * z): %Zd\n\n", expected_result);

    printf_et("time_generate_keys: ", time_generate_keys, tu_millis, "\n");
    printf_et("time_dis_shares: ", time_dis_shares, tu_millis, "\n");
    printf_et("time_s1: ", time_s1, tu_millis, "\n");
    printf_et("time_s2: ", time_s2, tu_millis, "\n");
    printf_et("decryption_time: ", decryption_time, tu_millis, "\n");
    printf_et("HSS time elapsed: ", time_generate_keys + time_dis_shares + time_s1 + time_s2 + decryption_time, tu_millis, "\n");
    printf_et("Direct computation time elapsed: ", computation_time, tu_millis, "\n");

    // Verify if the results match
    if (mpz_cmp(dec_res->m, expected_result) == 0) {
        printf("Verification Success: Computed result matches direct calculation!\n");
    } else {
        printf("Verification Failed: Computed result does NOT match direct calculation.\n");
    }

    // Free resources
    prs_plaintext_clear(x);
    prs_plaintext_clear(y);
    prs_plaintext_clear(z);
    prs_plaintext_clear(x1);
    prs_plaintext_clear(x2);
    prs_plaintext_clear(y1);
    prs_plaintext_clear(y2);
    prs_plaintext_clear(z1);
    prs_plaintext_clear(z2);
    prs_ciphertext_clear(cx1);
    prs_ciphertext_clear(cx2);
    prs_ciphertext_clear(cy1);
    prs_ciphertext_clear(cy2);
    prs_ciphertext_clear(cz1);
    prs_ciphertext_clear(cz2);
    prs_ciphertext_clear(s1);
    prs_ciphertext_clear(s2);
    //prs_ciphertext_clear(res);
    prs_plaintext_clear(dec_res);
    mpz_clear(expected_result);
    gmp_randclear(prng);

    return 0;
}


