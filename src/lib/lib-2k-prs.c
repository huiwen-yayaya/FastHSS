//
// Created by Francesco Di Franco on 08/11/19.
//

#include <lib-2k-prs.h>

/**
 * Generate keys: Given a security parameter κ, KeyGen defines an integer k ≥ 1, randomly generates
 * primes p and q such that p ≡ 1 ( mod 2 k ) , and sets N = pq. It also picks a random y ∈ J N \ QR N .
 * The public and private keys are pk = {N, y, k} and sk = {p}, respectively.
 * @param keys target keys struct where save keys
 * @param k message size in bit
 * @param n_bits modulus bit size
 * @param prng state for random number generator
 */
void prs_generate_keys(prs_keys_t keys, unsigned int k, unsigned int n_bits, gmp_randstate_t prng){

    mpz_t tmp;
    unsigned int p_bits, q_bits;

    //pmesg(msg_verbose, "keys generation");

    assert(keys);
    assert(n_bits > 1);

    p_bits = n_bits >> 1;

    keys->n_bits = n_bits;

    mpz_inits(keys->p, keys->q, keys->y, keys->n, keys->k_2, NULL);
    mpz_init(tmp);

    keys->k = k;
    // 2^k
    mpz_ui_pow_ui(keys->k_2, 2L, k);

    do {
        mpz_urandomb(keys->p, prng, p_bits - k);
        mpz_mul_2exp(keys->p, keys->p, k);
        mpz_setbit(keys->p, 0L);
    }while(mpz_sizeinbase(keys->p, 2) < p_bits || !mpz_probab_prime_p(keys->p, PRS_MR_ITERATIONS));

    q_bits = mpz_sizeinbase(keys->p, 2);
    /* pick random prime q*/
    do {
        mpz_urandomb(keys->q, prng, p_bits - 2);
        mpz_mul_2exp(keys->q, keys->q, 2);
        mpz_setbit(keys->q, 0L);
        mpz_setbit(keys->q, 1L);
    }while (mpz_sizeinbase(keys->q, 2) < q_bits  || !mpz_probab_prime_p(keys->q, PRS_MR_ITERATIONS));

    /* n = p*q */
    mpz_mul(keys->n, keys->p, keys->q);

    /**
     * J = { a € Zn: J(a/n) = 1 }
     * J(a/n) = J(a/p) * J(a/q) if n == p*q
     * QRn = { a € Zn: J(a/p) = J(a/q) = 1 }
     *
     * to pick a random y in Jn/QRn
     * J(y/N) == 1 => [J(y/p) = -1 && J(y/q) =-1]
     *
     * J(y/p) is +1 if and only if [y^((p-1)/2^k)) = 1 mod p] -1 otherwise
     *
     * */

    do {
        mpz_urandomb(keys->y, prng, n_bits);
        mpz_gcd(tmp, keys->y, keys->n);
        if(mpz_cmp_ui(tmp, 1L) != 0){
            continue;
        }
    } while (mpz_jacobi(keys->y, keys->p) != -1 ||  mpz_jacobi(keys->y, keys->q) != -1);

    mpz_clear(tmp);

}
/**
 * Init plaintext struct
 * @param plaintext
 */
void prs_plaintext_init(prs_plaintext_t plaintext){
    assert(plaintext);
    mpz_init(plaintext->m);
}

/**
 * Clear plaintext struct
 * @param plaintext
 */
void prs_plaintext_clear(prs_plaintext_t plaintext){
    assert(plaintext);
    mpz_clear(plaintext->m);
}

/**
 * Init ciphertext struct
 * @param ciphertext
 */
void prs_ciphertext_init(prs_ciphertext_t ciphertext){
    assert(ciphertext);
    mpz_init(ciphertext->c);
}

/**
 * Clear ciphertext struct
 * @param ciphertext
 */
void prs_ciphertext_clear(prs_ciphertext_t ciphertext){
    assert(ciphertext);
    mpz_clear(ciphertext->c);
}

/**
 * Encrypt ( pk, m ) Let M = {0, 1}^k .
 * Let M = {0, 1}^k . To encrypt a message m ∈ M (seen as an integer in {0, . . . , 2^k − 1})
 * Encrypt picks a random x ∈ Zn* and returns the ciphertext c = y^m * x^2^k mod N
 * @param ciphertext
 * @param keys
 * @param plaintext
 * @param prng
 */
void prs_encrypt(prs_ciphertext_t ciphertext, prs_keys_t keys, prs_plaintext_t plaintext, gmp_randstate_t prng){
    mpz_t x, y_m;
    mpz_inits(x, y_m, NULL);
    mpz_urandomm(x, prng, keys->n);
    mpz_powm(y_m, keys->y, plaintext->m, keys->n);
    mpz_powm(x, x, keys->k_2, keys->n);
    mpz_mul(ciphertext->c, x, y_m);
    mpz_mod(ciphertext->c, ciphertext->c, keys->n);
}

/**
 * Decrypt(sk, c) Given c ∈ Zn* and the private key sk = {p}, the algorithm first computes
 * d = y ^ -( (p-1) / (2^k) ) mod p
 * and then recover plaintext m = ( m_k−1 , . . . , m_0 ) base 2
 *
 * m ← 0; B ← 1; D ← D
 * C ← c^((p−1)/(2 ^k)) mod p
 * for j = 1 to k − 1 do
 *    z ← C^(2^(k− j)) mod p
 *    if ( z , 1) then
 *      m ← m + B ; C ← C · D mod p
 *    B ← 2 B ; D ← D 2 mod p
 * end for
 * if ( C , 1) then m ← m + B
 * return m
 *
 * @param plaintext target plaintext
 * @param keys keys
 * @param ciphertext ciphertext to decrypt
 */
void prs_decrypt(prs_plaintext_t plaintext, prs_keys_t keys, prs_ciphertext_t ciphertext){
    int i=0;
    mpz_t m, c, b, d, z, p_m_1, p_m_1_k, k_j;
    mpz_inits(m, c, b, d, z, p_m_1, p_m_1_k, k_j, NULL);
    mpz_set_ui(m, 0);
    mpz_set_ui(b, 1L);

    mpz_sub_ui(p_m_1, keys->p, 1L);

    mpz_div_2exp(p_m_1_k, p_m_1, keys->k);

    mpz_powm(d, keys->y, p_m_1_k, keys->p);
    mpz_invert(d, d, keys->p);

    mpz_powm(c, ciphertext->c, p_m_1_k, keys->p);
    for(i = 1; i <= keys->k; i++){
        mpz_ui_pow_ui(k_j, 2L, keys->k - i);
        mpz_powm(z, c, k_j, keys->p);
        if(mpz_cmp_ui(z, 1) != 0){
            mpz_add(m, m, b);
            mpz_mul(c, c, d);
            mpz_mod(c, c, keys->p);
        }
        mpz_mul_2exp(b, b, 1);
        mpz_powm_ui(d, d, 2L, keys->p);
    }
    if(mpz_cmp_ui(c, 1L) != 0){
        mpz_add(m, m, b);
    }
    mpz_set(plaintext->m, m);
    mpz_clears(m, c, b, d, z, p_m_1, p_m_1_k, k_j, NULL);
}