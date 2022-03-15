/**
 * Romulus-M ARMv7-M implementation (w/ 1st-order masking countermeasure)
 * following the API defined in the Call for Protected Software Implementations
 * of Finalists in the NIST Lightweight Cryptography Standardization Process
 * by George Mason Univeristy: https://cryptography.gmu.edu/athena/LWC/Call_for
 * _Protected_Software_Implementations.pdf
 * 
 * @author      Alexandre Adomnicai
 *              alex.adomnicai@gmail.com
 * 
 * @date        March 2022
 */
#include "romulus_m.h"
#include "randombytes.h"
#include "crypto_aead_shared.h"

/**
 * Wrapper for compliance with the API defined in the call for protected
 * implementations from GMU.
 * 
 * Converts an array with 4 mask_*_uint32_t element 2 16-byte byte arrays
 * (NUM_SHARES = 2).
 * The first and second output arrays contain the first and second shares in a
 * byte-wise representation, respectively.
 * 
 * Useful to pass the 16-byte block to mask the internal state and the 16-byte
 * key share as inputs to the Romulus functions.
 */
static void shares_to_bytearr_2(
    uint8_t bytearr_0[],
    uint8_t bytearr_1[],
    const mask_key_uint32_t *ks)
{
    int i;
    // pack the first shares into bytearr_0
    for(i = 0; i < BLOCKBYTES/4; i++) {
        bytearr_0[i*4 + 0] = (uint8_t)((ks[i].shares[0] >> 0)  & 0xff);
        bytearr_0[i*4 + 1] = (uint8_t)((ks[i].shares[0] >> 8)  & 0xff);
        bytearr_0[i*4 + 2] = (uint8_t)((ks[i].shares[0] >> 16) & 0xff);
        bytearr_0[i*4 + 3] = (uint8_t)((ks[i].shares[0] >> 24) & 0xff);
    }
    // pack the second shares into bytearr_1
    // use a distinct loop to avoid potential HD-based leakages
    for(i = 0; i < BLOCKBYTES/4; i++) {
        bytearr_1[i*4 + 0] = (uint8_t)((ks[i].shares[1] >> 0)  & 0xff);
        bytearr_1[i*4 + 1] = (uint8_t)((ks[i].shares[1] >> 8)  & 0xff);
        bytearr_1[i*4 + 2] = (uint8_t)((ks[i].shares[1] >> 16) & 0xff);
        bytearr_1[i*4 + 3] = (uint8_t)((ks[i].shares[1] >> 24) & 0xff);
    }
}

/**
 * Same as 'shares_to_bytearr_2' but with no masking => only one output buffer.
 */
static void shares_to_bytearr(
    uint8_t bytearr[],
    const mask_m_uint32_t *ms, unsigned long long mlen)
{
    unsigned long long i, r;
    r = mlen % 4;
    for(i = 0; i < mlen/4; i++) {
        bytearr[i*4 + 0] = (uint8_t)((ms[i].shares[0] >> 0)  & 0xff);
        bytearr[i*4 + 1] = (uint8_t)((ms[i].shares[0] >> 8)  & 0xff);
        bytearr[i*4 + 2] = (uint8_t)((ms[i].shares[0] >> 16) & 0xff);
        bytearr[i*4 + 3] = (uint8_t)((ms[i].shares[0] >> 24) & 0xff);
    }
    for(i = 0; i < r; i++)
        bytearr[mlen - r + i] = (uint8_t)((ms[mlen/4].shares[0] >> 8*i)  & 0xff);
}

/**
 * Split the encryption key into two shares and pack the other inputs according
 * to the call for protected software implementations from GMU.
 */
void generate_shares_encrypt(
    const unsigned char *m, mask_m_uint32_t *ms, const unsigned long long mlen,
    const unsigned char *ad, mask_ad_uint32_t *ads , const unsigned long long adlen,
    const unsigned char *npub, mask_npub_uint32_t *npubs,
    const unsigned char *k, mask_key_uint32_t *ks)
{
    unsigned long long i, r;

    // msg is not split into shares, simple copy
    r = mlen % 4;
    for(i = 0; i < mlen/4; i++) {
        ms[i].shares[0]  = (uint32_t)(m[i*4 + 0] << 0);
        ms[i].shares[0] |= (uint32_t)(m[i*4 + 1] << 8);
        ms[i].shares[0] |= (uint32_t)(m[i*4 + 2] << 16);
        ms[i].shares[0] |= (uint32_t)(m[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        ms[mlen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            ms[mlen/4].shares[0] |= (uint32_t)(m[mlen - r + i] << 8*i);
    }

    // ad is not split into shares, simple copy
    r = adlen % 4;
    for(i = 0; i < adlen/4; i++) {
        ads[i].shares[0]  = (uint32_t)(ad[i*4 + 0] << 0);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 1] << 8);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 2] << 16);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        ads[adlen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            ads[adlen/4].shares[0] |= (uint32_t)(ad[adlen - r + i] << 8*i);
    }

    // npub is not split into shares, simple copy
    for(i = 0; i < BLOCKBYTES/4; i++) {
        npubs[i].shares[0]  = (uint32_t)(npub[i*4 + 0] << 0);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 1] << 8);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 2] << 16);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 3] << 24);
    }

    // encryption key is split into 2 shares (1st-order masking)
    randombytes((uint8_t *)(&(ks[0].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[1].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[2].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[3].shares[1])), 4);
    ks[0].shares[0] = ks[0].shares[1] ^ ((uint32_t *)k)[0];
    ks[1].shares[0] = ks[1].shares[1] ^ ((uint32_t *)k)[1];
    ks[2].shares[0] = ks[2].shares[1] ^ ((uint32_t *)k)[2];
    ks[3].shares[0] = ks[3].shares[1] ^ ((uint32_t *)k)[3];
}

/**
 * Split the encryption key into two shares and pack the other inputs according
 * to the call for protected software implementations from GMU.
 */
void generate_shares_decrypt(
    const unsigned char *c, mask_m_uint32_t *cs, const unsigned long long clen,
    const unsigned char *ad, mask_ad_uint32_t *ads , const unsigned long long adlen,
    const unsigned char *npub, mask_npub_uint32_t *npubs,
    const unsigned char *k, mask_key_uint32_t *ks)
{
    unsigned long long i, r;

    // msg is not split into shares, simple copy
    r = clen % 4;
    for(i = 0; i < clen/4; i++) {
        cs[i].shares[0]  = (uint32_t)(c[i*4 + 0] << 0);
        cs[i].shares[0] |= (uint32_t)(c[i*4 + 1] << 8);
        cs[i].shares[0] |= (uint32_t)(c[i*4 + 2] << 16);
        cs[i].shares[0] |= (uint32_t)(c[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        cs[clen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            cs[clen/4].shares[0] |= (uint32_t)(c[clen - r + i] << 8*i);
    }

    // ad is not split into shares, simple copy
    r = adlen % 4;
    for(i = 0; i < adlen/4; i++) {
        ads[i].shares[0]  = (uint32_t)(ad[i*4 + 0] << 0);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 1] << 8);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 2] << 16);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        ads[adlen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            ads[adlen/4].shares[0] |= (uint32_t)(ad[adlen - r + i] << 8*i);
    }

    // npub is not split into shares, simple copy
    for(i = 0; i < BLOCKBYTES/4; i++) {
        npubs[i].shares[0]  = (uint32_t)(npub[i*4 + 0] << 0);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 1] << 8);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 2] << 16);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 3] << 24);
    }

    // encryption key is split into 2 shares (1st-order masking)
    randombytes((uint8_t *)(&(ks[0].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[1].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[2].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[3].shares[1])), 4);
    ks[0].shares[0] = ks[0].shares[1] ^ ((uint32_t *)k)[0];
    ks[1].shares[0] = ks[1].shares[1] ^ ((uint32_t *)k)[1];
    ks[2].shares[0] = ks[2].shares[1] ^ ((uint32_t *)k)[2];
    ks[3].shares[0] = ks[3].shares[1] ^ ((uint32_t *)k)[3];
}

/**
 * Combine the shares into the output ciphertext buffer.
 */
void combine_shares_encrypt(
    const mask_c_uint32_t *cs, unsigned char *c, unsigned long long clen) {
    shares_to_bytearr(c, (mask_m_uint32_t *)cs, clen);
}

/**
 * Combine the shares into the output plaintext buffer.
 */
void combine_shares_decrypt(
    const mask_m_uint32_t *ms, unsigned char *m, unsigned long long mlen) {
    shares_to_bytearr(m, ms, mlen);
}

/**
 * Encryption and authentication using Romulus-M w/ 1st-order masking.
 */
int crypto_aead_encrypt_shared(
    mask_c_uint32_t* cs, unsigned long long *clen,
    const mask_m_uint32_t *ms, unsigned long long mlen,
    const mask_ad_uint32_t *ads, unsigned long long adlen,
    const mask_npub_uint32_t *npubs,
    const mask_key_uint32_t *ks)
{
    uint8_t state[BLOCKBYTES];                          // internal state (1st share)
    uint8_t state_m[BLOCKBYTES];                        // internal state (2nd share)
    uint8_t tk1[BLOCKBYTES];
    uint8_t rtk_23[BLOCKBYTES*SKINNY128_384_ROUNDS];    // round tweakeys (1st share)
    uint8_t rtk_3m[BLOCKBYTES*SKINNY128_384_ROUNDS];    // round tweakeys (2nd share)
    uint8_t k[TWEAKEYBYTES];
    uint8_t k_m[TWEAKEYBYTES];

    shares_to_bytearr_2(k, k_m, ks);

    *clen = mlen + TAGBYTES;
    romulusm_init(state, state_m, tk1);
    romulusm_process_ad(
        state, state_m,
        (uint8_t *)ads, adlen,
        (uint8_t *)ms, mlen,
        rtk_23, rtk_3m,
        tk1, (uint8_t *)npubs,
        k, k_m);
    romulusm_generate_tag((uint8_t *)cs + mlen, state, state_m);
    romulusm_process_msg(
        (uint8_t *)cs,
        (uint8_t *)ms, mlen,
        state, state_m,
        rtk_23, rtk_3m,
        tk1,
        ENCRYPT_MODE);
    return 0;
}

/**
 * Decryption and tag verification using Romulus-M w/ 1st-order masking.
 * 
 * If tag verification fails, return a non-zero value.
 */
int crypto_aead_decrypt_shared(
    mask_m_uint32_t* ms, unsigned long long *mlen,
    const mask_c_uint32_t *cs, unsigned long long clen,
    const mask_ad_uint32_t *ads, unsigned long long adlen,
    const mask_npub_uint32_t *npubs,
    const mask_key_uint32_t *ks)
{
    uint8_t state[BLOCKBYTES];                          // internal state (1st share)
    uint8_t state_m[BLOCKBYTES];                        // internal state (2nd share)
    uint8_t tk1[BLOCKBYTES];
    uint8_t rtk_23[BLOCKBYTES*SKINNY128_384_ROUNDS];    // round tweakeys (1st share)
    uint8_t rtk_3m[BLOCKBYTES*SKINNY128_384_ROUNDS];    // round tweakeys (2nd share)
    uint8_t k[TWEAKEYBYTES];
    uint8_t k_m[TWEAKEYBYTES];

    if (clen < TAGBYTES)
        return -1;

    shares_to_bytearr_2(k, k_m, ks);
    clen -= TAGBYTES;
    *mlen = clen;
    romulusm_init(state, state_m, tk1);
    // precompute tk2 ^ tk3 for message processing
    tk_schedule_23(rtk_23, rtk_3m, (uint8_t *)npubs, k, k_m);
    // message processing
    romulusm_process_msg((uint8_t *)ms,
        (uint8_t *)cs, clen,
        state, state_m,
        rtk_23, rtk_3m,
        tk1,
        DECRYPT_MODE);
    // additional data processing
    romulusm_init(state, state_m, tk1);
    romulusm_process_ad(
        state, state_m,
        (uint8_t *)ads, adlen,
        (uint8_t *)ms, clen,
        rtk_23, rtk_3m,
        tk1, (uint8_t *)npubs,
        k, k_m);
    return romulusm_verify_tag((uint8_t *)cs + *mlen, state, state_m);
}
