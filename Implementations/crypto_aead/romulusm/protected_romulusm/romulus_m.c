/**
 * Romulus-M ARMv7-M core functions (w/ 1st-order masking countermeasure).
 * 
 * @author      Alexandre Adomnicai
 *              alex.adomnicai@gmail.com
 * 
 * @date        March 2022
 */
#include "skinny128.h"
#include "romulus_m.h"

/**
 * Equivalent to 'memset(buf, 0x00, buflen)'.
 */
static void zeroize(uint8_t buf[], int buflen)
{
  int i;
  for(i = 0; i < buflen; i++)
    buf[i] = 0x00;
}

/**
 * Equivalent to 'memcpy(dest, src, srclen)'.
 */
static void copy(uint8_t dest[], const uint8_t src[], int srclen)
{
  int i;
  for(i = 0; i < srclen; i++)
    dest[i] = src[i];
}

/**
 * Internal helper to compute the final Additional Data (AD) domain.
 */
static uint8_t final_ad_domain (unsigned long long adlen, unsigned long long mlen) {
    uint8_t domain = 0;
    uint32_t leftover;
    //Determine which domain bits we need based on the length of the ad
    if (adlen == 0) {
        domain ^= 0x02;         // No message, so only 1 block with padding
    } else {
        leftover = (uint32_t)(adlen % (2 * BLOCKBYTES));
        if (leftover == 0) {    // Even or odd ad length?
            domain ^= 0x08;     // Even with a full double block at the end
        } else if (leftover < BLOCKBYTES) {
            domain ^= 0x02;     // Odd with a partial single block at the end
        } else if (leftover > BLOCKBYTES) {
            domain ^= 0x0A;     // Even with a partial double block at the end
        }
    }
    //Determine which domain bits we need based on the length of the message
    if (mlen == 0) {
        domain ^= 0x01;         // No message, so only 1 block with padding
    } else {
        leftover = (unsigned)(mlen % (2 * BLOCKBYTES));
        if (leftover == 0) {    // Even or odd message length?
            domain ^= 0x04;     // Even with a full double block at the end
        } else if (leftover < BLOCKBYTES) {
            domain ^= 0x01;     // Odd with a partial single block at the end
        } else if (leftover > BLOCKBYTES) {
            domain ^= 0x05;     // Even with a partial double block at the end
        }
    }
    return domain;
}

/**
 * Romulus-M initialization.
 * 
 * TK1 is set to 0x0100...00.
 * 
 * The internal state is normally set to 0x00...00 w/o masking. Therefore we
 * simply copy the mask value into it instead.
 */
void romulusm_init(uint8_t *state, uint8_t *state_m, uint8_t *tk1)
{
    tk1[0] = 0x01;
    zeroize(tk1+1, BLOCKBYTES-1);
    zeroize(state, BLOCKBYTES);
    zeroize(state_m, BLOCKBYTES);
}

/**
 * Romulus-M Additional Data (AD) processing.
 * 
 * At the end of the function, 'rtk' and 'rtk_m' are ready for use for message
 * processing. 
 */
void romulusm_process_ad(
    uint8_t *state, uint8_t* state_m,
	const uint8_t *ad, unsigned long long adlen,
    const unsigned char *m, unsigned long long mlen,
    uint8_t *rtk, uint8_t *rtk_m, uint8_t *tk1,
    const uint8_t *npub,
    const uint8_t *k, const uint8_t *k_m)
{   
    uint32_t tmp;
    uint8_t pad[BLOCKBYTES];
    uint8_t rtk1[BLOCKBYTES*8];
    uint8_t final_domain = 0x30 ^ final_ad_domain(adlen, mlen);
    
    SET_DOMAIN(tk1, 0x28);
    while (adlen > 2*BLOCKBYTES) {          // Process double blocks but the last
        UPDATE_CTR(tk1);
        XOR_BLOCK(state, state, ad);
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, ad + BLOCKBYTES, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
        UPDATE_CTR(tk1);
        ad += 2*BLOCKBYTES;
        adlen -= 2*BLOCKBYTES;
    }
    // Pad and process the left-over blocks 
    if (adlen == 2*BLOCKBYTES) {            // Left-over complete double block
        UPDATE_CTR(tk1);
        XOR_BLOCK(state, state, ad);
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, ad + BLOCKBYTES, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
        UPDATE_CTR(tk1);
    } else if (adlen > BLOCKBYTES) {        // Left-over partial double block
        adlen -= BLOCKBYTES;
        UPDATE_CTR(tk1);
        XOR_BLOCK(state, state, ad);
        copy(pad, ad + BLOCKBYTES, adlen);
        zeroize(pad + adlen, 15-adlen);
        pad[15] = adlen;                    // Padding
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, pad, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
        UPDATE_CTR(tk1);
    } else {
        SET_DOMAIN(tk1, 0x2C);
        UPDATE_CTR(tk1);
        if (adlen == BLOCKBYTES) {          // Left-over complete single block 
            XOR_BLOCK(state, state, ad);
        } else {                            // Left-over partial single block
            for(int i =0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;             // Padding
        }
        if (mlen >= BLOCKBYTES) {
            tk_schedule_123(rtk, rtk_m, rtk1, tk1, m, k, k_m);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            if (mlen > BLOCKBYTES)
                UPDATE_CTR(tk1);
            mlen -= BLOCKBYTES;
            m += BLOCKBYTES;
        } else {
            copy(pad, m, mlen);
            zeroize(pad + mlen, BLOCKBYTES-mlen-1);
            pad[15] = (uint8_t)mlen;             // Padding
            tk_schedule_123(rtk, rtk_m, rtk1, tk1, pad, k, k_m);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            mlen = 0;
        }
    }
    // Process all message double blocks except the last
    SET_DOMAIN(tk1, 0x2C);
    while (mlen > 32) {
        UPDATE_CTR(tk1);
        XOR_BLOCK(state, state, m);
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, m + BLOCKBYTES, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
        UPDATE_CTR(tk1);
        m += 2 * BLOCKBYTES;
        mlen -= 2 * BLOCKBYTES;
    }
    // Process the last message double block
    if (mlen == 2 * BLOCKBYTES) {             // Last message double block is full
        UPDATE_CTR(tk1);
        XOR_BLOCK(state, state, m);
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, m + BLOCKBYTES, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
    } else if (mlen > BLOCKBYTES) {         // Last message double block is partial
        mlen -= BLOCKBYTES;
        UPDATE_CTR(tk1);
        XOR_BLOCK(state, state, m);
        copy(pad, m + BLOCKBYTES, mlen);
        zeroize(pad + mlen, BLOCKBYTES-mlen-1);
        pad[15] = (uint8_t)mlen;                 // Padding
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, pad, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
    } else if (mlen == BLOCKBYTES) {        // Last message single block is full
        XOR_BLOCK(state, state, m);
    } else if (mlen > 0) {                  // Last message single block is partial
        for(int i =0; i < (int)mlen; i++)
            state[i] ^= m[i];
        state[15] ^= (uint8_t)mlen;              // Padding
    }
    // Process the last partial block
    SET_DOMAIN(tk1, final_domain);
    UPDATE_CTR(tk1);
    tk_schedule_123(rtk, rtk_m, rtk1, tk1, npub, k, k_m);
    skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
}

void romulusm_process_msg(
    uint8_t *out, const uint8_t *in, unsigned long long inlen,
    uint8_t *state, uint8_t *state_m,
    const uint8_t *rtk, const uint8_t *rtk_m, uint8_t *tk1,
    const int mode)
{
    uint32_t tmp;
    uint8_t tmp_blk[BLOCKBYTES];
    uint8_t rtk1[BLOCKBYTES*8];
    
    if (mode == ENCRYPT_MODE) {
        tk1[0] = 0x01;
        zeroize(tk1+1, KEYBYTES-1);
    }
    else { // if DECRYPT_MODE init state with the tag and mask with 'state_m'
        for(int i = 0; i < TAGBYTES; i++)
            state[i] =  in[inlen + i] ^ state_m[i];
    }
        
    if (inlen > 0) {
        SET_DOMAIN(tk1, 0x24);
        while (inlen > BLOCKBYTES) {
            tk_schedule_1(rtk1, tk1);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            if (mode == ENCRYPT_MODE)
                RHO(state, state_m, out, in, tmp_blk);
            else
                RHO_INV(state, state_m, in, out, tmp_blk);
            UPDATE_CTR(tk1);
            out += BLOCKBYTES;
            in += BLOCKBYTES;
            inlen -= BLOCKBYTES;
        }
        tk_schedule_1(rtk1, tk1);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
        for(int i = 0; i < (int)inlen; i++) {
            tmp = in[i];                     // Use of tmp variable in case c = m
            out[i] = in[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
            out[i] ^= (state_m[i] >> 1) ^ (state_m[i] & 0x80) ^ (state_m[i] << 7);
            state[i] ^= (uint8_t)tmp;
        }
        state[15] ^= (uint8_t)inlen;              // Padding
    }
}

/**
 * Romulus-M tag generation.
 * 
 * Unmasking is performed right before storing the tag in the output buffer
 * 'c'.
 */
void romulusm_generate_tag(uint8_t *c, uint8_t *state, uint8_t *state_m)
{
    uint32_t tmp;
    G(state, state);
    G(state_m, state_m);
    for(int i =0; i < TAGBYTES; i++)
        c[i] = state[i] ^ state_m[i];
}

/**
 * Romulus-M tag verification.
 * 
 * Unmasking is performed on-the-fly when accumulating into the temporary var
 * 'tmp'.
 * 
 * Returns non-zero value if verification fails.
 */
uint32_t romulusm_verify_tag(const uint8_t *tag, uint8_t *state, uint8_t *state_m)
{
    uint32_t tmp;
    G(state,state);
    G(state_m, state_m);
    tmp = 0;
    for(int i = 0; i < TAGBYTES; i++)
        tmp |= state[i] ^ state_m[i] ^ tag[i];
    return tmp;
}
