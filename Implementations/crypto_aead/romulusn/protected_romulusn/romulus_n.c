/**
 * Romulus-N ARMv7-M core functions (w/ 1st-order masking countermeasure).
 * 
 * @author      Alexandre Adomnicai
 *              alex.adomnicai@gmail.com
 * 
 * @date        March 2022
 */
#include "skinny128.h"
#include "romulus_n.h"

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
 * Romulus-N initialization.
 * 
 * TK1 is set to 0x0100...00.
 * 
 * The internal state is normally set to 0x00...00 w/o masking. Therefore we
 * simply copy the mask value into it instead.
 */
void romulusn_init(uint8_t *state, uint8_t *state_m, uint8_t *tk1)
{
	uint8_t i;
    tk1[0] = 0x01;
    zeroize(tk1+1, BLOCKBYTES-1);
    zeroize(state, BLOCKBYTES);
    zeroize(state_m, BLOCKBYTES);
}

/**
 * Romulus-N Additional Data (AD) processing.
 * 
 * At the end of the function, 'rtk' and 'rtk_m' are ready for use for message
 * processing. 
 */
void romulusn_process_ad(
    uint8_t *state, uint8_t* state_m,
    const uint8_t *ad, unsigned long long adlen,
    uint8_t *rtk, uint8_t *rtk_m, uint8_t *tk1,
    const uint8_t *npub, const uint8_t *k, const uint8_t *k_m)
{
    int i;
    uint32_t tmp;
    uint8_t rtk1[BLOCKBYTES*8];
    uint8_t pad[BLOCKBYTES];
    if (adlen == 0) {
        UPDATE_CTR(tk1);
        SET_DOMAIN(tk1, 0x1A);
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, npub, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
    } else {    // Process all double blocks except the last
        SET_DOMAIN(tk1, 0x08);
        while (adlen > 2*BLOCKBYTES) {
            UPDATE_CTR(tk1);
            XOR_BLOCK(state, state, ad);
            tk_schedule_123(rtk, rtk_m, rtk1, tk1, ad + BLOCKBYTES, k, k_m);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            UPDATE_CTR(tk1);
            ad += 2*BLOCKBYTES;
            adlen -= 2*BLOCKBYTES;
        }
        //Pad and process the left-over blocks 
        UPDATE_CTR(tk1);
        if (adlen == 2*BLOCKBYTES) {        // Left-over complete double block
            XOR_BLOCK(state, state, ad);
            tk_schedule_123(rtk, rtk_m, rtk1, tk1, ad + BLOCKBYTES, k, k_m);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            UPDATE_CTR(tk1);
            SET_DOMAIN(tk1, 0x18);
        } else if (adlen > BLOCKBYTES) {    //  Left-over partial double block
            adlen -= BLOCKBYTES;
            XOR_BLOCK(state, state, ad);
            copy(pad, ad + BLOCKBYTES, adlen);
            zeroize(pad + adlen, 15 - adlen);
            pad[15] = adlen;
            tk_schedule_123(rtk, rtk_m, rtk1, tk1, pad, k, k_m);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            UPDATE_CTR(tk1);
            SET_DOMAIN(tk1, 0x1A);
        } else if (adlen == BLOCKBYTES) {   //  Left-over complete single block 
            XOR_BLOCK(state, state, ad);
            SET_DOMAIN(tk1, 0x18);
        } else {    // Left-over partial single block
            for(i = 0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;
            SET_DOMAIN(tk1, 0x1A);
        }
        tk_schedule_123(rtk, rtk_m, rtk1, tk1, npub, k, k_m);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
    }
}

/**
 * Romulus-N message processing.
 * 
 * Unmasking is performed right before storing the ciphertext in the output
 * buffer 'out'.
 */
void romulusn_process_msg(
    uint8_t *out, const uint8_t *in, unsigned long long inlen,
    uint8_t *state, uint8_t *state_m,
    const uint8_t *rtk, const uint8_t *rtk_m, uint8_t *tk1,
    const int mode)
{
    int         i;
    uint32_t    tmp;
    uint8_t     tmp_blck[BLOCKBYTES];
    uint8_t     rtk1[BLOCKBYTES*8];
    tk1[0] = 0x01;          //init the 56-bit LFSR counter
    zeroize(tk1+1, TWEAKEYBYTES-1);
    if (inlen == 0) {
        UPDATE_CTR(tk1);
        SET_DOMAIN(tk1, 0x15);
        tk_schedule_1(rtk1, tk1);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
    } else {        //process all blocks except the last
        SET_DOMAIN(tk1, 0x04);
        while (inlen > BLOCKBYTES) {
            if(mode == ENCRYPT_MODE)
                RHO(state, state_m, out, in, tmp_blck);
            else
                RHO_INV(state, state_m, in, out, tmp_blck);
            UPDATE_CTR(tk1);
            tk_schedule_1(rtk1, tk1);
            skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
            out     += BLOCKBYTES;
            in      += BLOCKBYTES;
            inlen   -= BLOCKBYTES;
        }
        // (eventually pad) and process the last block
        UPDATE_CTR(tk1);
        if (inlen < BLOCKBYTES) {
            if (mode == ENCRYPT_MODE) {
                for(i = 0; i < (int)inlen; i++) {
                    tmp = in[i];         //just in case 'in = out'
                    out[i] = in[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
                    out[i] ^= (state_m[i] >> 1) ^ (state_m[i] & 0x80) ^ (state_m[i] << 7);
                    state[i] ^= (uint8_t)tmp;
                }
            } else {
                for(i = 0; i < (int)inlen; i++) {
                    out[i] = in[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
                    out[i] ^= (state_m[i] >> 1) ^ (state_m[i] & 0x80) ^ (state_m[i] << 7);
                    state[i] ^= out[i];
                }
            }
            state[15] ^= (uint8_t)inlen; //padding
            SET_DOMAIN(tk1, 0x15);
        } else {
            if(mode == ENCRYPT_MODE)
                RHO(state, state_m, out, in, tmp_blck);
            else
                RHO_INV(state, state_m, in, out, tmp_blck);
            SET_DOMAIN(tk1, 0x14);
        }
        tk_schedule_1(rtk1, tk1);
        skinny128_384_plus(state, state_m, state, state_m, rtk, rtk_m, rtk1);
    }
}

/**
 * Romulus-N tag generation.
 * 
 * Unmasking is performed right before storing the tag in the output buffer
 * 'c'.
 */
void romulusn_generate_tag(uint8_t *c, uint8_t *state, uint8_t *state_m)
{
    uint32_t tmp;
    G(state, state);
    G(state_m, state_m);
    for(int i =0; i < TAGBYTES; i++)
        c[i] = state[i] ^ state_m[i];
}

/**
 * Romulus-N tag verification.
 * 
 * Unmasking is performed on-the-fly when accumulating into the temporary var
 * 'tmp'.
 * 
 * Returns non-zero value if verification fails.
 */
uint32_t romulusn_verify_tag(const uint8_t *tag, uint8_t *state, uint8_t *state_m)
{
    uint32_t tmp;
    G(state,state);
    G(state_m, state_m);
    tmp = 0;
    for(int i = 0; i < TAGBYTES; i++)
        tmp |= state[i] ^ state_m[i] ^ tag[i];
    return tmp;
}
