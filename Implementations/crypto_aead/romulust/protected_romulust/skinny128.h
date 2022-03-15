#ifndef SKINNY128_H_
#define SKINNY128_H_

#include <stdint.h>

#define SKINNY128_384_ROUNDS    40
#define TWEAKEYBYTES            16
#define BLOCKBYTES              16
#define TKPERMORDER             16

/**
 * Skinny-128-384+ w/ 1st-order masking (for KDF and tag generation).
 */
extern void skinny128_384_plus_m(
    uint8_t ctext[BLOCKBYTES],
    uint8_t ctext_m[BLOCKBYTES],
    const uint8_t ptext[BLOCKBYTES],
    const uint8_t ptext_m[BLOCKBYTES],
    const uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t rtk_3m[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t rtk1[TKPERMORDER*BLOCKBYTES]
);

/**
 * Skinny-128-384+ w/o 1st-order masking (for internal calls).
 */
extern void skinny128_384_plus(
    uint8_t out[BLOCKBYTES],
    const uint8_t in[BLOCKBYTES],
    const uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    const uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES]
);

/**
 * Precomputes LFSR2(tk2) ^ LFSR3(tk3) for a given number of rounds.
 * 
 * Output round tweakeys are in fixsliced representation.
 */
extern void tks_lfsr_23(
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_2[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES],
    const int rounds
);

/**
 * Precomputes LFSR3(tk3) for a given number of rounds.
 * Useful for masking since secret key is passed as TK3 only.
 * 
 * Output round tweakeys are in fixsliced representation.
 */
extern void tks_lfsr_3(
    uint8_t rtk_3[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_3[TWEAKEYBYTES],
    const int rounds
);

/**
 * Apply the tweakey permutation to round tweakeys for 40 rounds.
 * Also add the round constants at the same time.
 * 
 * Input/output round tweakeys are expected to be in fixsliced representation.
 */
extern void tks_perm_23(
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES]
);

/**
 * Apply the tweakey permutation to round tweakeys for 40 rounds.
 * 
 * Input/output round tweakeys are expected to be in fixsliced representation.
 */
extern void tks_perm_23_norc(
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES]
);

/**
 * Apply the tweakey permutation to round tweakeys for 16 rounds. 
 * 
 * Input tk1 is expected to be in byte-wise representation while output round
 * tweakeys are in fixsliced representation.
 */
extern void tks_perm_1(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES]
);

/**
 * Calculation of round tweakeys related to TK1 only.
 */
inline void tk_schedule_1(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES])
{
    tks_perm_1(rtk_1, tk_1);
};


/**
 * Calculation of round tweakeys related to TK2 and TK3 only w/ 1st-order
 * masking of TK3.
 */
inline void tk_schedule_13_m(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    uint8_t rtk_3[SKINNY128_384_ROUNDS*BLOCKBYTES],
    uint8_t rtk_3m[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES],
    const uint8_t tk_3m[TWEAKEYBYTES])
{
    tks_perm_1(rtk_1, tk_1);
    tks_lfsr_3(rtk_3, tk_3, SKINNY128_384_ROUNDS);
    tks_perm_23(rtk_3);
    tks_lfsr_3(rtk_3m, tk_3m, SKINNY128_384_ROUNDS);
    tks_perm_23_norc(rtk_3m);
};

/**
 * Calculation of round tweakeys related to TK1, TK2 and TK3 (full TK schedule)
 * w/ 1st-order masking of TK3.
 */
inline void tk_schedule_123_m(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    uint8_t rtk_3m[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES],
    const uint8_t tk_2[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES],
    const uint8_t tk_3m[TWEAKEYBYTES])
{
    tks_perm_1(rtk_1, tk_1);
    tks_lfsr_23(rtk_23, tk_2, tk_3, SKINNY128_384_ROUNDS);
    tks_perm_23(rtk_23);
    tks_lfsr_3(rtk_3m, tk_3m, SKINNY128_384_ROUNDS);
    tks_perm_23_norc(rtk_3m);
};


/**
 * Calculation of round tweakeys related to TK1 and TK3 only.
 */
inline void tk_schedule_13(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    uint8_t rtk_3[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES])
{
    tks_perm_1(rtk_1, tk_1);
    tks_lfsr_3(rtk_3, tk_3, SKINNY128_384_ROUNDS);
    tks_perm_23(rtk_3);
};

/**
 * Calculation of round tweakeys related to TK1, TK2 and TK3 (full TK schedule)
 */
inline void tk_schedule_123(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES],
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES],
    const uint8_t tk_2[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES])
{
    tks_perm_1(rtk_1, tk_1);
    tks_lfsr_23(rtk_23, tk_2, tk_3, SKINNY128_384_ROUNDS);
    tks_perm_23(rtk_23);
};

#endif  // SKINNY128_H_
