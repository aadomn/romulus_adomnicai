#ifndef ROMULUSN_H_
#define ROMULUSN_H_

#include "skinny128.h"


#define ENCRYPT_MODE 0
#define DECRYPT_MODE 1

#define TAGBYTES    16
#define KEYBYTES    16
#define BLOCKBYTES  16

#define SET_DOMAIN(tk1, domain) (tk1[7] = (domain))

//G as defined in the Romulus specification in a 32-bit word-wise manner
#define G(x,y) ({                                                                       \
    tmp = ((uint32_t*)(y))[0];                                                          \
    ((uint32_t*)(x))[0] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);  \
    tmp = ((uint32_t*)(y))[1];                                                          \
    ((uint32_t*)(x))[1] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);  \
    tmp = ((uint32_t*)(y))[2];                                                          \
    ((uint32_t*)(x))[2] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);  \
    tmp = ((uint32_t*)(y))[3];                                                          \
    ((uint32_t*)(x))[3] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);  \
})

//update the counter in tk1 in a 32-bit word-wise manner
#define UPDATE_CTR(tk1) ({                                  \
    tmp = ((uint32_t*)(tk1))[1];                            \
    ((uint32_t*)(tk1))[1] = (tmp << 1) & 0x00ffffff;        \
    ((uint32_t*)(tk1))[1] |= (((uint32_t*)(tk1))[0] >> 31); \
    ((uint32_t*)(tk1))[1] |= tmp & 0xff000000;              \
    ((uint32_t*)(tk1))[0] <<= 1;                            \
    if ((tmp >> 23) & 0x01)                                 \
        ((uint32_t*)(tk1))[0] ^= 0x95;                      \
})

//x <- y ^ z for 128-bit blocks
#define XOR_BLOCK(x,y,z) ({                                             \
    ((uint32_t*)(x))[0] = ((uint32_t*)(y))[0] ^ ((uint32_t*)(z))[0];    \
    ((uint32_t*)(x))[1] = ((uint32_t*)(y))[1] ^ ((uint32_t*)(z))[1];    \
    ((uint32_t*)(x))[2] = ((uint32_t*)(y))[2] ^ ((uint32_t*)(z))[2];    \
    ((uint32_t*)(x))[3] = ((uint32_t*)(y))[3] ^ ((uint32_t*)(z))[3];    \
})

//Rho as defined in the Romulus specification
//use pad as a tmp variable in case y = z
#define RHO(x,x_m,y,z,tmp) ({       \
    G(tmp,x);                       \
    XOR_BLOCK(y, tmp, z);           \
    G(tmp,x_m);                     \
    XOR_BLOCK(y, tmp, y);           \
    XOR_BLOCK(x, x, z);             \
})

//Rho inverse as defined in the Romulus specification
//use pad as a tmp variable in case y = z
#define RHO_INV(x, x_m, y, z, tmp) ({   \
    G(tmp, x);                          \
    XOR_BLOCK(z, tmp, y);               \
    G(tmp, x_m);                        \
    XOR_BLOCK(z, tmp, z);               \
    XOR_BLOCK(x, x, z);                 \
})


void romulusn_init(uint8_t *state, uint8_t *state_m, uint8_t *tk1);

void romulusn_process_ad(
    uint8_t *state, uint8_t* state_m,
    const uint8_t *ad, unsigned long long adlen,
    uint8_t *rtk, uint8_t *rtk_m, uint8_t *tk1,
    const uint8_t *npub, const uint8_t *k, const uint8_t *k_m);


void romulusn_process_msg(
    uint8_t *out, const uint8_t *in, unsigned long long inlen,
    uint8_t *state, uint8_t *state_m,
    const uint8_t *rtk, const uint8_t *rtk_m, uint8_t *tk1,
    const int mode);


void romulusn_generate_tag(uint8_t *c, uint8_t *state, uint8_t *state_m);
uint32_t romulusn_verify_tag(const uint8_t *tag, uint8_t *state, uint8_t *state_m);

#endif  // ROMULUSN1_H_