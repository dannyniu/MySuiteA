/* DannyNiu/NJF, 2018-02-01. Public Domain. */

#include "rijndael.h"

#include "../0-datum/endian.h"
#include <arm_neon.h>

#define Define_AES_Cipher(name,Nr)              \
    void name(void const *in, void *out,        \
              void const *restrict w)           \
    {                                           \
        Rijndael_Nb4_Cipher(in, out, w, Nr);    \
    }
static void Rijndael_Nb4_Cipher(
    uint8_t const in[16], uint8_t out[16],
    uint8_t const *restrict w, int Nr)
{
    register uint8x16_t state = vld1q_u8((const void*)in), rk;
    register int i;

    rk = vld1q_u8((const void*)(w));
    state = vaeseq_u8(state, rk);
    
    for(i=1; i<Nr; i++) {
        rk = vld1q_u8((const void*)(w+i*16));
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk);
    }

    rk = vld1q_u8((const void*)(w+Nr*16));
    state ^= rk;

    vst1q_u8((void*)out, state);
    return;
}

#define Define_AES_InvCipher(name,Nr)           \
    void name(void const *in, void *out,        \
              void const *restrict w)           \
    {                                           \
        Rijndael_Nb4_InvCipher(in, out, w, Nr); \
    }
static void Rijndael_Nb4_InvCipher(
    uint8_t const in[16], uint8_t out[16],
    uint8_t const *restrict w, int Nr)
{
    register uint8x16_t state = vld1q_u8((const void*)in), rk;
    register int i;

    rk = vld1q_u8((const void*)(w+Nr*16));
    state = vaesdq_u8(state, rk);

    for(i=Nr; --i>0; ) {
        rk = vld1q_u8((const void*)(w+i*16));
        rk = vaesimcq_u8(rk);
        state = vaesimcq_u8(state);
        state = vaesdq_u8(state, rk);
    }

    rk = vld1q_u8((const void*)(w));
    state ^= rk;

    vst1q_u8((void*)out, state);
    return;
}

#include "rijndael.c"
