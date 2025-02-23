/* DannyNiu/NJF, 2018-02-01. Public Domain. */

#include "rijndael.h"
#include <x86intrin.h>

#define NI_Define_AES_Cipher(name,Nr)           \
    void name(void const *in, void *out,        \
              void const *restrict w)           \
    {                                           \
        NI_Rijndael_Nb4_Cipher(in, out, w, Nr); \
    }
static void NI_Rijndael_Nb4_Cipher(
    uint8_t const in[16], uint8_t out[16],
    uint8_t const *restrict w, int Nr)
{
    register __m128i
        state = _mm_loadu_si128((const void*)in),
        rk;

    rk = _mm_loadu_si128((const void*)(w));
    state = _mm_xor_si128(state, rk);

    for(register int i=1; i<Nr; i++) {
        rk = _mm_loadu_si128((const void*)(w+i*16));
        state = _mm_aesenc_si128(state, rk);
    }

    rk = _mm_loadu_si128((const void*)(w+Nr*16));
    state = _mm_aesenclast_si128(state, rk);

    _mm_storeu_si128((void*)out, state);
    return;
}

#define NI_Define_AES_InvCipher(name,Nr)                \
    void name(void const *in, void *out,                \
              void const *restrict w)                   \
    {                                                   \
        NI_Rijndael_Nb4_InvCipher(in, out, w, Nr);      \
    }
static void NI_Rijndael_Nb4_InvCipher(
    uint8_t const in[16], uint8_t out[16],
    uint8_t const *restrict w, int Nr)
{
    register __m128i
        state = _mm_loadu_si128((const void*)in),
        rk;

    rk = _mm_loadu_si128((const void*)(w+Nr*16));
    state = _mm_xor_si128(state, rk);

    for(register int i=Nr; --i>0; ) {
        rk = _mm_loadu_si128((const void*)(w+i*16));
        rk = _mm_aesimc_si128(rk);
        state = _mm_aesdec_si128(state, rk);
    }

    rk = _mm_loadu_si128((const void*)(w));
    state = _mm_aesdeclast_si128(state, rk);

    _mm_storeu_si128((void*)out, state);
    return;
}

/* Even though "Intel(R) Advanced Encryption Standard (AES) New Instruction Set"
 * by Shay Gueron,
 * - Intel Architecture Group,
 * - Isreal Development Center,
 * - Intel Corporation.
 * had sample key expansion code, it causes alignment warnings during compilation,
 * so I dropped it in favor of C-based version.
 */

#define IntrinSelf
#include "rijndael.c"
