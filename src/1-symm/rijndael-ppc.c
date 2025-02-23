/* DannyNiu/NJF, 2022-10-02. Public Domain. */

#include "rijndael.h"

#include "../0-datum/endian.h"
#include <altivec.h>

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
    register vector unsigned char state = vec_xl_be(0, in);
    register vector unsigned char rk;
    register int i;

    rk = vec_xl_be(0, w);
    state ^= rk;

    for(i=1; i<Nr; i++) {
        rk = vec_xl_be(0, w+i*16);
        state = vec_cipher_be(state, rk);
    }

    rk = vec_xl_be(0, w+Nr*16);
    state = vec_cipherlast_be(state, rk);

    vec_xst_be(state, 0, (uint8_t*)out);
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
    register vector unsigned char state = vec_xl_be(0, in);
    register vector unsigned char rk;
    register int i;

    rk = vec_xl_be(0, w+Nr*16);
    state ^= rk;

    for(i=Nr; --i>0; ) {
        rk = vec_xl_be(0, (w+i*16));
        state = vec_ncipher_be(state, rk);
    }

    rk = vec_xl_be(0, w);
    state = vec_ncipherlast_be(state, rk);

    vec_xst_be(state, 0, out);
    return;
}

#define IntrinSelf
#include "rijndael.c"
