/* DannyNiu/NJF, 2018-02-15. Public Domain. */

#include "../0-datum/endian.h"
#include "chacha20-poly1305.h"

void *ChaCha_AEAD_Init(
    chacha_aead_t *restrict x,
    void const *restrict K,
    size_t klen)
{
    if( klen != 32 ) return NULL;
    chacha20_set_state(x->state, K, NULL);
    return x;
}

static inline size_t min(size_t a, size_t b) { return a<b ? a : b; }

void ChaCha_AEAD_Encrypt(
    chacha_aead_t *restrict x,
    void const *restrict iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void *T)
{
    alignas(uint64_t) uint8_t words[32];
    const uint8_t *iptr=in; uint8_t *optr=out;
    size_t i, j;
    
    chacha20_set_state(x->state, NULL, iv);
    chacha20_block(x->state, 0, 32, NULL, words);
    poly1305_init(&x->poly1305, words);

    for(i=0; i<len; i+=64) {
        chacha20_block(x->state, (uint32_t)(i/64+1), min(64,len-i), iptr+i, optr+i);
    }

    for(i=0; i<alen; i+=16) {
        for(j=0; j<16; j++) words[j] = i+j<alen ? ((const uint8_t *)aad)[i+j] : 0;
        poly1305_1block(&x->poly1305, words);
    }

    for(i=0; i<len; i+=16) {
        for(j=0; j<16; j++) words[j] = i+j<len ? ((const uint8_t *)out)[i+j] : 0;
        poly1305_1block(&x->poly1305, words);
    }

    ((uint64_t *)words)[0] = htole64(alen);
    ((uint64_t *)words)[1] = htole64(len);
    poly1305_1block(&x->poly1305, words);

    poly1305_final(&x->poly1305);
    for(i=0; i<4; i++) ((uint32_t *)words)[i] = htole32(x->poly1305.a[i]);
    for(i=0; i<tlen; i++) {
        // Zero-extends if tlen>16. 
        ((uint8_t *)T)[i] = i<16 ? words[i] : 0;
    }
}

void *ChaCha_AEAD_Decrypt(
    chacha_aead_t *restrict x,
    void const *restrict iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void const *T)
{
    alignas(uint64_t) uint8_t words[32];
    const uint8_t *iptr=in; uint8_t *optr=out;
    size_t i, j;

    chacha20_set_state(x->state, NULL, iv);
    chacha20_block(x->state, 0, 32, NULL, words);
    poly1305_init(&x->poly1305, words);

    for(i=0; i<alen; i+=16) {
        for(j=0; j<16; j++) words[j] = i+j<alen ? ((const uint8_t *)aad)[i+j] : 0;
        poly1305_1block(&x->poly1305, words);
    }

    for(i=0; i<len; i+=16) {
        for(j=0; j<16; j++) words[j] = i+j<len ? ((const uint8_t *)in)[i+j] : 0;
        poly1305_1block(&x->poly1305, words);
    }

    ((uint64_t *)words)[0] = htole64(alen);
    ((uint64_t *)words)[1] = htole64(len);
    poly1305_1block(&x->poly1305, words);

    poly1305_final(&x->poly1305);
    for(i=0; i<4; i++) ((uint32_t *)words)[i] = htole32(x->poly1305.a[i]);
    for(i=0; i<tlen; i++) {
        if( ((const uint8_t *)T)[i] != (i<16 ? words[i] : 0) )
            out = NULL;
    }

    if( !out ) return NULL;

    for(i=0; i<len; i+=64) {
        chacha20_block(x->state, (uint32_t)(i/64+1), min(64,len-i), iptr+i, optr+i);
    }

    return out;
}

IntPtr iChaCha_AEAD(int q) { return cChaCha_AEAD(q); }
