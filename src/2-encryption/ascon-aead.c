/* DannyNiu/NJF, 2025-01-28. Public Domain. */

#include "ascon-aead.h"
#include "../0-datum/endian.h"

static void Ascon_P8(void const *in, void *out)
{
    return Ascon_Permute(in, out, 8);
}

#define xAscon_P8(q) (                          \
        q==blockBytes ? 40 :                    \
        q==PermuteFunc ? (IntPtr)Ascon_P8 :     \
        0 )

static void Ascon_P12(void const *in, void *out)
{
    return Ascon_Permute(in, out, 12);
}

#define xAscon_P12(q) (                         \
        q==blockBytes ? 40 :                    \
        q==PermuteFunc ? (IntPtr)Ascon_P12 :    \
        0 )

void *Ascon_AEAD_Init(
    ascon_aead_t *restrict ctx, void const *restrict k, size_t klen)
{
    size_t t;
    if( klen != 32 && klen != 16 )
    {
        return NULL;
    }

    *ctx = (ascon_aead_t){
        .sponge = SPONGE_INIT(16, 0x01, 0, xAscon_P8),
        .state[0].u64 = {0},
        .key = {0},
    };

    for(t=0; t<klen; t++)
        ctx->key[t] = ((uint8_t *)k)[t];

    return ctx;
}

static void init_prelude(ascon_aead_t *restrict ctx,
                         size_t ivlen, void const *iv,
                         size_t alen, void const *aad)
{
    size_t t;

    assert( ivlen == 16 ); // Check done by Encrypt and Decrypt subroutines.

    ctx->state[0].u64[0] = htole64(0x00001000808c0001);
    for(t=1; t<5; t++) ctx->state[0].u64[t] = 0;
    for(t=0; t<16; t++) ctx->state[0].u8[t+24] = ((uint8_t *)iv)[t];
    for(t=0; t<32; t++) ctx->state[0].u8[t+8] ^= ctx->key[t];
    Ascon_P12(ctx->state, ctx->state);
    for(t=0; t<16; t++) ctx->state[0].u8[t+24] ^= ctx->key[t];

    if( alen > 0 )
    {
        Sponge_Update(&ctx->sponge, aad, alen);
        Sponge_Final(&ctx->sponge);
        ctx->sponge.finalized = false;
    }
    ctx->state[0].u8[39] ^= 0x80;
}

void *Ascon_AEAD_Encrypt(
    ascon_aead_t *restrict ctx,
    size_t ivlen, void const *iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void *T)
{
    size_t t;
    if( ivlen != 16 ) return NULL;

    init_prelude(ctx, ivlen, iv, alen, aad);

    for(t=0; t<len; t++)
    {
        ((uint8_t *)out)[t] = ctx->state[0].u8[t % 16] ^= ((uint8_t *)in)[t];
        if( t % 16 == 15 ) Ascon_P8(ctx->state, ctx->state);
    }

    ctx->state[0].u8[t % 16] ^= 0x01;
    for(t=0; t<16; t++) ctx->state[0].u8[t+16] ^= ctx->key[t];
    Ascon_P12(ctx->state, ctx->state);

    for(t=0; t<16 && t<tlen; t++)
        ((uint8_t *)T)[t] = ctx->state[0].u8[t+24] ^ ctx->key[t];

    for(; t<tlen; t++)
        ((uint8_t *)T)[t] = 0;

    return out;
}

void *Ascon_AEAD_Decrypt(
    ascon_aead_t *restrict ctx,
    size_t ivlen, void const *iv,
    size_t alen, void const *aad,
    size_t len, void const *in, void *out,
    size_t tlen, void const *T)
{
    size_t t;
    int b = 0;

    if( ivlen != 16 ) return NULL;

    init_prelude(ctx, ivlen, iv, alen, aad);

    Sponge_Save(&ctx->sponge);

    for(t=0; t<len; t++)
    {
        ctx->state[0].u8[t % 16] = ((uint8_t *)in)[t];
        if( t % 16 == 15 ) Ascon_P8(ctx->state, ctx->state);
    }

    ctx->state[0].u8[t % 16] ^= 0x01;
    for(t=0; t<16; t++) ctx->state[0].u8[t+16] ^= ctx->key[t];
    Ascon_P12(ctx->state, ctx->state);

    for(t=0; t<16 && t<tlen; t++)
        b |= ((uint8_t *)T)[t] ^ ctx->state[0].u8[t+24] ^ ctx->key[t];

    if( b ) return NULL;

    Sponge_Restore(&ctx->sponge);

    for(t=0; t<len; t++)
    {
        ((uint8_t *)out)[t] = ctx->state[0].u8[t % 16] ^ ((uint8_t *)in)[t];
        ctx->state[0].u8[t % 16] ^= ((uint8_t *)out)[t];
        if( t % 16 == 15 ) Ascon_P8(ctx->state, ctx->state);
    }

    return out;
}

IntPtr iAscon_AEAD128(int q)
{
    return xAscon_AEAD128(q);
}

IntPtr iAscon_AEAD128nm(int q)
{
    return xAscon_AEAD128nm(q);
}
