/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#include "shake.h"
#include "../1-symm/keccak.h"
#include "../0-datum/endian.h"

void SHAKE128_Init(shake_t *restrict x)
{
    *x = (shake_t){
        .sponge = SPONGE_INIT(200-16*2, 0x1f, 0x80, xKeccakF1600),
        .state = {0},
    };
}

void SHAKE256_Init(shake_t *restrict x)
{
    *x = (shake_t){
        .sponge = SPONGE_INIT(200-32*2, 0x1f, 0x80, xKeccakF1600),
        .state = {0},
    };
}

void SHAKE_Write(shake_t *restrict x, const void *restrict data, size_t len)
{
    Sponge_Update(&x->sponge, data, len);
}

void SHAKE_Final(shake_t *restrict x)
{
    // 2023-05-17:
    // Changed so that a call to this function
    // would resets output stream to the start.

    if( !x->sponge.finalized )
    {
        Sponge_Final(&x->sponge);
        Sponge_Save(&x->sponge);
    }
    else Sponge_Restore(&x->sponge);
}

void SHAKE_Read(shake_t *restrict x, void *restrict data, size_t len)
{
    Sponge_Read(&x->sponge, data, len);
}

static inline uint8_t ilen(uint64_t v)
{
    uint8_t o = 8;

    if( v < (uint64_t)1 << 56 ) o = 7; else return o;
    if( v < (uint64_t)1 << 48 ) o = 6; else return o;
    if( v < (uint64_t)1 << 40 ) o = 5; else return o;
    if( v < (uint64_t)1 << 32 ) o = 4; else return o;
    if( v < (uint64_t)1 << 24 ) o = 3; else return o;
    if( v < (uint64_t)1 << 16 ) o = 2; else return o;
    if( v < (uint64_t)1 <<  8 ) o = 1; else return o;

    return o;
}

void cshake_left_encode(shake_t *restrict x, uint64_t v)
{
    union {
        uint64_t l;
        uint8_t c[8];
    } b;

    b.l = htobe64(v);
    uint8_t o = ilen(v);

    SHAKE_Write(x, &o, 1);
    SHAKE_Write(x, b.c+8-o, o);
}

void cshake_right_encode(shake_t *restrict x, uint64_t v)
{
    union {
        uint64_t l;
        uint8_t c[8];
    } b;

    b.l = htobe64(v);
    uint8_t o = ilen(v);

    SHAKE_Write(x, b.c+8-o, o);
    SHAKE_Write(x, &o, 1);
}

void cshake_encode_string(
    shake_t *restrict x,
    const void *restrict S,
    size_t len)
{
    cshake_left_encode(x, len * 8);
    SHAKE_Write(x, S, len);
}

void *SHAKE_Xctrl(
    shake_t *restrict x,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    unsigned rate;
    (void)flags;

    switch( cmd )
    {
    case SHAKE_cSHAKE_customize:
        // run-time error.
        if( !bufvec || veclen < 2 ) return NULL;

        rate = x->sponge.rate;

        // fall-back to plain SHAKE.
        if( bufvec[0].len == 0 && bufvec[1].len == 0 )
        {
            *x = (shake_t){
                .sponge = SPONGE_INIT(rate, 0x1f, 0x80, xKeccakF1600),
                .state = {0},
            };
            return x;
        }

        // cSHAKE customization.
        *x = (shake_t){
            .sponge = SPONGE_INIT(rate, 0x04, 0x80, xKeccakF1600),
            .state = {0},
        };

        cshake_left_encode(x, rate);
        cshake_encode_string(x, bufvec[0].dat, bufvec[0].len);
        cshake_encode_string(x, bufvec[1].dat, bufvec[1].len);
        Sponge_Update(&x->sponge, NULL, 1); // indirect invocation of bytepad.
        return x;
        break;

    default:
        return NULL;
    }
}

IntPtr iSHAKE128(int q){ return xSHAKE128(q); }
IntPtr iSHAKE256(int q){ return xSHAKE256(q); }

IntPtr iSHAKE128o32(int q){ return xSHAKE128o32(q); }
IntPtr iSHAKE256o64(int q){ return xSHAKE256o64(q); }
