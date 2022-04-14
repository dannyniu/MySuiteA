/* DannyNiu/NJF, 2022-04-14. Public Domain. */

#include "kmac.h"
#include "../1-symm/keccak.h"

void *KMAC_VInit(
    kmac_t *restrict kmac,
    const void *restrict k, size_t klen,
    const void *restrict s, size_t slen,
    unsigned rate)
{
    bufvec_t bv[2];

    if( rate >= 200 ) return NULL;

    bv[0].dat = "KMAC";
    bv[1].dat = s;
    bv[0].len = 4;
    bv[1].len = slen;

    *kmac = (kmac_t){
        .sponge = SPONGE_INIT(rate, 0x0f, 0x80, xKeccakF1600),
        .state = {0},
    };

    SHAKE_Xctrl(kmac, SHAKE_cSHAKE_customize, bv, 2, 0);
    cshake_left_encode(kmac, rate);
    cshake_encode_string(kmac, k, klen);
    Sponge_Update(&kmac->sponge, NULL, 1);

    return kmac;
}

void *KMAC128_Init(
    kmac128_t *restrict kmac,
    void const *restrict key,
    size_t keylen)
{
    return KMAC_VInit(kmac, key, keylen, NULL, 0, 200-16*2);
}

void *KMAC256_Init(
    kmac256_t *restrict kmac,
    void const *restrict key,
    size_t keylen)
{
    return KMAC_VInit(kmac, key, keylen, NULL, 0, 200-32*2);
}

void *KMAC128_Xctrl(
    kmac128_t *restrict kmac,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    unsigned rate = 200 - 16 * 2;
    (void)veclen;
    (void)flags;

    switch( cmd )
    {
    case KMAC_KInit_WithS:
        return KMAC_VInit(
            kmac,
            bufvec[1].dat, bufvec[1].len,
            bufvec[0].dat, bufvec[0].len,
            rate);
        break;
        
    default:
        return NULL;
    }
}

void *KMAC256_Xctrl(
    kmac256_t *restrict kmac,
    int cmd,
    const bufvec_t *restrict bufvec,
    int veclen,
    int flags)
{
    unsigned rate = 200 - 32 * 2;
    (void)veclen;
    (void)flags;

    switch( cmd )
    {
    case KMAC_KInit_WithS:
        return KMAC_VInit(
            kmac,
            bufvec[1].dat, bufvec[1].len,
            bufvec[0].dat, bufvec[0].len,
            rate);
        break;
        
    default:
        return NULL;
    }
}

void KMAC_Update(kmac_t *restrict kmac, const void *restrict data, size_t len)
{
    Sponge_Update(&kmac->sponge, data, len);
}

void KMAC_Final(kmac_t *restrict kmac, void *restrict out, size_t t)
{
    // [2022-04-14:n-out-len]:
    // It is a natural design that output of different desired length
    // be supported without requiring the entire input be re-inputted.
    
    if( !kmac->sponge.finalized )
    {
        Sponge_Save(&kmac->sponge);
    }
    else Sponge_Restore(&kmac->sponge);

    cshake_right_encode(kmac, t * 8);
    Sponge_Final(&kmac->sponge);
    Sponge_Read(&kmac->sponge, out, t);
}

void KMAC_XofFinal(kmac_t *restrict kmac)
{
    // see also [2022-04-14:n-out-len] in ``KMAC_Final''.
    
    if( !kmac->sponge.finalized )
    {
        Sponge_Save(&kmac->sponge);
    }
    else Sponge_Restore(&kmac->sponge);

    cshake_right_encode(kmac, 0);
    Sponge_Final(&kmac->sponge);
}

void KMAC_XofRead(kmac_t *restrict kmac, void *restrict out, size_t t)
{
    Sponge_Read(&kmac->sponge, out, t);
}

IntPtr iKMAC128(int q){ return xKMAC128(q); }
IntPtr iKMAC256(int q){ return xKMAC256(q); }
