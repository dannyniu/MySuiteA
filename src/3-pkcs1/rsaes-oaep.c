/* DannyNiu/NJF, 2021-12-24. Public Domain. */

#include "rsaes-oaep.h"

IntPtr tRSAES_OAEP(const CryptoParam_t *P, int q)
{
    if( P ) assert( P[3].aux >= 2 );
    return xRSAES_OAEP(
        (P ? P[0].info : PKCS1_NullHash),
        (P ? P[1].info : PKCS1_NullHash),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 1),
        q);
}

IntPtr iRSAES_OAEP_CtCodec(int q) { return xRSAES_OAEP_CtCodec(q); }
