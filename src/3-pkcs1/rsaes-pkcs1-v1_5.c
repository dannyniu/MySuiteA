/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsaes-pkcs1-v1_5.h"

IntPtr tRSAEncryption(const CryptoParam_t *P, int q)
{
    if( P ) assert( P[3].aux >= 2 );
    return xRSAEncryption(
        (P ? P[0].info : PKCS1_NullHash),
        (P ? P[1].info : PKCS1_NullHash),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 1),
        q);
}

IntPtr iRSAEncryption_CtCodec(int q)
{ return xRSAEncryption_CtCodec(q); }
