/* DannyNiu/NJF, 2021-12-24. Public Domain. */

#include "rsassa-pss.h"

IntPtr tRSASSA_PSS(const CryptoParam_t *P, int q)
{
    if( P ) assert( P[4].aux >= 2 ); // There was a mistake before 2023-08-03.
    return xRSASSA_PSS(
        (P ? P[0].info : PKCS1_NullHash),
        (P ? P[1].info : PKCS1_NullHash),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 1),
        q);
}

IntPtr iRSASSA_PSS_CtCodec(int q) { return xRSASSA_PSS_CtCodec(q); }
