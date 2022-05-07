/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsaes-pkcs1-v1_5.h"

IntPtr tRSAEncryption(const CryptoParam_t *P, int q)
{
    return xRSAEncryption(
        (P ? P[0].info : NULL),
        (P ? P[1].info : NULL),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 0),
        (P ? P[4].aux : 0),
        q);
}

IntPtr iRSAEncryption_CtCodec(int q)
{ return xRSAEncryption_CtCodec(q); }
