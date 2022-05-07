/* DannyNiu/NJF, 2022-05-07. Public Domain. */

#include "rsassa-pkcs1-v1_5.h"
#include "../2-hash/sha.h"

const RSAEnc_HashOID HashOIDs_Table[] =
{
    {
        .HashInitFunc = (InitFunc_t)SHA1_Init,
        .DER_Prefix =
        "\x30\x21\x30\x09\x06\x05\x2b\x0e"
        "\x03\x02\x1a\x05\x00\x04\x14",
        .DER_Prefix_Len = 15,
        .Digest_Len = 20,
    },

    {
        .HashInitFunc = (InitFunc_t)SHA224_Init,
        .DER_Prefix =
        "\x30\x2d\x30\x0d\x06\x09\x60\x86"
        "\x48\x01\x65\x03\x04\x02\x04\x05"
        "\x00\x04\x1c",
        .DER_Prefix_Len = 19,
        .Digest_Len = 28,
    },

    {
        .HashInitFunc = (InitFunc_t)SHA256_Init,
        .DER_Prefix =
        "\x30\x31\x30\x0d\x06\x09\x60\x86"
        "\x48\x01\x65\x03\x04\x02\x01\x05"
        "\x00\x04\x20",
        .DER_Prefix_Len = 19,
        .Digest_Len = 32,
    },

    {
        .HashInitFunc = (InitFunc_t)SHA384_Init,
        .DER_Prefix =
        "\x30\x41\x30\x0d\x06\x09\x60\x86"
        "\x48\x01\x65\x03\x04\x02\x02\x05"
        "\x00\x04\x30",
        .DER_Prefix_Len = 19,
        .Digest_Len = 48,
    },

    {
        .HashInitFunc = (InitFunc_t)SHA512_Init,
        .DER_Prefix =
        "\x30\x51\x30\x0d\x06\x09\x60\x86"
        "\x48\x01\x65\x03\x04\x02\x03\x05"
        "\x00\x04\x40",
        .DER_Prefix_Len = 19,
        .Digest_Len = 64,
    },

    {
        .HashInitFunc = (InitFunc_t)SHA512t224_Init,
        .DER_Prefix =
        "\x30\x2d\x30\x0d\x06\x09\x60\x86"
        "\x48\x01\x65\x03\x04\x02\x05\x05"
        "\x00\x04\x1c",
        .DER_Prefix_Len = 19,
        .Digest_Len = 28,
    },

    {
        .HashInitFunc = (InitFunc_t)SHA512t256_Init,
        .DER_Prefix =
        "\x30\x31\x30\x0d\x06\x09\x60\x86"
        "\x48\x01\x65\x03\x04\x02\x06\x05"
        "\x00\x04\x20",
        .DER_Prefix_Len = 19,
        .Digest_Len = 32,
    },

    // FIPS-202 SHA-3 and SHAKE functions had
    // never been used with legacy algorithms.

    {0}
};

IntPtr tRSAEncryptionWithHash(const CryptoParam_t *P, int q)
{
    return xRSAEncryptionWithHash(
        (P ? P[0].info : NULL),
        (P ? P[1].info : NULL),
        (P ? P[2].aux : 0),
        (P ? P[3].aux : 0),
        (P ? P[4].aux : 0),
        q);
}

IntPtr iRSAEncryptionWithHash_CtCodec(int q)
{ return xRSAEncryptionWithHash_CtCodec(q); }
