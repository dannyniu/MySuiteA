/* DannyNiu/NJF, 2023-10-25. Public Domain. */

#include "mlkem.c"
#include "../2-hash/sha3.h"

#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#define PKC_CtAlgo iMLKEM_CtCodec

#ifndef SSLEN
#define SSLEN 32
#endif /* SSLEN */

#define PKC_KeyAlgo iMLKEM_KeyCodec

MLKEM_Param_t params = {
    [0] = { .info = NULL, .aux = LatticeK, },
};

sha3_256_t hctx;
#define hash(in, inlen, out, outlen) do {       \
        SHA3_256_Init(&hctx);                   \
        SHA3_256_Update(&hctx, in, inlen);      \
        SHA3_256_Final(&hctx, out, outlen);     \
    } while( false )

int main()
{
    uint8_t m1[32];
    uint8_t m2[32];
    int rndfd = open("/dev/urandom", O_RDONLY);
    MLKEM_Ctx_Hdr_t *x = calloc(1, MLKEM_CTX_SIZE(LatticeK));
    MLKEM_Keygen(x, params, (GenFunc_t)read, (void *)rndfd);

    read(rndfd, m1, 32);
    read(rndfd, m2, 32);

    KPKE_Enc(x, m1, m2);
    KPKE_Dec(x);

    return 0;
}
