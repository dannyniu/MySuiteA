/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#if defined(aead) && defined(mode) && defined(bc)
#include "../test-utils.c.h"

static uint8_t CiphCtx[32768];
static uint8_t k[32], n[16], a[32768], u[32768], v[32768], t[16];
static size_t xlen, alen, klen, nlen, tlen;


int Encrypt(int argc, char *argv[])
{
    size_t x;
    CryptoParam_t Bc;
    assert( argc >= 4 );

    Bc.info = bc, Bc.param = NULL;

    alen = (uint8_t *)scanhex(a, sizeof(a), argv[1]) - a;
    xlen = (uint8_t *)scanhex(u, sizeof(u), argv[2]) - u;
    klen = (uint8_t *)scanhex(k, sizeof(k), argv[3]) - k;
    nlen = (uint8_t *)scanhex(n, sizeof(n), argv[4]) - n;
    tlen = atoi(argv[5]) / 8;

    //for(x=0; x<alen; x++) fprintf(stderr, "%02x", a[x]);
    //fprintf(stderr, " %zd\n", alen);

    if( aead )
    {
        KINIT_FUNC(aead)(
            (void *)CiphCtx, k, KEY_BYTES(aead));
        AENC_FUNC(aead)(
            (void *)CiphCtx, nlen, n, alen, a, xlen, u, v, tlen, t);

        for(x=0; x<xlen; x++) printf("%02x", v[x]);
        printf(" ");

        for(x=0; x<16; x++) printf("%02x", t[x]);
        printf("\n");
    }

    if( mode && bc )
    {
        ((PKInitFunc_t)mode(&Bc, KInitFunc))(
            &Bc,
            (void *)CiphCtx, k, mode(&Bc, keyBytes));
        ((AEncFunc_t)mode(&Bc, AEncFunc))(
            (void *)CiphCtx, nlen, n, alen, a, xlen, u, v, tlen, t);

        for(x=0; x<xlen; x++) printf("%02x", v[x]);
        printf(" ");

        for(x=0; x<16; x++) printf("%02x", t[x]);
        printf("\n");
    }

    return EXIT_SUCCESS;
}

int Decrypt(int argc, char *argv[])
{
    size_t x;
    CryptoParam_t Bc;
    int ret = EXIT_SUCCESS;
    assert( argc >= 5 );

    Bc.info = bc, Bc.param = NULL;

    alen = (uint8_t *)scanhex(a, sizeof(a), argv[1]) - a;
    xlen = (uint8_t *)scanhex(u, sizeof(u), argv[2]) - u;
    klen = (uint8_t *)scanhex(k, sizeof(k), argv[3]) - k;
    nlen = (uint8_t *)scanhex(n, sizeof(n), argv[4]) - n;
    tlen = (uint8_t *)scanhex(t, sizeof(t), argv[5]) - t;

    if( aead )
    {
        KINIT_FUNC(aead)(
            (void *)CiphCtx, k, KEY_BYTES(aead));
        if( ADEC_FUNC(aead)(
                (void *)CiphCtx, nlen, n, alen, a, xlen, u, v, tlen, t) )
        {
            for(x=0; x<xlen; x++) printf("%02x", v[x]);
            printf("\n");
        }
        else ret = 12;
    }

    if( mode && bc )
    {
        ((PKInitFunc_t)mode(&Bc, KInitFunc))(
            &Bc, (void *)CiphCtx, k, mode(&Bc, keyBytes));
        if( ((ADecFunc_t)mode(&Bc, ADecFunc))(
                (void *)CiphCtx, nlen, n, alen, a, xlen, u, v, tlen, t) )
        {
            for(x=0; x<xlen; x++) printf("%02x", v[x]);
            printf("\n");
        }
        else ret = EXIT_FAILURE;
    }

    return ret;
}

#endif /* defined(aead) && defined(mode) && defined(bc) */
