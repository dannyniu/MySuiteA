/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#include "test-prng-stub.c.h"
#include "../test-utils.c.h"

// Expects: PKC_InstAlgo, PKC_CtAlgo, MSGMAX, params.

#define PKC_PreHash_Type PKC_InstAlgo(params, dssPreHashingType)

#define PKC_Sign                                \
    ((PKSignFunc_t)(PKC_CtAlgo(PKSignFunc)))

#define PKC_Verify                                      \
    ((PKVerifyFunc_t)(PKC_CtAlgo(PKVerifyFunc)))

#define PKC_IncSign_Init                                                \
    ((PKIncSignInitFunc_t)(PKC_InstAlgo(params, PKIncSignInitFunc)))

#define PKC_IncSign_Final                                               \
    ((PKIncSignFinalFunc_t)(PKC_InstAlgo(params, PKIncSignFinalFunc)))

#define PKC_IncVerify_Init                                              \
    ((PKIncVerifyInitFunc_t)(PKC_InstAlgo(params, PKIncVerifyInitFunc)))

#define PKC_IncVerify_Final                                             \
    ((PKIncVerifyFinalFunc_t)(PKC_InstAlgo(params, PKIncVerifyFinalFunc)))

#define PKC_Encode_Signature                            \
    ((PKCiphergramEncoder_t)(PKC_CtAlgo(PKCtEncoder)))

#define PKC_Decode_Signature                            \
    ((PKCiphergramDecoder_t)(PKC_CtAlgo(PKCtDecoder)))

void *my_alloc(const char *s, size_t len)
{
    printf("my_alloc: %s: %zd bytes\n", s, len);
    return malloc(len);
}

int main(int argc, char *argv[])
{
    IntPtr lret;
    size_t size;

#include "test-api-keycpy.c.h"

    printf("tests start\n");

    int failures = 0;
    int testcount = 80 / 5;

    uint32_t dword; // data word that receives output from PRNG.
    size_t msglen = MSGMAX;
    void *msg = malloc(msglen);
    void *sig;

    printf("all-at-once tests.\n");

    for(int i=0; i<testcount; i++)
    {
        printf("\t""test %d of %d\r", i+1, testcount);
        fflush(NULL);

#ifdef PKC_Prologue
        PKC_Prologue();
#endif /* PKC_Prologue */

        PKC_PRNG_Gen(prng, &dword, sizeof(dword));
        msglen = dword % MSGMAX;

        PKC_PRNG_Gen(prng, msg, msglen);

        PKC_Sign(dex, msg, msglen, PKC_PRNG_Gen, prng);
        PKC_Encode_Signature(dex, NULL, &size);

        if( !(sig = realloc(copy, size)) )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }
        else copy = sig;

        PKC_Encode_Signature(dex, copy, &size);
        PKC_Decode_Signature(enx, copy, size);

        lret = (IntPtr)PKC_Verify(enx, msg, msglen);
        if( !lret )
        {
            printf("%d: Signature Failure\n", i);
            failures ++;
            break;
        }

#ifdef PKC_Epilogue
        PKC_Epilogue();
#endif /* PKC_Epilogue */
    }

    if( PKC_PreHash_Type != dssPreHashing_Interface &&
        PKC_PreHash_Type != dssPreHashing_Variant )
    {
        printf("no incremental tests.\n");
        goto test_done;
    }

    printf("incremental tests.\n");

    for(int i=0; i<testcount; i++)
    {
        uint8_t seed[16];
        UpdateFunc_t hfn_update;
        void *sig_hctx;

        printf("\t""test %d of %d\r", i+1, testcount);
        fflush(NULL);

#ifdef PKC_Prologue
        PKC_Prologue();
#endif /* PKC_Prologue */

        sig_hctx = PKC_IncSign_Init(dex, &hfn_update);

        PKC_PRNG_Gen(prng, seed, sizeof(seed));
        Gimli_XOF_Init(&mx);
        Gimli_XOF_Write(&mx, seed, sizeof(seed));
        Gimli_XOF_Final(&mx);

        for(int r=0; r<i; r++)
        {
            Gimli_XOF_Read(&mx, &dword, sizeof(dword));
            msglen = dword % MSGMAX;
            Gimli_XOF_Read(&mx, msg, msglen);
            hfn_update(sig_hctx, msg, msglen);
        }

        PKC_IncSign_Final(dex, PKC_PRNG_Gen, prng);
        PKC_Encode_Signature(dex, NULL, &size);

        if( !(sig = realloc(copy, size)) )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }
        else copy = sig;

        PKC_Encode_Signature(dex, copy, &size);
        PKC_Decode_Signature(enx, copy, size);

        sig_hctx = PKC_IncVerify_Init(enx, &hfn_update);

        // 2024-10-05:
        // since the addition of the rewinding functionality,
        // only the ''*_Final'' is necessary.
        //- Gimli_XOF_Init(&mx);
        //- Gimli_XOF_Write(&mx, seed, sizeof(seed));
        Gimli_XOF_Final(&mx);

        for(int r=0; r<i; r++)
        {
            Gimli_XOF_Read(&mx, &dword, sizeof(dword));
            msglen = dword % MSGMAX;
            Gimli_XOF_Read(&mx, msg, msglen);
            hfn_update(sig_hctx, msg, msglen);
        }

        lret = (IntPtr)PKC_IncVerify_Final(enx);
        if( !lret )
        {
            printf("%d: Signature Failure\n", i);
            failures ++;
            break;
        }

#ifdef PKC_Epilogue
        PKC_Epilogue();
#endif /* PKC_Epilogue */
    }

test_done:
    printf("\n%d of %d tests failed\n", failures, testcount*2);
    free(copy);
    free(enx);
    free(dex);
    free(kgx);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
