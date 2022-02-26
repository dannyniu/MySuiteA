/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#include "test-prng-stub.c.h"
#include "../test-utils.c.h"

// Expects: PKC_CtAlgo, MSGMAX, params.

#define PKC_Sign                                \
    ((PKSignFunc_t)(PKC_CtAlgo(PKSignFunc)))

#define PKC_Verify                                      \
    ((PKVerifyFunc_t)(PKC_CtAlgo(PKVerifyFunc)))

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

    for(int i=0; i<testcount; i++)
    {
        printf("\t""test %d of %d\r", i+1, testcount);
        fflush(NULL);

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
    }

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    free(enx);
    free(dex);
    free(kgx);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
