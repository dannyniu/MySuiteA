/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#include "test-prng-stub.c.h"
#include "../test-utils.c.h"

// Expects: PKC_Algo_Prefix, MSGMAX, params, {kgx,enx}_{decl,init}.

#define PKC_Sign                glue(PKC_Algo_Prefix,_Sign)
#define PKC_Verify              glue(PKC_Algo_Prefix,_Verify)
#define PKC_Encode_Signature    glue(PKC_Algo_Prefix,_Encode_Signature)
#define PKC_Decode_Signature    glue(PKC_Algo_Prefix,_Decode_Signature)

void *my_alloc(const char *s, size_t len)
{
    printf("my_alloc: %s: %zd bytes\n", s, len);
    return malloc(len);
}

int main(int argc, char *argv[])
{
    IntPtr lret;
    size_t size;

#include "test-self-fed-keycpy.c.h"

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

#ifdef PKC_Prologue
        PKC_Prologue();
#endif /* PKC_Epilogue */

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
        PKC_Decode_Signature(&enx.header, copy, size);

        lret = (IntPtr)PKC_Verify(&enx.header, msg, msglen);
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

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
