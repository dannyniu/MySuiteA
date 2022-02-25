/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "test-prng-stub.c.h"
#include "../test-utils.c.h"

// Expects: PKC_Algo_Prefix, SSLEN, params, {kgx,enx}_{decl,init}.

#define PKC_Enc                 glue(PKC_Algo_Prefix,_Enc)
#define PKC_Dec                 glue(PKC_Algo_Prefix,_Dec)
#define PKC_Encode_Ciphertext   glue(PKC_Algo_Prefix,_Encode_Ciphertext)
#define PKC_Decode_Ciphertext   glue(PKC_Algo_Prefix,_Decode_Ciphertext)

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

    size_t sslen = SSLEN;
    void *ss1 = malloc(sslen);
    void *ss2 = malloc(sslen);

    //dumphex(dex, 1328);
    //dumphex(&enx.header, 780);

    for(int i=1; i<=testcount; i++)
    {
        printf("\t""test %d of %d\r", i, testcount);
        fflush(NULL);

        PKC_Enc(
            &enx.header, ss1, &sslen,
            (GenFunc_t)Gimli_XOF_Read, &gx);
        PKC_Encode_Ciphertext(&enx.header, NULL, &size);

        if( !copy ) copy = malloc(size);

        if( !copy )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }

        PKC_Encode_Ciphertext(&enx.header, copy, &size);
        PKC_Decode_Ciphertext(dex, copy, size);

        lret = (IntPtr)PKC_Dec(dex, ss2, &sslen);
        if( memcmp(ss1, ss2, sslen) || !lret )
        {
            printf("Cipher Failure, %zd, %ld\n", sslen, (long)lret);
            printf("seed: %s\n", argv[1]);
            failures ++;
        }
    }

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
