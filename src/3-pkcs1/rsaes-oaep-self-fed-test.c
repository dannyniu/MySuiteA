/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-rsa/rsa-codec-der.h"
#include "../2-hash/sha.h"

#include "../test-utils.c.h"
#include "../2-xof/gimli-xof.h"
static gimli_xof_t gx;

#define NBITS 768
#define SSLEN 16

void *my_alloc(const char *s, size_t len)
{
    printf("my_alloc: %s: %zd bytes\n", s, len);
    return malloc(len);
}

int main(int argc, char *argv[])
{
    IntPtr lret;
    size_t size;

#include "test-self-fed-test.c.h"

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

        RSAES_OAEP_Enc(
            &enx.header, ss1, &sslen,
            (GenFunc_t)Gimli_XOF_Read, &gx);
        RSAES_OAEP_Encode_Ciphertext(&enx.header, NULL, &size);

        if( !copy ) copy = malloc(size);

        if( !copy )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }

        RSAES_OAEP_Encode_Ciphertext(&enx.header, copy, &size);
        RSAES_OAEP_Decode_Ciphertext(dex, copy, size);

        lret = (IntPtr)RSAES_OAEP_Dec(dex, ss2, &sslen);
        if( memcmp(ss1, ss2, sslen) || !lret )
        {
            printf("Cipher Failure, %zd, %ld\n", sslen, (long)lret);
            printf("seed: %s\n", argv[1]);
            failures ++;
        }
    }

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    return 0;
}