/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-rsa/rsa-codec-der.h"
#include "../2-hash/sha.h"

#include "../test-utils.c.h"
#include "../2-xof/gimli-xof.h"
static gimli_xof_t gx;

#define NBITS 768
#define SSLEN 16

#define PKC_CtAlgo iRSAES_OAEP_CtCodec

#define PKC_Enc                                 \
    ((PKEncFunc_t)(PKC_CtAlgo(PKEncFunc)))

#define PKC_Dec                                 \
    ((PKDecFunc_t)(PKC_CtAlgo(PKDecFunc)))

#define PKC_Encode_Ciphertext                           \
    ((PKCiphergramEncoder_t)(PKC_CtAlgo(PKCtEncoder)))

#define PKC_Decode_Ciphertext                           \
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

#include "test-api-test.c.h"

    printf("tests start\n");
    
    int failures = 0;
    int testcount = 80 / 5;
    
    size_t sslen = SSLEN;
    void *ss1 = malloc(sslen);
    void *ss2 = malloc(sslen);

    for(int i=0; i<testcount; i++)
    {
        printf("\t""test %d of %d\r", i+1, testcount);
        fflush(NULL);

        PKC_Enc(enx, ss1, &sslen, (GenFunc_t)Gimli_XOF_Read, &gx);
        PKC_Encode_Ciphertext(enx, NULL, &size);

        if( !copy ) copy = malloc(size);

        if( !copy )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }

        PKC_Encode_Ciphertext(enx, copy, &size);
        PKC_Decode_Ciphertext(dex, copy, size);
        
        lret = (IntPtr)PKC_Dec(dex, ss2, &sslen);
        if( memcmp(ss1, ss2, sslen) || !lret )
        {
            printf("Cipher Failure, %zd, %ld\n", sslen, (long)lret);
            failures ++;
        }
    }

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    free(enx);
    free(dex);
    free(kgx);
    return 0;
}
