/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#include "test-prng-stub.c.h"
#include "../test-utils.c.h"

// Expects: PKC_CtAlgo, SSLEN, params.

#define PKC_Enc                                 \
    ((PKEncFunc_t)(PKC_CtAlgo(PKEncFunc)))

#define PKC_Dec                                 \
    ((PKDecFunc_t)(PKC_CtAlgo(PKDecFunc)))

#define PKC_Encode_Ciphertext                           \
    ((PKCiphergramEncoder_t)(PKC_CtAlgo(PKCtEncoder)))

#define PKC_Decode_Ciphertext                           \
    ((PKCiphergramDecoder_t)(PKC_CtAlgo(PKCtDecoder)))

#define PKC_Keygen                                      \
    ((PKKeygenFunc_t)(PKC_KeyAlgo(PKKeygenFunc)))

#define PKC_Encode_PrivateKey                           \
    ((PKKeyEncoder_t)(PKC_KeyAlgo(PKPrivkeyEncoder)))

#define PKC_Decode_PrivateKey                           \
    ((PKKeyDecoder_t)(PKC_KeyAlgo(PKPrivkeyDecoder)))

#define PKC_Export_PublicKey                            \
    ((PKKeyEncoder_t)(PKC_KeyAlgo(PKPubkeyExporter)))

#define PKC_Encode_PublicKey                            \
    ((PKKeyEncoder_t)(PKC_KeyAlgo(PKPubkeyEncoder)))

#define PKC_Decode_PublicKey                            \
    ((PKKeyDecoder_t)(PKC_KeyAlgo(PKPubkeyDecoder)))

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
    
    size_t sslen = SSLEN;
    void *ss1 = malloc(sslen);
    void *ss2 = malloc(sslen);

    for(int i=0; i<testcount; i++)
    {
        printf("\t""test %d of %d\r", i+1, testcount);
        fflush(NULL);

#ifdef PKC_Prologue
        PKC_Prologue();
#endif /* PKC_Epilogue */
        
        PKC_Enc(enx, ss1, &sslen, PKC_PRNG_Gen, prng);
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
        
#ifdef PKC_Epilogue
        PKC_Epilogue();
#endif /* PKC_Epilogue */
    }

    printf("\n%d of %d tests failed\n", failures, testcount);
    free(copy);
    free(enx);
    free(dex);
    free(kgx);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
