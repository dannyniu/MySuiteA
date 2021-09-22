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

    PKCS1_Private_Param_t params = PKCS1_PRIVATE_PARAM_ENTUPLE(
        NBITS,2,iSHA256,iSHA256,32);

    PKCS1_Codec_Aux_t ap = {
        .aux_po = PKCS1_PADDING_ORACLES_PARAM_ENTUPLE(
            iSHA256,iSHA256,32),
    };
    
    PKCS1_Private_Context_t *kgx = NULL;

    Gimli_XOF_Init(&gx);
    Gimli_XOF_Write(&gx, "Hello World!", 12);
    if( argc >= 2 )
        Gimli_XOF_Write(&gx, argv[1], strlen(argv[1]));
    Gimli_XOF_Final(&gx);

    lret = PKCS1_Keygen(NULL, &params, NULL, NULL);
    kgx = my_alloc("kgx", lret);

    if( !kgx )
    {
        perror("malloc 1");
        exit(EXIT_FAILURE);
    }
    
    lret = PKCS1_Keygen(kgx, &params, (GenFunc_t)Gimli_XOF_Read, &gx);

    if( !lret )
    {
        perror("MySuiteA RSA Key Generation 1");
        exit(EXIT_FAILURE);
    }
    else printf("keygen.lret: %lx, %p\n", lret, kgx);

    PKCS1_Private_Context_t *dex = NULL;
    void *copy;

    // recoding private key.
    lret = PKCS1_Encode_RSAPrivateKey(1, NULL, 0, kgx, &ap);
    copy = malloc(lret);
    PKCS1_Encode_RSAPrivateKey(2, copy, lret, kgx, NULL);

    FILE *fp = fopen("./rsa-priv-768.key", "wb"); // in "bin/"
    fwrite(copy, 1, lret, fp);
    fclose(fp);

    size = lret;
    lret = PKCS1_Decode_RSAPrivateKey(1, copy, size, NULL, &ap);
    if( lret < 0 )
    {
        perror("privkey-decode 1");
        exit(EXIT_FAILURE);
    }
    dex = my_alloc("dex", lret);
    PKCS1_Decode_RSAPrivateKey(2, copy, size, dex, &ap);
    free(copy); copy = NULL;

    // transfer public key to encryption working context.
    lret = PKCS1_Encode_RSAPublicKey(1, NULL, 0, dex, NULL);
    copy = my_alloc("pubkey.der", lret);

    if( !copy )
    {
        perror("malloc 2");
        exit(EXIT_FAILURE);
    }

    PKCS1_Encode_RSAPublicKey(2, copy, lret, kgx, NULL);

    PKCS1_Public_Context_t *enx = NULL;
    size = lret;
    lret = PKCS1_Decode_RSAPublicKey(1, copy, size, NULL, &ap);
    if( lret < 0 )
    {
        perror("pubkey-decode 1");
        exit(EXIT_FAILURE);
    }
    enx = my_alloc("enx", lret);
    PKCS1_Decode_RSAPublicKey(2, copy, size, enx, &ap);
    free(copy); copy = NULL;

    printf("tests start\n");
    
    int failures = 0;
    int testcount = 80 / 5;
    
    size_t sslen = SSLEN;
    void *ss1 = malloc(sslen);
    void *ss2 = malloc(sslen);

    for(int i=0; i<testcount; i++)
    {
        printf("\t""test %d of %d\r", i+1, testcount);
        fflush(NULL);;

        RSAES_OAEP_Enc(enx, ss1, &sslen, (GenFunc_t)Gimli_XOF_Read, &gx);
        RSAES_OAEP_Encode_Ciphertext(enx, NULL, &size);

        if( !copy ) copy = malloc(size);

        if( !copy )
        {
            perror("malloc 3");
            exit(EXIT_FAILURE);
        }

        RSAES_OAEP_Encode_Ciphertext(enx, copy, &size);        
        RSAES_OAEP_Decode_Ciphertext(dex, copy, size);
        
        lret = (IntPtr)RSAES_OAEP_Dec(dex, ss2, &sslen);
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
