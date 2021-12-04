/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-rsa/rsa-codec-der.h"
#include "../2-hash/sha.h"

#include "../test-utils.c.h"

#define NBITS 1440

void *my_alloc(const char *s, size_t len)
{
    printf("my_alloc: %s: %zd bytes\n", s, len);
    return malloc(len);
}

int main(int argc, char *argv[])
{
    IntPtr lret;
    size_t size;

    PKCS1_RSA_Param_t params = {
        [0] = { .info = iSHA256, .param = NULL, },
        [1] = { .info = iSHA256, .param = NULL, },
        [2] = { .info = NULL, .aux = 32, },
        [3] = { .info = NULL, .aux = NBITS, },
        [4] = { .info = NULL, .aux = 2, },
    };

    PKCS1_Priv_Ctx_Hdr_t *dex = NULL;
    void *copy;

    FILE *fp = fopen("../tests/rsa-1440-3primes.der", "rb"); // in "tests/"
    fseek(fp, 0, SEEK_END);
    lret = ftell(fp);
    copy = malloc(lret);
    rewind(fp);
    fread(copy, 1, lret, fp);
    fclose(fp);

    size = lret;
    lret = PKCS1_Decode_RSAPrivateKey(NULL, copy, size, params);
    if( lret < 0 )
    {
        perror("privkey-decode 1");
        exit(EXIT_FAILURE);
    }
    dex = malloc(lret);
    PKCS1_Decode_RSAPrivateKey(dex, copy, size, params);
    free(copy); copy = NULL;

    int exitstat = 0;
    
    size_t sslen = 0;
    void *ss = NULL;

    copy = malloc(NBITS / 8);

    if( !copy )
    {
        perror("malloc 3");
        exit(EXIT_FAILURE);
    }

    fread(copy, 1, NBITS / 8, stdin);
    RSAES_OAEP_Decode_Ciphertext(dex, copy, NBITS / 8);
        
    lret = (IntPtr)RSAES_OAEP_Dec(dex, NULL, &sslen);
    if( !lret )
    {
        printf("Decryption Failure. \n");
        exitstat = 1;
    }

    ss = realloc(ss, sslen);
    RSAES_OAEP_Dec(dex, ss, &sslen);
    
    if( argc < 2 || strncmp(ss, argv[1], sslen) )
    {
        printf("Reference Testing Failed Once, (ss=%zd,arg=%zd)%s\n",
               sslen, strlen(argv[1]), argv[1]);
        exitstat = 1;
    }

    free(copy);
    free(dex);
    return exitstat;
}
