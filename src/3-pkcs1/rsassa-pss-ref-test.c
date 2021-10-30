/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsassa-pss.h"
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
    if( argc < 2 )
    {
        fprintf(stderr, "Missing message input.\n");
        return 1;
    }
    
    IntPtr lret;
    size_t size;

    PKCS1_Codec_Aux_t ap = {
        .aux_po = {
            [0] = { .info = iSHA256, .param = NULL, },
            [1] = { .info = iSHA256, .param = NULL, },
            [2] = { .info = NULL, .aux = 32, },
        },
    };

    PKCS1_Pub_Ctx_Hdr_t *enx = NULL;
    void *copy;

    FILE *fp = fopen("../tests/rsa-1440-pub.der", "rb"); // in "tests/"
    fseek(fp, 0, SEEK_END);
    lret = ftell(fp);
    copy = malloc(lret);
    rewind(fp);
    fread(copy, 1, lret, fp);
    fclose(fp);

    size = lret;
    lret = PKCS1_Decode_RSAPublicKey(1, copy, size, NULL, &ap);
    if( lret < 0 )
    {
        perror("pubkey-decode 1");
        exit(EXIT_FAILURE);
    }
    enx = malloc(lret);
    PKCS1_Decode_RSAPublicKey(2, copy, size, enx, &ap);
    free(copy); copy = NULL;

    int exitstat = 0;
    
    copy = malloc(NBITS / 8);

    if( !copy )
    {
        perror("malloc 3");
        exit(EXIT_FAILURE);
    }

    fread(copy, 1, NBITS / 8, stdin);
    RSASSA_PSS_Decode_Signature(enx, copy, NBITS / 8);
        
    lret = (IntPtr)RSASSA_PSS_Verify(enx, argv[1], strlen(argv[1]));
    if( !lret )
    {
        printf("Reference Testing Failed Once, (%zd)%s\n",
               strlen(argv[1]), argv[1]);
        exitstat = 1;
    }

    free(copy);
    free(enx);
    return exitstat;
}
