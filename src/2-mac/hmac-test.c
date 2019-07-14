/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include "hmac-sha.h"
#include <stdio.h>
#include <string.h>

static unsigned long a, b;
#define p 65521UL

void mysrand(unsigned long);
unsigned long myrand(void);

void mysrand(unsigned long x) { a = b = x % p; }
unsigned long myrand(void) {
    unsigned long x, y;
    x = a*a + p*p - b*b;
    x %= p;
    y = 2 * a * b;
    y %= p;
    a = x;
    b = y;
    return x;
}

static unsigned char buf[256*(p/256+1)];

typedef void (*Hmac_Init_Func)(
    void *restrict,
    const void *restrict,
    size_t);

const static struct {
    const char *name;
    Hmac_Init_Func func;
    size_t taglen;
} hashlist[] =
{
    { "sha1", (Hmac_Init_Func)HMAC_SHA1_Init, 20, }, 
    { "sha224", (Hmac_Init_Func)HMAC_SHA224_Init, 28, }, 
    { "sha256", (Hmac_Init_Func)HMAC_SHA256_Init, 32, }, 
    { "sha384", (Hmac_Init_Func)HMAC_SHA384_Init, 48, }, 
    { "sha512", (Hmac_Init_Func)HMAC_SHA512_Init, 64, }, 
    { "sha3-224", (Hmac_Init_Func)HMAC_SHA3_224_Init, 28, }, 
    { "sha3-256", (Hmac_Init_Func)HMAC_SHA3_256_Init, 32, }, 
    { "sha3-384", (Hmac_Init_Func)HMAC_SHA3_384_Init, 48, }, 
    { "sha3-512", (Hmac_Init_Func)HMAC_SHA3_512_Init, 64, }, 
    { NULL, NULL, 0, }, 
}, *hashinfo = hashlist + 0;

int main(int argc, char *argv[])
{
    union {
        HMAC_SHA1_t hmac_sha1;
        HMAC_SHA224_t hmac_sha224;
        HMAC_SHA256_t hmac_sha256;
        HMAC_SHA384_t hmac_sha384;
        HMAC_SHA512_t hmac_sha512;
        HMAC_SHA3_224_t hmac_sha3_224;
        HMAC_SHA3_256_t hmac_sha3_256;
        HMAC_SHA3_384_t hmac_sha3_384;
        HMAC_SHA3_512_t hmac_sha3_512;
    } hmac;
    
    FILE *kfp, *mfp;
    unsigned i; size_t l;

    if( argc < 2 ) return 1;
    
    kfp = fopen("hmac-test-key", "rb");
    mfp = fopen("hmac-test-data", "rb");

    for(; hashinfo->name; hashinfo++) {
        if( strcmp(hashinfo->name, argv[1]) ) continue;

        hashinfo->func(&hmac, buf, fread(buf, 1, 1024, kfp));
        fclose(kfp); kfp = NULL;
        break;
    }

    if( !hashinfo->name ) {
        printf("algo-unrecogized\n");
        return 1;
    }

    while( (l = fread(buf, 1, myrand()+1, mfp)) > 0 )
    {
        HMAC_Update((void *)&hmac, buf, l);
    }

    HMAC_Final((void *)&hmac, buf, hashinfo->taglen);
    for(i=0; i<hashinfo->taglen; i++) printf("%02x", buf[i]);

    return 0;
}
