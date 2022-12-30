/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include "hmac-sha.h"
#include "hmac-sha3.h"

#include "../test-utils.c.h"

static unsigned char buf[4096];

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;

    iCryptoObj_t h = NULL;
    FILE *kfp;

    mysrand((unsigned long)time(NULL));

    if( argc < 2 ) return EXIT_FAILURE;
    else
    {
        struct { uint64_t hid; iCryptoObj_t obj; } htab[] = {
            { u8cc("sha1"), iHMAC_SHA1 },
            { u8cc("sha224"), iHMAC_SHA224 },
            { u8cc("sha256"), iHMAC_SHA256 },
            { u8cc("sha384"), iHMAC_SHA384 },
            { u8cc("sha512"), iHMAC_SHA512 },
            { u8cc("sha3_224"), iHMAC_SHA3_224 },
            { u8cc("sha3_256"), iHMAC_SHA3_256 },
            { u8cc("sha3_384"), iHMAC_SHA3_384 },
            { u8cc("sha3_512"), iHMAC_SHA3_512 },
            { 0, NULL }
        };

        uint64_t id = u8cc(argv[1]);
        int i;

        for(i=0; htab[i].obj; i++)
        {
            if( id == htab[i].hid ) break;
        }

        if( !htab[i].obj ) return EXIT_FAILURE;
        else h = htab[i].obj;
    }

    kfp = fopen("mac-test-key", "rb");
    x = malloc(CTX_BYTES(h));

    KINIT_FUNC(h)(x, buf, fread(buf, 1, 512, kfp));
    fclose(kfp); kfp = NULL;

    while( (in_len = fread(buf, 1, myrand()+1, stdin)) > 0 )
    {
        UPDATE_FUNC(h)(x, buf, in_len);
    }

    FINAL_FUNC(h)(x, buf, OUT_BYTES(h));
    free(x);
    x = NULL;

    for(int i=0; i<OUT_BYTES(h); i++) printf("%02x", buf[i]);
    return EXIT_SUCCESS;
}
