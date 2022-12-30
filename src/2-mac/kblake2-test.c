/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include "../2-hash/blake2.h"

#include "../test-utils.c.h"

static unsigned char buf[4096];

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;

    iCryptoObj_t h = NULL;
    FILE *kfp;

    if( argc < 2 ) return EXIT_FAILURE;
    else
    {
        struct { uint64_t hid; iCryptoObj_t obj; } htab[] = {
            { u4cc("b160"), ikBLAKE2b160 },
            { u4cc("b256"), ikBLAKE2b256 },
            { u4cc("b384"), ikBLAKE2b384 },
            { u4cc("b512"), ikBLAKE2b512 },
            { u4cc("s128"), ikBLAKE2s128 },
            { u4cc("s160"), ikBLAKE2s160 },
            { u4cc("s224"), ikBLAKE2s224 },
            { u4cc("s256"), ikBLAKE2s256 },
            { 0, NULL }
        };

        uint64_t id = u4cc(argv[1]+6);
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
