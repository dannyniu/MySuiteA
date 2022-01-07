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
        switch( u4cc(argv[1]+6) )
        {
        case u4cc("b160"): h = ikBLAKE2b160; break;
        case u4cc("b256"): h = ikBLAKE2b256; break;
        case u4cc("b384"): h = ikBLAKE2b384; break;
        case u4cc("b512"): h = ikBLAKE2b512; break;
        case u4cc("s128"): h = ikBLAKE2s128; break;
        case u4cc("s160"): h = ikBLAKE2s160; break;
        case u4cc("s224"): h = ikBLAKE2s224; break;
        case u4cc("s256"): h = ikBLAKE2s256; break;
        
        default: return EXIT_FAILURE; break;
        }
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
