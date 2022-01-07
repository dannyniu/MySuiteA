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
    tCryptoObj_t m = tHMAC;
    CryptoParam_t H;
    FILE *kfp;

    mysrand((unsigned long)time(NULL));
    
    if( argc < 2 ) return EXIT_FAILURE;
    else
    {
        switch( u8cc(argv[1]) )
        {
        case u8cc("sha1"): h = iSHA1; break;
        case u8cc("sha224"): h = iSHA224; break;
        case u8cc("sha256"): h = iSHA256; break;
        case u8cc("sha384"): h = iSHA384; break;
        case u8cc("sha512"): h = iSHA512; break;
        case u8cc("sha3_224"): h = iSHA3_224; break;
        case u8cc("sha3_256"): h = iSHA3_256; break;
        case u8cc("sha3_384"): h = iSHA3_384; break;
        case u8cc("sha3_512"): h = iSHA3_512; break;
        
        default: return EXIT_FAILURE; break;
        }
    }

    H.info = h, H.param = NULL;

    kfp = fopen("mac-test-key", "rb");
    x = malloc(m(&H, contextBytes));
    
    ((PKInitFunc_t)m(&H, KInitFunc))(&H, x, buf, fread(buf, 1, 512, kfp));
    fclose(kfp); kfp = NULL;

    while( (in_len = fread(buf, 1, myrand()+1, stdin)) > 0 )
    {
        ((UpdateFunc_t)m(&H, UpdateFunc))(x, buf, in_len);
    }

    ((FinalFunc_t)m(&H, FinalFunc))(x, buf, OUT_BYTES(h));
    free(x);
    x = NULL;
    
    for(int i=0; i<OUT_BYTES(h); i++) printf("%02x", buf[i]);
    return EXIT_SUCCESS;
}
