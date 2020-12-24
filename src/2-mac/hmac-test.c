/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "hmac-sha.h"
#include "hmac-sha3.h"

#include "../test-utils.c.h"

static unsigned char buf[4096];

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;
    
    uparam_t (*h)() = NULL;
    FILE *kfp;

    mysrand((unsigned long)time(NULL));
    
    if( argc < 2 ) return 1;
    else
    {
        switch( u8cc(argv[1]) )
        {
        case u8cc("sha1"): h = iHMAC_SHA1; break;
        case u8cc("sha224"): h = iHMAC_SHA224; break;
        case u8cc("sha256"): h = iHMAC_SHA256; break;
        case u8cc("sha384"): h = iHMAC_SHA384; break;
        case u8cc("sha512"): h = iHMAC_SHA512; break;
        case u8cc("sha3_224"): h = iHMAC_SHA3_224; break;
        case u8cc("sha3_256"): h = iHMAC_SHA3_256; break;
        case u8cc("sha3_384"): h = iHMAC_SHA3_384; break;
        case u8cc("sha3_512"): h = iHMAC_SHA3_512; break;
        
        default: return 1; break;
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
    
    for(unsigned i=0; i<OUT_BYTES(h); i++) printf("%02x", buf[i]);
    return 0;
}
