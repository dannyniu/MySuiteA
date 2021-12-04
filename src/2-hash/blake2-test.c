/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include "blake2.h"

#include "../test-utils.c.h"

static unsigned char buf[4096];

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;

    iCryptoObj_t h = iBLAKE2b256;

    mysrand((unsigned long)time(NULL));
    
    if( argc < 2 ) return 1;
    else
    {
        switch( u4cc(argv[1]+6) )
        {
        case u4cc("b160"): h = iBLAKE2b160; break;
        case u4cc("b256"): h = iBLAKE2b256; break;
        case u4cc("b384"): h = iBLAKE2b384; break;
        case u4cc("b512"): h = iBLAKE2b512; break;
        case u4cc("s128"): h = iBLAKE2s128; break;
        case u4cc("s160"): h = iBLAKE2s160; break;
        case u4cc("s224"): h = iBLAKE2s224; break;
        case u4cc("s256"): h = iBLAKE2s256; break;
        
        default: return 1; break;
        }
    }

    x = malloc(CTX_BYTES(h));
    INIT_FUNC(h)(x);
    
    while( (in_len = fread(buf, 1, myrand()+1, stdin)) > 0 )
    {
        UPDATE_FUNC(h)(x, buf, in_len);
    }
    
    FINAL_FUNC(h)(x, buf, OUT_BYTES(h));
    free(x);
    x=NULL;

    for(int i=0; i<OUT_BYTES(h); i++) { printf("%02x", buf[i]); } printf("\n");
    return 0;
}
