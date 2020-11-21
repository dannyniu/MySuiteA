/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sha.h"
#include "sha3.h"
#include "../2-xof/shake.h"

#include "../test-utils.c.h"

// Call-once-wrong-ever-since test stubs. 

void SHA3_128000_Final(void *restrict x, void *restrict out, size_t t)
{ SHAKE_Final(x); SHAKE_Read(x, out, t); }

void SHA3_256000_Final(void *restrict x, void *restrict out, size_t t)
{ SHAKE_Final(x); SHAKE_Read(x, out, t); }

uintmax_t iSHA3_128000(int q){
    return (
        q==outBytes ? 256 :
        q==blockBytes ? 168 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (uintmax_t)SHAKE128_Init :
        q==UpdateFunc ? (uintmax_t)SHAKE_Write :
        q==FinalFunc  ? (uintmax_t)SHA3_128000_Final :
        0);
}

uintmax_t iSHA3_256000(int q);
uintmax_t iSHA3_256000(int q){
    return (
        q==outBytes ? 256 :
        q==blockBytes ? 136 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (uintmax_t)SHAKE256_Init :
        q==UpdateFunc ? (uintmax_t)SHAKE_Write :
        q==FinalFunc  ? (uintmax_t)SHA3_256000_Final :
        0);
}

static unsigned char buf[4096];

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;
    
    uintmax_t (*h)() = NULL;

    mysrand((unsigned long)time(NULL));
    
    if( argc < 2 ) return 1;
    else
    {
        switch( u8cc(argv[1]) )
        {
        case u8cc("sha1"): h = iSHA1; break;
        case u8cc("sha224"): h = iSHA224; break;
        case u8cc("sha256"): h = iSHA256; break;
        case u8cc("sha384"): h = iSHA384; break;
        case u8cc("sha512"): h = iSHA512; break;
        case u8cc("sha3-224"): h = iSHA3_224; break;
        case u8cc("sha3-256"): h = iSHA3_256; break;
        case u8cc("sha3-384"): h = iSHA3_384; break;
        case u8cc("sha3-512"): h = iSHA3_512; break;
        case u8cc("shake128"): h = iSHA3_128000; break;
        case u8cc("shake256"): h = iSHA3_256000; break;
        
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
    x = NULL;

    for(unsigned i=0; i<OUT_BYTES(h); i++) printf("%02x", buf[i]);
    return 0;
}
