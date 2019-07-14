/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sha.h"
#include "sha3.h"
#include "../2-xof/shake.h"

// Call-once-wrong-ever-since. 

void SHA3_128000_Final(void *restrict x, void *restrict out);
void SHA3_128000_Final(void *restrict x, void *restrict out)
{ SHAKE_Final(x); SHAKE_Read(x, out, 168); }

void SHA3_256000_Final(void *restrict x, void *restrict out);
void SHA3_256000_Final(void *restrict x, void *restrict out)
{ SHAKE_Final(x); SHAKE_Read(x, out, 136); }

uintptr_t iSHA3_128000(int q);
uintptr_t iSHA3_128000(int q){
    return (
        q==outBytes ? 168 :
        q==blockBytes ? 168 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (uintptr_t)SHAKE128_Init :
        q==UpdateFunc ? (uintptr_t)SHAKE_Write :
        q==FinalFunc  ? (uintptr_t)SHA3_128000_Final :
        0);
}

uintptr_t iSHA3_256000(int q);
uintptr_t iSHA3_256000(int q){
    return (
        q==outBytes ? 136 :
        q==blockBytes ? 136 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (uintptr_t)SHAKE256_Init :
        q==UpdateFunc ? (uintptr_t)SHAKE_Write :
        q==FinalFunc  ? (uintptr_t)SHA3_256000_Final :
        0);
}

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

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;
    
    uintptr_t (*h)(int) = iSHA1;

    mysrand((unsigned long)time(NULL));
    
    if( argc < 2 ) h = iSHA1;
    else
    {
        switch( atoi(argv[1]) )
        {
        case 224: h = iSHA224; break;
        case 256: h = iSHA256; break;
        case 384: h = iSHA384; break;
        case 512: h = iSHA512; break;
        case 3224: h = iSHA3_224; break;
        case 3256: h = iSHA3_256; break;
        case 3384: h = iSHA3_384; break;
        case 3512: h = iSHA3_512; break;
        case 3128000: h = iSHA3_128000; break;
        case 3256000: h = iSHA3_256000; break;
        
        default: h = iSHA1; break;
        }
    }

    x = malloc(CTX_BYTES(h));
    INIT_FUNC(h)(x);
    while( (in_len = fread(buf, 1, myrand()+1, stdin)) > 0 )
    {
        UPDATE_FUNC(h)(x, buf, in_len);
    }
    FINAL_FUNC(h)(x, buf);
    free(x);
    x=NULL;

    for(unsigned i=0; i<OUT_BYTES(h); i++) { printf("%02x", buf[i]); } printf("\n");
    return 0;
}
