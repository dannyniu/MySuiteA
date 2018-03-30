/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sha.h"
#include "sha3.h"
#include "../2-xof/shake.h"

// Call-once-wrong-ever-since. 

void SHA3_128000_Final(void *restrict x, void *restrict out)
{ SHAKE_Final(x), SHAKE_Read(x, out, 168); }

void SHA3_256000_Final(void *restrict x, void *restrict out)
{ SHAKE_Final(x), SHAKE_Read(x, out, 136); }

intptr_t iSHA3_128000(int q){
    return (
        q==outBytes ? 168 :
        q==blockBytes ? 168 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (intptr_t)SHAKE128_Init :
        q==UpdateFunc ? (intptr_t)SHAKE_Write :
        q==FinalFunc  ? (intptr_t)SHA3_128000_Final :
        -1);
}

intptr_t iSHA3_256000(int q){
    return (
        q==outBytes ? 136 :
        q==blockBytes ? 136 :
        q==contextBytes ? sizeof(struct shake_context) :
        q==InitFunc   ? (intptr_t)SHAKE256_Init :
        q==UpdateFunc ? (intptr_t)SHAKE_Write :
        q==FinalFunc  ? (intptr_t)SHA3_256000_Final :
        -1);
}

static unsigned long a, b;
static const unsigned long p = 65521;

void mysrand(long x) { a = b = x % p; }
long myrand() {
    int x, y;
    x = a*a + p*p - b*b;
    x %= p;
    y = 2 * a * b;
    y %= p;
    a = x, b = y;
    return x;
}

static unsigned char buf[256*(p/256+1)];

int main(int argc, char *argv[])
{
    ssize_t in_len = -1;
    void *x = NULL;
    
    intptr_t (*h)(int) = iSHA1;

    mysrand(time(NULL));
    
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
    free(x), x=NULL;

    for(int i=0; i<OUT_BYTES(h); i++) { printf("%02x", buf[i]); } printf("\n");
    return 0;
}
