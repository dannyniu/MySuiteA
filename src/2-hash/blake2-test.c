/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "blake2.h"

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
    
    intptr_t (*h)(int) = iBLAKE2b256;

    mysrand(time(NULL));
    
    if( argc < 2 ) h = iBLAKE2b256;
    else
    {
        switch( argv[1][6]<<24 | argv[1][7]<<16 | argv[1][8]<<8 | argv[1][9] )
        {
        case 0x62313630: h = iBLAKE2b160; break;
        case 0x62323536: h = iBLAKE2b256; break;
        case 0x62333834: h = iBLAKE2b384; break;
        case 0x62353132: h = iBLAKE2b512; break;
        case 0x73313238: h = iBLAKE2s128; break;
        case 0x73313630: h = iBLAKE2s160; break;
        case 0x73323234: h = iBLAKE2s224; break;
        case 0x73323536: h = iBLAKE2s256; break;
        
        default: h = iBLAKE2b256; break;
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
