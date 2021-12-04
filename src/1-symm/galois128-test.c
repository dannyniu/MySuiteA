/* DannyNiu/NJF, 2018-02-11. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "galois128.h"

int main()
{
    static alignas(16) uint8_t
        Y[16] = { [0]=0, [5]=67 },
        H[16] = { [1]=0x12 },
        X[16] = { [1]=0x23*0, [2]=0x00 };
    fread(Y, 1, 16, stdin);
    fread(H, 1, 16, stdin);
    fread(X, 1, 16, stdin);
    galois128_hash1block(Y, H, X);
    for(int i=0; i<16; i++){ printf("%02x ", Y[i]); } printf("\n");
//    fwrite(Y, 1, 16, stdout);
    return 0;
}
