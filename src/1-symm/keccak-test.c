/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "keccak.h"

static _Alignas(uint64_t) uint8_t state[200] = { [0] = 0x06, [135] = 0x80 };

int main()
{
    KeccakF1600_Permute(state, state);
    for(int i=0; i<200; i++) {
        printf("%02x ", state[i]);
        if( i % 16 == 15 ) printf("\n");
    }
    printf("\n");
    return 0;
}
