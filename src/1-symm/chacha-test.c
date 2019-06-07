/* DannyNiu/NJF, 2018-02-10. Public Domain. */

#include <stdalign.h>
#include <stdio.h>
#include "chacha.h"

int main()
{
    static alignas(4) uint8_t key[32];
    static alignas(4) uint8_t nonce[12] = { [3] = 0x09, [7] = 0x4a, };
    static alignas(4) uint8_t out[64];
    static uint32_t state[16];
    int i;

    puts("Check output against test vectors in RFC8439 section 2.3.2.");
    for(i=0; i<32; i++) key[i] = i;

    chacha_word_set_state(state, key, nonce);
    chacha_word_block(state, 1, 64, NULL, out);

    for(i=0; i<64; i++) {
        printf("%02x ", out[i]);
        if( i%16 == 15 ) printf("\n");
    }
    printf("\n");
}
