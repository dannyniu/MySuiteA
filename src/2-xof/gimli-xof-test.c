/* DannyNiu/NJF, 2018-04-20. Public Domain. */

#include "gimli-xof.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const char *test =
    "There's plenty for the both of us, may the best Dwarf win.";

int main()
{
    gimli_xof_t gh;
    uint8_t out[16];
    int i;

    Gimli_XOF_Init(&gh);
    Gimli_XOF_Write(&gh, test, strlen(test));
    Gimli_XOF_Final(&gh);
    
    Gimli_XOF_Read(&gh, out, 16);
    for(i=0; i<16; i++) printf("%02"PRIx8, out[i]);
    Gimli_XOF_Read(&gh, out, 16);
    for(i=0; i<16; i++) printf("%02"PRIx8, out[i]);
    puts("");

    return 0;
}
