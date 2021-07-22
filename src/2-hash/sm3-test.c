/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sm3.h"

#include "../test-utils.c.h"

static unsigned char buf[4096];

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;

    iCryptoObj_t h = iSM3;

    mysrand((unsigned long)time(NULL));
    
    argc = 0, argv = NULL; // To silence the unused argument warning.
    
    x = malloc(CTX_BYTES(h));
    INIT_FUNC(h)(x);
    
    while( (in_len = fread(buf, 1, myrand()+1, stdin)) > 0 )
    {
        UPDATE_FUNC(h)(x, buf, in_len);
    }
    
    FINAL_FUNC(h)(x, buf, OUT_BYTES(h));
    free(x);
    x = NULL;

    for(int i=0; i<OUT_BYTES(h); i++) printf("%02x", buf[i]);
    return 0;
}
