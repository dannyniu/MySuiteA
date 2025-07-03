/* DannyNiu/NJF, 2025-06-22. Public Domain. */

#include "pkc-xfmt.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../test-utils.c.h"

static const char *b64u = "\"________________\"";

int main()
{
    json_io_t jstr = { .str = b64u, .limit = strlen(b64u), };
    uint8_t *enc = NULL;
    IntPtr subret = 0;
    subret = BERIntegerFromBase64URL(jstr, enc, subret);
    enc = calloc(1, subret);
    subret = BERIntegerFromBase64URL(jstr, enc, subret);
    if( isatty(STDOUT_FILENO) )
        dumphex(enc, subret);
    else fwrite(enc, 1, subret, stdout);
    return EXIT_SUCCESS;
}
