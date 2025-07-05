/* DannyNiu/NJF, 2025-06-22. Public Domain. */

#include "rsa-privkey-der-from-jwk.c"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../test-utils.c.h"

static const char *oth =
    "[{ \"r\": \"ABCDEFGHIJKLMNOP\",  "
    "   \"d\": \"QRSTUVWXUZabcdef\",  "
    "   \"t\": \"ghijklmnopqrstuv\" },"
    " { \"r\": \"wxyz0123456789-_\",  "
    "   \"t\": \"ABCDEFGHIJKLMNOP\",  "
    "   \"d\": \"QRSTUVWXUZabcdef\" }]";

int main()
{
    json_io_t jstr = { .str = oth, .limit = strlen(oth) };
    uint8_t *enc = NULL;
    IntPtr subret = 0;
    subret = OtherPrimeInfos_FromJsonArray(jstr, enc, subret);
    enc = calloc(1, subret);
    subret = OtherPrimeInfos_FromJsonArray(jstr, enc, subret);
    if( isatty(STDOUT_FILENO) )
        dumphex(enc, subret);
    else fwrite(enc, 1, subret, stdout);
    return EXIT_SUCCESS;
}
