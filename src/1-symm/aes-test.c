/* DannyNiu/NJF, 2018-01-31. Public Domain. */

#undef bc
#define bc xAES128
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc xAES192
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc xAES256
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iAES128
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iAES192
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iAES256
#include "../1-symm/blockcipher-test.c.h"

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;

    if( argc < 2 ) return EXIT_FAILURE;

    if( !strcmp(argv[1], "128") )
    {
        ret =
            blockcipher_test_xAES128() == EXIT_SUCCESS &&
            blockcipher_test_iAES128() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    if( !strcmp(argv[1], "192") )
    {
        ret =
            blockcipher_test_xAES192() == EXIT_SUCCESS &&
            blockcipher_test_iAES192() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    if( !strcmp(argv[1], "256") )
    {
        ret =
            blockcipher_test_xAES256() == EXIT_SUCCESS &&
            blockcipher_test_iAES256() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    return ret;
}
