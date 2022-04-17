/* DannyNiu/NJF, 2021-06-23. Public Domain. */

#undef bc
#define bc xCamellia128
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc xCamellia192
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc xCamellia256
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iCamellia128
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iCamellia192
#include "../1-symm/blockcipher-test.c.h"

#undef bc
#define bc iCamellia256
#include "../1-symm/blockcipher-test.c.h"

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;

    if( argc < 2 ) return EXIT_FAILURE;

    if( !strcmp(argv[1], "128") )
    {
        ret =
            blockcipher_test_xCamellia128() == EXIT_SUCCESS &&
            blockcipher_test_iCamellia128() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    if( !strcmp(argv[1], "192") )
    {
        ret =
            blockcipher_test_xCamellia192() == EXIT_SUCCESS &&
            blockcipher_test_iCamellia192() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    if( !strcmp(argv[1], "256") )
    {
        ret =
            blockcipher_test_xCamellia256() == EXIT_SUCCESS &&
            blockcipher_test_iCamellia256() == EXIT_SUCCESS ?
            EXIT_SUCCESS : EXIT_FAILURE;
    }

    return ret;
}
