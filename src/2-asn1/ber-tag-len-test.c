/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "der-codec.h"

int test_tag(void)
{
    uint8_t blob[] = { 0xff, 0x8f, 0x80, 0x11, };
    size_t length = 4;
    const uint8_t *ptr = blob;
    size_t len = length;
    uint32_t t = ber_get_tag(&ptr, &len);

    const char *expect = "e003c011 4 0";
    char actual[128];
    snprintf(actual, 128, "%08x %ld %zd", t, (long)(ptr - blob), len);
    if( strcmp(expect, actual) )
    {
        printf("t:expect: %s\n", expect);
        printf("t:actual: %s\n", actual);
        return EXIT_FAILURE;
    }
    else return EXIT_SUCCESS;
}

int test_len(void)
{
    uint8_t blob[] = { 0x12, 0x11, 0x22, 0x33, 0x44, 0x56, 0x78, };
    size_t length = 4;
    const uint8_t *ptr = blob;
    size_t len = length;
    size_t t = ber_get_len(&ptr, &len);

    const char *expect = "00000012 1 3";
    char actual[128];
    snprintf(actual, 128, "%08zx %ld %zd", t, (long)(ptr - blob), len);
    if( strcmp(expect, actual) )
    {
        printf("t:expect: %s\n", expect);
        printf("t:actual: %s\n", actual);
        return EXIT_FAILURE;
    }
    else return EXIT_SUCCESS;
}

int main()
{
    return
        test_tag() == EXIT_SUCCESS &&
        test_len() == EXIT_SUCCESS ?
        EXIT_SUCCESS : EXIT_FAILURE;
}
