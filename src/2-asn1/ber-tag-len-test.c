/* DannyNiu/NJF, 2021-02-12. Public Domain. */

#include "der-codec.h"
#include <stdio.h>

void test_tag(void)
{
    uint8_t blob[] = { 0xff, 0x8f, 0x80, 0x11, };
    size_t length = 4;
    const uint8_t *ptr = blob;
    size_t len = length;
    uint32_t t = ber_get_tag(&ptr, &len);
    printf("t:expected: e003c011 4 0\n");
    printf("t:actual:   %08x %ld %zd\n", t, ptr - blob, len);
}

void test_len(void)
{
    uint8_t blob[] = { 0x12, 0x11, 0x22, 0x33, 0x44, 0x56, 0x78, };
    size_t length = 4;
    const uint8_t *ptr = blob;
    size_t len = length;
    size_t t = ber_get_len(&ptr, &len);
    printf("l:actual:   %08zx %ld %zd\n", t, ptr - blob, len);
}

int main()
{
    test_tag();
    test_len();
    return 0;
}
