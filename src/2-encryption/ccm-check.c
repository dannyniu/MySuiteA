/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#include "ccm-aes.h"
#include "../test-utils.c.h"

static uint8_t k[32], iv[16], a[32], p[1024], c[1024], s[16], t[16], x[1024];
static size_t len, clen, alen, klen, ivlen, tlen;
static int pass = true;

static ccm_aes256_t ccm;

static int vflushed = false;

static const char *vname;

void PrintIf(intmax_t cond, const char *fmt, ...)
{
    va_list ap;

    if( !cond ) return;
    else if( !pass ) return;
    va_start(ap, fmt);

    if( !vflushed )
    {
        printf("%s\n", vname);
        vflushed = true;
    }

    vprintf(fmt, ap);
}

#define out2(...) printf(__VA_ARGS__)

int main()
{
    unsigned i;
    uint8_t *ptr = NULL;
    iCryptoObj_t aead = iCCM_AES128;

    aead=iCCM_AES128;
    vname = "CCM-AES-128";

    len = 4;
    alen = 8;
    ivlen = 7;
    tlen = 4;
    for(i=0; i<16; i++) k[i] = 0x40 + i;
    for(i=0; i<ivlen; i++) iv[i] = 0x10 + i;
    for(i=0; i<alen; i++) a[i] = 0x00 + i;
    for(i=0; i<len; i++) p[i] = 0x20 + i;
    (void)klen;

    clen = 8;
    c[0] = 0x71;
    c[1] = 0x62;
    c[2] = 0x01;
    c[3] = 0x5b;
    c[4] = 0x4d;
    c[5] = 0xac;
    c[6] = 0x25;
    c[7] = 0x5d;

    KINIT_FUNC(aead)(
        &ccm, k, KEY_BYTES(aead));
    AENC_FUNC(aead)(
        (void *)&ccm, ivlen, iv, alen, a, len, p, x, tlen, s);
    PrintIf(memcmp(s, c+len, tlen), "Enc Fail: Tag Wrong!\n");
    PrintIf(memcmp(c, x, len),"Enc Fail: Ciphertext Wrong!\n");
    ptr = ADEC_FUNC(aead)(
        (void *)&ccm, ivlen, iv, alen, a, len, c, x, tlen, c+len);
    PrintIf(!ptr, "Dec Errornously Returned FAIL\n");
    PrintIf(memcmp(p, x, len), "Dec Fail: Plaintext Wrong!\n");

    if( alen && pass ) {
        ptr = ADEC_FUNC(aead)(
            (void *)&ccm, ivlen, iv, alen-1, a+1, len, c, x, tlen, t);
        PrintIf((intmax_t)ptr ,"Dec Errornously Secceeded!\n");
    }

    PrintIf(vflushed, "Test Over\n");
    return vflushed ? EXIT_FAILURE : EXIT_SUCCESS;
}
