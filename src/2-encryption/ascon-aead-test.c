/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#include "ascon-aead.h"
#include "../test-utils.c.h"

static char line[128], word[128];
static uint8_t k[32], iv[16], a[32], p[1024], c[1024], s[16], t[16], x[1024];
static size_t len, clen, alen, klen, ivlen, tlen;

static ascon_aead_t actx;

static int vflushed = false, vflushed_saved = false;

static const char *vname;
static long tested, fails;

void PrintIf(intmax_t cond, const char *fmt, ...)
{
    va_list ap;

    if( !cond ) return;

    if( !vflushed && !vflushed_saved )
    {
        //printf("%s\n", vname);
    }

    vflushed = true;

    // 2022-05-23:
    // linter detected a problem
    // involving variadic arguments.
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

#define out2(...) (0) // printf(__VA_ARGS__)

int main(int argc, char *argv[])
{
    int i, l=-1;
    uint8_t *ptr = NULL;
    iCryptoObj_t aead = iAscon_AEAD128;

    (void)argc;
    vname = argv[1];
    // printf("%s\n", vname);
    freopen(argv[1], "r", stdin);

    while( fgets(line, sizeof(line), stdin) )
    {
        *word = '\0'; sscanf(line, "%s", word);

        if( iscntrl(*word) && l>=0 )
        {
            if( false ) {
                printf("%-5d: %zd %zd %zd %zd\n", l, alen, len, ivlen, tlen);
                dumphex(k, klen);
                dumphex(iv, ivlen);
                dumphex(a, alen);
                dumphex(p, len);
                dumphex(c, clen); }
            vflushed_saved = vflushed;
            vflushed = false;

            tested++;
            l = -1;
            (void)t;

            KINIT_FUNC(aead)(
                &actx, k, KEY_BYTES(aead));
            AENC_FUNC(aead)(
                (void *)&actx, ivlen, iv, alen, a, len, p, x, tlen, s);
            PrintIf(memcmp(s, c+len, tlen), "Enc Fail: Tag Wrong!\n");
            PrintIf(memcmp(c, x, len),"Enc Fail: Ciphertext Wrong!\n");
            ptr = ADEC_FUNC(aead)(
                (void *)&actx, ivlen, iv, alen, a, len, c, x, tlen, c+len);
            PrintIf(!ptr, "Dec Errornously Returned FAIL\n");
            PrintIf(memcmp(p, x, len), "Dec Fail: Plaintext Wrong!\n");
            c[len] ^= 1;
            ptr = ADEC_FUNC(aead)(
                (void *)&actx, ivlen, iv, alen, a, len, c, x, tlen, c+len);
            PrintIf((bool)ptr, "Dec Errornously Secceeded\n");

            PrintIf(vflushed, "Test Over\n");
            if( vflushed ) fails++;
            vflushed = vflushed_saved || vflushed;
            continue;
        }

        if( strstr(line, "len =") )
        {
            char *ent;
            if( (ent = strstr(line, "Alen")) ) sscanf(ent, "Alen = %zd", &alen);
            if( (ent = strstr(line, "Plen")) ) sscanf(ent, "Plen = %zd", &len);
            if( (ent = strstr(line, "Nlen")) ) sscanf(ent, "Nlen = %zd", &ivlen);
            if( (ent = strstr(line, "Tlen")) ) sscanf(ent, "Tlen = %zd", &tlen);
            if( len > 0 || tlen > 0 ) clen = len + tlen;
        }

        if( !strcmp(word, "Count") ) {
            sscanf(line, "%s = %d", word, &l);

            out2("Count = %d\n", l);
        }

        if( !strcmp(word, "Key") ) {
            sscanf(line, "%s = %n", word, &i);
            klen = (strlen(line) - i) / 2;
            scanhex(k, klen, line+i);
            //KINIT_FUNC(aead)(&actx, k, klen);

            if( out2("Key\n") ) dumphex(k, klen);
        }

        if( !strcmp(word, "Nonce") ) {
            sscanf(line, "%s = %n", word, &i);
            ivlen = (strlen(line) - i) / 2;
            scanhex(iv, ivlen, line+i);

            if( out2("Nonce\n") ) dumphex(iv, ivlen);
        }

        if( !strcmp(word, "AD") ) {
            sscanf(line, "%s = %n", word, &i);
            alen = (strlen(line) - i) / 2;
            scanhex(a, alen, line+i);

            if( out2("AD\n") ) dumphex(a, alen);
        }

        if( !strcmp(word, "CT") ) {
            sscanf(line, "%s = %n", word, &i);
            clen = (strlen(line) - i) / 2;
            scanhex(c, clen, line+i);
            if( len >= 0 ) tlen = clen - len;

            if( out2("CT\n") ) dumphex(c, clen);
        }

        if( !strcmp(word, "PT") ) {
            sscanf(line, "%s = %n", word, &i);
            len = (strlen(line) - i) / 2;
            scanhex(p, len, line+i);
            if( clen > 0 ) tlen = clen - len;

            if( out2("PT\n") ) dumphex(p, len);
        }
    }

    // printf("%ld tested %ld fail(s).\n", tested, fails);
    return vflushed ? EXIT_FAILURE : EXIT_SUCCESS;
}
