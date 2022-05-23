/* DannyNiu/NJF, 2018-02-12. Public Domain. */

#include "ccm-aes.h"
#include "../test-utils.c.h"

static char line[128], word[128];
static uint8_t k[32], iv[16], a[32], p[1024], c[1024], s[16], t[16], x[1024];
static size_t len, clen, alen, klen, ivlen, tlen;
static int pass;

static ccm_aes256_t ccm;

static int vflushed = false, vflushed_saved = false;

static const char *vname;
static long tested, fails;

void PrintIf(intmax_t cond, const char *fmt, ...)
{
    va_list ap;

    if( !cond ) return;
    else if( !pass ) return;

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
    iCryptoObj_t aead = iCCM_AES128, bc = iAES128;
    tCryptoObj_t mode = tCCM;
    CryptoParam_t Bc;

    if( argc < 3 ) return 1;

    if( !strcmp(argv[1], "CCM-AES-128") )
        aead=iCCM_AES128, bc=iAES128, mode=tCCM;

    if( !strcmp(argv[1], "CCM-AES-192") )
        aead=iCCM_AES192, bc=iAES192, mode=tCCM;

    if( !strcmp(argv[1], "CCM-AES-256") )
        aead=iCCM_AES256, bc=iAES256, mode=tCCM;

    Bc.info = bc, Bc.param = NULL;

    vname = argv[2];
    printf("%s\n", vname);
    freopen(argv[2], "r", stdin);

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

            if( !mode || !bc )
            {
                PrintIf(vflushed, "Test Over\n");
                if( vflushed ) fails++;
                vflushed = vflushed_saved || vflushed;
                continue;
            }

            ((PKInitFunc_t)mode(&Bc, KInitFunc))(
                &Bc, &ccm, k, mode(&Bc, keyBytes));
            ((AEncFunc_t)mode(&Bc, AEncFunc))(
                (void *)&ccm, ivlen, iv, alen, a, len, p, x, tlen, s);
            PrintIf(memcmp(s, c+len, tlen), "Enc Fail: Tag Wrong!\n");
            PrintIf(memcmp(c, x, len), "Enc Fail: Ciphertext Wrong!\n");
            ptr = ((ADecFunc_t)mode(&Bc, ADecFunc))(
                (void *)&ccm, ivlen, iv, alen, a, len, c, x, tlen, c+len);
            PrintIf(!ptr, "Dec Errornously Returned FAIL\n");
            PrintIf(memcmp(p, x, len), "Dec Fail: Plaintext Wrong!\n");

            if( alen && pass ) {
                ptr = ((ADecFunc_t)mode(&Bc, ADecFunc))(
                    (void *)&ccm, ivlen, iv, alen-1, a+1, len, c, x, tlen, t);
                PrintIf((intmax_t)ptr, "Dec Errornously Secceeded!\n");
            }

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
            scanhex(k, KEY_BYTES(bc), line+i);
            klen = KEY_BYTES(bc);
            //KINIT_FUNC(aead)(&ccm, k, klen);

            if( out2("Key\n") ) dumphex(k, klen);
        }

        if( !strcmp(word, "Nonce") ) {
            sscanf(line, "%s = %n", word, &i);
            ivlen = (size_t)((uint8_t *)scanhex(iv, ivlen, line+i) - iv);

            if( out2("Nonce\n") ) dumphex(iv, ivlen);
        }

        if( !strcmp(word, "Adata") ) {
            sscanf(line, "%s = %n", word, &i);
            alen = (size_t)((uint8_t *)scanhex(a, alen, line+i) - a);

            if( out2("Adata\n") ) dumphex(a, alen);
        }

        if( !strcmp(word, "CT") ) {
            sscanf(line, "%s = %n", word, &i);
            clen = (size_t)((uint8_t *)scanhex(c, clen, line+i) - c);
            if( len >= 0 ) tlen = clen - len;

            if( out2("CT\n") ) dumphex(c, clen);
        }

        if( !strcmp(word, "Payload") ) {
            sscanf(line, "%s = %n", word, &i);
            len = (size_t)((uint8_t *)scanhex(p, len, line+i) - p);
            if( clen > 0 ) tlen = clen - len;

            if( out2("Payload\n") ) dumphex(p, len);
        }

        if( !strcmp(word, "Result") ) {
            sscanf(line, "%s = %n", word, &i);
            if( strncmp(line+i, "Pass", 4) ) pass = false; else pass = true;

            out2("Testcase: %s\n", pass ? "Pass" : "Fail");
        }
    }

    printf("%ld tested %ld fail(s).\n", tested, fails);
    return vflushed ? EXIT_FAILURE : EXIT_SUCCESS;
}
