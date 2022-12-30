/* DannyNiu/NJF, 2022-08-29. Public Domain. */

#include "../2-hash/blake3.h"
#include "../1-oslib/TCrew.h"

void BLAKE3_Update(
    blake3_t *restrict x,
    void const *restrict data,
    size_t len);

void BLAKE3_Final(
    blake3_t *restrict x,
    void *restrict out,
    size_t t);

#define xkBLAKE3_ForTest(q) (\
        q==outBytes ? 131 :\
        q==UpdateFunc ? (IntPtr)BLAKE3_Update :\
        q==FinalFunc ? (IntPtr)BLAKE3_Final :\
        xBLAKE3(q) )

#undef h
#define h xkBLAKE3_ForTest
static unsigned char buf[4096];

#include "../test-utils.c.h"

#ifdef THREADS_CREW_H
static TCrew_t tcrew_shared;
#endif /* THREADS_CREW_H */

void BLAKE3_Update(blake3_t *restrict x, void const *restrict data, size_t len)
{
    BLAKE3_Update4(x, data, len, &tcrew_shared.funcstab);
}

void BLAKE3_Final(blake3_t *restrict x, void *restrict out, size_t t)
{
    size_t l;
    uint8_t *ptr = out;

    BLAKE3_Final2(x, &tcrew_shared.funcstab);

    while( t > 0 )
    {
        l = myrand()+1;
        if( l > t ) l = t;

        BLAKE3_Read4(x, ptr, l, 0);
        t -= l;
        ptr += l;
    }
}

int main(int argc, char *argv[])
{
    size_t in_len = 0;
    void *x = NULL;

    // if( argc < 2 ) return EXIT_FAILURE; // only kBLAKE3.
    (void)argc; (void)argv;

#ifdef THREADS_CREW_H
    TCrew_Init(&tcrew_shared);
#endif /* THREADS_CREW_H */

    x = malloc(CTX_BYTES(h));

    KINIT_FUNC(h)(x, "whats the Elvish word for friend", 32);

    while( (in_len = fread(buf, 1, myrand()+1, stdin)) > 0 )
    {
        UPDATE_FUNC(h)(x, buf, in_len);
    }

    FINAL_FUNC(h)(x, buf, OUT_BYTES(h));
    free(x);
    x = NULL;

    for(int i=0; i<OUT_BYTES(h); i++) printf("%02x", buf[i]);

#ifdef THREADS_CREW_H
    TCrew_Destroy(&tcrew_shared);
#endif /* THREADS_CREW_H */

    return EXIT_SUCCESS;
}
