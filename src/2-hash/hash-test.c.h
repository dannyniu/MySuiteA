/* DannyNiu/NJF, 2022-01-07. Public Domain. */

#ifndef hash_test_c_h
#define hash_test_c_h

#include "blake2.h"
#include "sha.h"
#include "sha3.h"
#include "sm3.h"

#include "../2-xof/shake.h"

#include "../test-utils.c.h"

#define test1case(name)                         \
    if( !strcmp(argv[1], #name) ) {             \
        glue(hash_test_,name)();                \
    }

static unsigned char buf[4096];

#endif /* hash_test_c_h */

#ifndef h
#error The hash function query object ``h'' is not defined!
#endif /* h */

#ifdef THREADS_CREW_H
static TCrew_t tcrew_shared;
#endif /* THREADS_CREW_H */

void glue(hash_test_,h)(void)
{
    uint64_t dgst1, dgst2;
    size_t in_len = 0;
    void *x = NULL;

#ifdef THREADS_CREW_H
    TCrew_Init(&tcrew_shared);
#endif /* THREADS_CREW_H */

    x = malloc(CTX_BYTES(h));

    // [2025-07-05,upd-zero-pad]: zero-padding test for update function.

    INIT_FUNC(h)(x);
    UPDATE_FUNC(h)(x, buf, BLOCK_BYTES(h));
    FINAL_FUNC(h)(x, &dgst1, 8);

    INIT_FUNC(h)(x);
    UPDATE_FUNC(h)(x, NULL, 1);
    FINAL_FUNC(h)(x, &dgst2, 8);

    if( dgst1 != dgst2 ) printf("!.");//*/

    mysrand((unsigned long)time(NULL));
    INIT_FUNC(h)(x);

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
}
