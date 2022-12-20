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
    size_t in_len = 0;
    void *x = NULL;

    mysrand((unsigned long)time(NULL));

#ifdef THREADS_CREW_H
    TCrew_Init(&tcrew_shared);
#endif /* THREADS_CREW_H */

    x = malloc(CTX_BYTES(h));
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
