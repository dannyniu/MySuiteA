/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsassa-pss.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix RSASSA_PSS
#define MSGMAX 96
#include "test-self-fed-defs.c.h"

#define PKC_Prologue() do {                     \
        RSASSA_PSS_Sign_Xctrl(                  \
            dex, RSASSA_PSS_set_slen,           \
            NULL, 0, 24);                       \
        RSASSA_PSS_Verify_Xctrl(                \
            &enx.header, RSASSA_PSS_set_slen,   \
            NULL, 0, 24);                       \
    } while(0)

#define PKC_Epilogue() do {                             \
        if( RSASSA_PSS_Sign_Xctrl(                      \
                dex, RSASSA_PSS_get_slen,               \
                NULL, 0, 0) != (void *)24 ) {           \
            printf("Salt Length Error.\n");             \
            failures++;                                 \
        }                                               \
        if( RSASSA_PSS_Verify_Xctrl(                    \
                &enx.header, RSASSA_PSS_get_slen,       \
                NULL, 0, 0) != (void *)24 ) {           \
            printf("Salt Length Error.\n");             \
            failures++;                                 \
        }                                               \
    } while(0)

#include "../3-pkc-test-utils/test-self-fed-dss.c.h"
