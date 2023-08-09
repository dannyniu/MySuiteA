/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsassa-pss.h"
#include "../2-hash/sha.h"

#define PKC_CtAlgo iRSASSA_PSS_CtCodec
#define MSGMAX 96
#include "test-api-defs.c.h"

#define PKC_Prologue() do {                                     \
        ((XctrlFunc_t)tRSASSA_PSS(NULL, PrivXctrlFunc))(        \
            dex, RSASSA_PSS_set_slen,                           \
            NULL, 0, 24);                                       \
        ((XctrlFunc_t)tRSASSA_PSS(NULL, PubXctrlFunc))(         \
            enx, RSASSA_PSS_set_slen,                           \
            NULL, 0, 24);                                       \
    } while(0)

#define PKC_Epilogue() do {                                     \
        if( ((XctrlFunc_t)tRSASSA_PSS(NULL, PrivXctrlFunc))(    \
                dex, RSASSA_PSS_get_slen,                       \
                NULL, 0, 0) != (void *)24 ) {                   \
            printf("Salt Length Error.\n");                     \
            failures++;                                         \
        }                                                       \
        if( ((XctrlFunc_t)tRSASSA_PSS(NULL, PubXctrlFunc))(     \
                enx, RSASSA_PSS_get_slen,                       \
                NULL, 0, 0) != (void *)24 ) {                   \
            printf("Salt Length Error.\n");                     \
            failures++;                                         \
        }                                                       \
    } while(0)

#include "../3-pkc-test-utils/test-api-dss.c.h"
