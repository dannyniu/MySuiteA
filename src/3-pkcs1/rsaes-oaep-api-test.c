/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-hash/sha.h"

#define PKC_CtAlgo iRSAES_OAEP_CtCodec
#define SSLEN 16
#include "test-api-defs.c.h"

const char label[] = "DannyNiu/NJF";
const bufvec_t cbuf[1] = {
    [0].len = sizeof(label),
    [0].dat = label,
};

#define PKC_Prologue()                                  \
    ((XctrlFunc_t)tRSAES_OAEP(NULL, PubXctrlFunc))(     \
        enx, RSAES_OAEP_label_set,                      \
        cbuf, 1, 0)

#define PKC_Epilogue()                                          \
    if( !((XctrlFunc_t)tRSAES_OAEP(NULL, PrivXctrlFunc))(       \
            dex, RSAES_OAEP_label_test,                         \
            cbuf, 1, 0) ) {                                     \
        printf("Label Verification Failure.\n");                \
        failures++;                                             \
    }

#include "../3-pkc-test-utils/test-api-kem.c.h"
