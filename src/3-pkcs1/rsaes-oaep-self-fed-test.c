/* DannyNiu/NJF, 2021-09-11. Public Domain. */

#include "rsaes-oaep.h"
#include "../2-hash/sha.h"

#define PKC_Algo_Prefix RSAES_OAEP
#define SSLEN 16
#include "test-self-fed-defs.c.h"

const char label[] = "DannyNiu/NJF";
const bufvec_t cbuf[1] = {
    [0].len = sizeof(label),
    [0].dat = label,
};

#define PKC_Prologue()                          \
    RSAES_OAEP_Enc_Xctrl(                       \
        &enx.header, RSAES_OAEP_label_set,      \
        cbuf, 1, 0)

#define PKC_Epilogue()                                  \
    if( !RSAES_OAEP_Dec_Xctrl(                          \
            dex, RSAES_OAEP_label_test,                 \
            cbuf, 1, 0) ) {                             \
        printf("Label Verification Failure.\n");        \
        failures++;                                     \
    }

#include "../3-pkc-test-utils/test-self-fed-kem.c.h"
