/* DannyNiu/NJF, 2018-02-19. Public Domain. */

#ifndef MySuiteA_cmac_h
#define MySuiteA_cmac_h 1

#include "../mysuitea-common.h"

#define CMAC_BLKSIZE 16

// The structure size is a multiply of 16
// under ILP32 and I32LP64 environments.
// [!A-E-D!]: only blockciphiers with 128-bit blocks are supported.
typedef struct cmac_context {
    uint8_t     T[CMAC_BLKSIZE];
    uint8_t     K1[CMAC_BLKSIZE];
    uint8_t     K2[CMAC_BLKSIZE];
    union {
        struct {
            int16_t    filled;
            int8_t     finalized;
            int8_t     keylen_valid;
        };
        size_t         pad;
    };

    // Similar to that in "sponge.h". 
    ptrdiff_t       offset;
    KschdFunc_t     kschd;
    EncFunc_t       enc;
} cmac_t;

// related notes [keyed-interfaces] in "hmac.h".

#define CMAC_INIT(bc)                   \
    (BLOCK_BYTES(bc) == CMAC_BLKSIZE ?  \
     (cmac_t){                          \
        .T = {0}, .K1 = {0}, .K2 = {0}, \
        .filled = 0,                    \
        .finalized = false,             \
        .keylen_valid = KEY_BYTES(bc),  \
        .offset = sizeof(cmac_t),       \
        .kschd = KSCHD_FUNC(bc),        \
        .enc = ENC_FUNC(bc),            \
    } : (cmac_t){0})

void *CMAC_SetKey(
    cmac_t *restrict cmac, const void *restrict key, size_t keylen);

void CMAC_Update(
    cmac_t *restrict cmac, const void *restrict data, size_t len);

void CMAC_Final(
    cmac_t *restrict cmac, void *restrict out, size_t t);

#define Declare_CMAC_Blockcipher(algo,name)     \
    typedef struct {                            \
        cmac_t cmac;                            \
        uint8_t kw[KSCHD_BYTES(c##algo)];       \
    } cmac_##name;                              \
                                                \
    void *CMAC_##algo##_Init(                   \
        cmac_##name *restrict x,                \
        void const *restrict key,               \
        size_t keylen);                         \
                                                \
    IntPtr iCMAC_##algo(int q);
    

#define cCMAC(bc,q) (                                           \
        q==outBytes || q==blockBytes ? BLOCK_BYTES(c##bc) :     \
        q==keyBytes ? KEY_BYTES(c##bc) :                        \
        q==contextBytes ? sizeof(cmac_t) + KSCHD_BYTES(c##bc) : \
        0)

#define xCMAC(bc,q) (                                           \
        q==KInitFunc ? (IntPtr)CMAC_##bc##_Init :               \
        q==UpdateFunc ? (IntPtr)CMAC_Update :                   \
        q==FinalFunc ? (IntPtr)CMAC_Final :                     \
        cCMAC(bc,q) )

IntPtr tCMAC(const CryptoParam_t *P, int q);

void *CMAC_T_Init(
    const CryptoParam_t *restrict P,
    cmac_t *restrict x,
    void const *restrict k,
    size_t klen);

#endif /* MySuiteA_cmac_h */
