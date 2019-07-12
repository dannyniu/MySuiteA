/* DannyNiu/NJF, 2018-02-14. Public Domain */

#include "gcm-aes.h"

#define Define_GCM_AES_Init(bits)                               \
    void GCM_AES##bits##_Init(void *restrict x,                 \
                              const void *restrict k){          \
        gcm_aes##bits##_t *ctx = x;                             \
        *ctx = (gcm_aes##bits##_t){                             \
            .gcm = GCM_INIT(_iAES##bits),                       \
        };                                                      \
        KSCHD_FUNC(_iAES##bits)(k, ctx->kschd);                 \
        ctx->gcm.enc(ctx->gcm.H, ctx->gcm.H, ctx->kschd);       \
    }

Define_GCM_AES_Init(128)
Define_GCM_AES_Init(192)
Define_GCM_AES_Init(256)

uintptr_t iGCM_AES128(int q){ return _iGCM_AES128(q); }
uintptr_t iGCM_AES192(int q){ return _iGCM_AES192(q); }
uintptr_t iGCM_AES256(int q){ return _iGCM_AES256(q); }
