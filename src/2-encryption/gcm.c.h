/* DannyNiu/NJF, 2020-07-10. Public Domain. */

#define Define_GCM_Blockcipher(algo,name)                       \
    void *GCM_##algo##_Init(                                    \
        gcm_##name *restrict x,                                 \
        void const *restrict k,                                 \
        size_t klen)                                            \
    {                                                           \
        gcm_t *ctx = &x->gcm;                                   \
        if( klen != KEY_BYTES(c##algo) )                        \
            return NULL;                                        \
        *x = (gcm_##name){                                      \
            .gcm = GCM_INIT(c##algo),                           \
        };                                                      \
        KSCHD_FUNC(c##algo)(k, x->kschd);                       \
        ctx->enc(ctx->H, ctx->H, x->kschd);                     \
        return x;                                               \
    }                                                           \
                                                                \
    uintmax_t iGCM_##algo(int q){ return cGCM_##algo(q); }
