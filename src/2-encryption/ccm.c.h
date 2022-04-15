/* DannyNiu/NJF, 2022-04-15. Public Domain. */

#define Define_CCM_Blockcipher(algo,name)                       \
    void *CCM_##algo##_Init(                                    \
        ccm_##name *restrict x,                                 \
        void const *restrict k,                                 \
        size_t klen)                                            \
    {                                                           \
        if( klen != KEY_BYTES(c##algo) ) return NULL;           \
        *x = (ccm_##name){                                      \
            .ccm = CCM_INIT(x##algo),                           \
        };                                                      \
        KSCHD_FUNC(x##algo)(k, x->kschd);                       \
        return x;                                               \
    }                                                           \
                                                                \
    IntPtr iCCM_##algo(int q){ return xCCM_##algo(q); }
