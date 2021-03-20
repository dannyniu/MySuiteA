/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#if ! CTR_DRBG_OMIT_DF
#define __CTR_DRBG_Seed CTR_DRBG_Seed_WithDF
#else
#define __CTR_DRBG_Seed CTR_DRBG_Seed
#endif

#define Define_CTR_DRBG_Blockcipher(algo,name)                  \
    void *CTR_DRBG_##algo##_InstInit(                           \
        ctr_drbg_##name *restrict x,                            \
        void const *restrict seedstr,                           \
        size_t len)                                             \
    {                                                           \
        x->ctr_drbg = CTR_DRBG_INIT(c##algo);                   \
        if( x->ctr_drbg.bc_blksize > CTR_DRBG_MAX_BLKSIZE ||    \
            x->ctr_drbg.bc_keysize > CTR_DRBG_MAX_KEYSIZE )     \
            return NULL;                                        \
        __CTR_DRBG_Seed(&x->ctr_drbg, seedstr, len);            \
        return x;                                               \
    }                                                           \
                                                                \
    IntPtr iCTR_DRBG_##algo(int q)                              \
    { return cCTR_DRBG_##algo(q); }
