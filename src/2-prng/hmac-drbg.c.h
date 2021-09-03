/* DannyNiu/NJF, 2020-11-29. Public Domain. */

#define Define_HMAC_DRBG_PRF(algo,name)                                 \
    void *HMAC_DRBG_##algo##_InstInit(                                  \
        hmac_drbg_##name *restrict x,                                   \
        void const *restrict seedstr,                                   \
        size_t len)                                                     \
    {                                                                   \
        x->hmac_drbg = HMAC_DRBG_INIT(x##algo);                         \
        x->hmac_drbg.parameterization = NULL;                           \
        HMAC_DRBG_Seed(&x->hmac_drbg, seedstr, len);                    \
        return x;                                                       \
    }                                                                   \
                                                                        \
    IntPtr iHMAC_DRBG_##algo(int q) { return xHMAC_DRBG_##algo(q); }
