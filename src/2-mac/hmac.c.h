/* DannyNiu/NJF, 2020-07-10. Public Domain. */

#define Define_HMAC_Hash(algo,name)                             \
    void *HMAC_##algo##_Init(                                   \
        hmac_##name *restrict x,                                \
        void const *restrict key,                               \
        size_t keylen)                                          \
    {                                                           \
        x->hmac = HMAC_INIT(x##algo);                           \
        x = HMAC_SetKey(&x->hmac, key, keylen);                 \
        return x;                                               \
    }                                                           \
                                                                \
    IntPtr iHMAC_##algo(int q){ return xHMAC_##algo(q); }
