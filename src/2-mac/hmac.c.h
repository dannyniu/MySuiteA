
#define Define_HMAC_Hash(algo,name)                             \
    void *HMAC_##algo##_Init(                                   \
        hmac_##name *restrict x,                                \
        const void *restrict key,                               \
        size_t keylen)                                          \
    {                                                           \
        x->hmac = HMAC_INIT(c##algo);                           \
        HMAC_SetKey(&x->hmac, key, keylen);                     \
        return x;                                               \
    }                                                           \
                                                                \
    uintptr_t iHMAC_##algo(int q){ return cHMAC_##algo(q); }