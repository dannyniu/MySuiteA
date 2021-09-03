/* DannyNiu/NJF, 2020-07-10. Public Domain. */

#define Define_CMAC_Blockcipher(algo,name)                      \
    void *CMAC_##algo##_Init(                                   \
        cmac_##name *restrict x,                                \
        void const *restrict key,                               \
        size_t keylen)                                          \
    {                                                           \
        x->cmac = CMAC_INIT(x##algo);                           \
        x = CMAC_SetKey(&x->cmac, key, keylen);                 \
        return x;                                               \
    }                                                           \
                                                                \
    IntPtr iCMAC_##algo(int q){ return xCMAC_##algo(q); }
