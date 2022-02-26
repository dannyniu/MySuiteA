/* DannyNiu/NJF, 2022-02-25. Public Domain. */

#define PKC_KeyAlgo iPKCS1_KeyCodec

#define NBITS 768

PKCS1_RSA_Param_t params = {
    [0] = { .info = iSHA256, .param = NULL, },
    [1] = { .info = iSHA256, .param = NULL, },
    [2] = { .info = NULL, .aux = 32, },
    [3] = { .info = NULL, .aux = NBITS, },
    [4] = { .info = NULL, .aux = 2, },
};
