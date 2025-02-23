/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa-paramset.h"
#include "sphincs-hash-params-family-sha256.h"
#include "sphincs-hash-params-family-sha512.h"
#include "sphincs-hash-params-family-shake.h"

#define HashSubX(name,algo) SPHINCS_HashParam_##name##_##algo
#define HashSub(name,algo) (IntPtr)HashSubX(name,algo)
#define PrehashInfo(obj) [8].info = i##obj

static SLHDSA_Param_t Param_SHA2_128s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHA256),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA256),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA256),
    [7].aux = HashSub(T, SHA256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHA2_128f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHA256),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA256),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA256),
    [7].aux = HashSub(T, SHA256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHA2_192s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHA2_192f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHA2_256s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 64,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHA2_256f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 68,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(CryptoObj_Null),
};

PKC_Algo_Inst_t SLHDSA_SHA2_128s = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHA2_128s
};

PKC_Algo_Inst_t SLHDSA_SHA2_128f = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHA2_128f
};

PKC_Algo_Inst_t SLHDSA_SHA2_192s = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHA2_192s
};

PKC_Algo_Inst_t SLHDSA_SHA2_192f = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHA2_192f
};

PKC_Algo_Inst_t SLHDSA_SHA2_256s = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHA2_256s
};

PKC_Algo_Inst_t SLHDSA_SHA2_256f = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHA2_256f
};

static SLHDSA_Param_t Param_SHAKE_128s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHAKE_128f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHAKE_192s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHAKE_192f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHAKE_256s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 64,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(CryptoObj_Null),
};

static SLHDSA_Param_t Param_SHAKE_256f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 68,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(CryptoObj_Null),
};

PKC_Algo_Inst_t SLHDSA_SHAKE_128s = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHAKE_128s
};

PKC_Algo_Inst_t SLHDSA_SHAKE_128f = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHAKE_128f
};

PKC_Algo_Inst_t SLHDSA_SHAKE_192s = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHAKE_192s
};

PKC_Algo_Inst_t SLHDSA_SHAKE_192f = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHAKE_192f
};

PKC_Algo_Inst_t SLHDSA_SHAKE_256s = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHAKE_256s
};

PKC_Algo_Inst_t SLHDSA_SHAKE_256f = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHAKE_256f
};

static SLHDSA_Param_t Param_SHA2_128s_wSHA256 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHA256),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA256),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA256),
    [7].aux = HashSub(T, SHA256),
    PrehashInfo(SHA256),
};

static SLHDSA_Param_t Param_SHA2_128f_wSHA256 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHA256),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA256),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA256),
    [7].aux = HashSub(T, SHA256),
    PrehashInfo(SHA256),
};

static SLHDSA_Param_t Param_SHA2_192s_wSHA512 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(SHA512),
};

static SLHDSA_Param_t Param_SHA2_192f_wSHA512 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(SHA512),
};

static SLHDSA_Param_t Param_SHA2_256s_wSHA512 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 64,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(SHA512),
};

static SLHDSA_Param_t Param_SHA2_256f_wSHA512 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 68,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
    PrehashInfo(SHA512),
};

PKC_Algo_Inst_t SLHDSA_SHA2_128s_wSHA256 = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHA2_128s_wSHA256
};

PKC_Algo_Inst_t SLHDSA_SHA2_128f_wSHA256 = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHA2_128f_wSHA256
};

PKC_Algo_Inst_t SLHDSA_SHA2_192s_wSHA512 = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHA2_192s_wSHA512
};

PKC_Algo_Inst_t SLHDSA_SHA2_192f_wSHA512 = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHA2_192f_wSHA512
};

PKC_Algo_Inst_t SLHDSA_SHA2_256s_wSHA512 = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHA2_256s_wSHA512
};

PKC_Algo_Inst_t SLHDSA_SHA2_256f_wSHA512 = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHA2_256f_wSHA512
};

static SLHDSA_Param_t Param_SHAKE_128s_wSHAKE128 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_128f_wSHAKE128 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 16,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_192s_wSHAKE256 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_192f_wSHAKE256 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 24,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_256s_wSHAKE256 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 64,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_256f_wSHAKE256 = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [8].aux = 0,
    [0].aux = 32,
    [1].aux = 68,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
    PrehashInfo(SHAKE256),
};

PKC_Algo_Inst_t SLHDSA_SHAKE_128s_wSHAKE128 = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHAKE_128s_wSHAKE128
};

PKC_Algo_Inst_t SLHDSA_SHAKE_128f_wSHAKE128 = {
    .secbits = 128,
    .algo = tSLHDSA,
    .param = Param_SHAKE_128f_wSHAKE128
};

PKC_Algo_Inst_t SLHDSA_SHAKE_192s_wSHAKE256 = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHAKE_192s_wSHAKE256
};

PKC_Algo_Inst_t SLHDSA_SHAKE_192f_wSHAKE256 = {
    .secbits = 192,
    .algo = tSLHDSA,
    .param = Param_SHAKE_192f_wSHAKE256
};

PKC_Algo_Inst_t SLHDSA_SHAKE_256s_wSHAKE256 = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHAKE_256s_wSHAKE256
};

PKC_Algo_Inst_t SLHDSA_SHAKE_256f_wSHAKE256 = {
    .secbits = 256,
    .algo = tSLHDSA,
    .param = Param_SHAKE_256f_wSHAKE256
};
