/* DannyNiu/NJF, 2023-11-11. Public Domain. */

#include "slhdsa-paramset.h"
#include "sphincs-hash-params-family-sha256.h"
#include "sphincs-hash-params-family-sha512.h"
#include "sphincs-hash-params-family-shake.h"

#define HashSubX(name,algo) SPHINCS_HashParam_##name##_##algo
#define HashSub(name,algo) (IntPtr)HashSubX(name,algo)

static SLHDSA_Param_t Param_SHA2_128s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 16,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHA256),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA256),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA256),
    [7].aux = HashSub(T, SHA256),
};

static SLHDSA_Param_t Param_SHA2_128f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 16,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHA256),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA256),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA256),
    [7].aux = HashSub(T, SHA256),
};

static SLHDSA_Param_t Param_SHA2_192s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 24,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
};

static SLHDSA_Param_t Param_SHA2_192f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 24,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
};

static SLHDSA_Param_t Param_SHA2_256s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 32,
    [1].aux = 64,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
};

static SLHDSA_Param_t Param_SHA2_256f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 32,
    [1].aux = 68,
    [2].aux = HashSub(Hmsg, SHA512),
    [3].aux = HashSub(PRF, SHA256),
    [4].aux = HashSub(PRFmsg, SHA512),
    [5].aux = HashSub(F, SHA256),
    [6].aux = HashSub(H, SHA512),
    [7].aux = HashSub(T, SHA512),
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
    [0].aux = 16,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_128f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 16,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_192s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 24,
    [1].aux = 63,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_192f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 24,
    [1].aux = 66,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_256s = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 32,
    [1].aux = 64,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
};

static SLHDSA_Param_t Param_SHAKE_256f = {
    [0].info = NULL, [1].info = NULL,
    [2].info = NULL, [3].info = NULL,
    [4].info = NULL, [5].info = NULL,
    [6].info = NULL, [7].info = NULL,
    [0].aux = 32,
    [1].aux = 68,
    [2].aux = HashSub(Hmsg, SHAKE256),
    [3].aux = HashSub(PRF, SHAKE256),
    [4].aux = HashSub(PRFmsg, SHAKE256),
    [5].aux = HashSub(F, SHAKE256),
    [6].aux = HashSub(H, SHAKE256),
    [7].aux = HashSub(T, SHAKE256),
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
