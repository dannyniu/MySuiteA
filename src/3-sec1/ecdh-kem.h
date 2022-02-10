/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#ifndef MySuiteA_ecdh_kem_h
#define MySuiteA_ecdh_kem_h 1

#include "../2-ec/ecp-xyz.h"

// In a typical Diffie-Hellman-like key exchange, each peer operates
// identically, i.e. that being peer-symmetric. However, some post-quantum
// PKE/KEM schemes the operation is peer-asymmetric.
//
// For code-based PKEs, it's because the encrypting peer is applying
// different operation than the decrypting peer; for lattice-based KEMs,
// the Fujisaki-Okamoto transformation dictates that the decrypting peer
// must do different additional work to verify that the ciphertext is
// not one that would tricks the decrypting oracle with methods like
// decryption failure amplification to guess private key bits.
//
// Additionally, it is intended that MySuiteA provide a uniform interface
// across all algorithms of same type - KEM is a more general form than
// key-agreement (and PKE) in terms of API design. And RSA encryption cannot
// fit in the form of key-agreement.
//
// All in all, ECDH is implemented as a KEM. And, the documents in the
// suite describe ECDH as ECDH-KEM to emphasize that it's not implemented
// in the form of a traditional key-agreement API.

// data model: SIP16 | ILP32 | LP64
// ----------+-------+-------+------
// align spec: 4*8.5 | 4 * 9 | 8 * 5
typedef struct {
    // 4 32-bit words counted.
    uint32_t offset_d, offset_Q; // the entity keypair.
    uint32_t offset_k, offset_R; // ephemeral keypair.

    // 4 32-bit words counted.
    uint32_t offset_Tmp1, offset_Tmp2; // for ec_point_scale_accumulate.
    uint32_t offset_opctx;
    int32_t status;
    
    // 1 machine word counted.
    ecp_curve_t *curve;

    // The above members are common to both ECDH-KEM and ECDSA.
    // The key generation function assume such structure layout,
    // as it's intended that keygen function be shared between
    // ECDH-KEM and ECDSA.
    // ---
} ECDH_KEM_Priv_Ctx_Hdr_t;

#endif /* MySuiteA_ecdh_kem_h */
