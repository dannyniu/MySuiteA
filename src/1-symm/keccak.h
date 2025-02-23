/* DannyNiu/NJF, 2018-02-06. Public Domain. */

#ifndef MySuiteA_keccak_h
#define MySuiteA_keccak_h 1

#include "../mysuitea-common.h"

void KeccakP1600_Permute_ci(void const *in, void *out, int rounds);
void KeccakP1600_Permute_ni(void const *in, void *out, int rounds);
void KeccakF1600_Permute(void const *in, void *out);

#define cKeccakF(b,q) ( q==blockBytes ? b/8 : 0 )

#define xKeccakF(b,q) (                                 \
        q==PermuteFunc ? (IntPtr)KeccakF##b##_Permute : \
        cKeccakF(b,q) )

#define cKeccakF1600(q) cKeccakF(1600,q)
#define xKeccakF1600(q) xKeccakF(1600,q)
IntPtr iKeccakF1600(int q);

void KeccakP1600nr12_Permute(void const *in, void *out);
void KeccakP1600nr14_Permute(void const *in, void *out);

#define xKeccakP1600nr12(q) (                                   \
        q==PermuteFunc ? (IntPtr)KeccakP1600nr12_Permute :      \
        cKeccakF(1600,q) )

#define xKeccakP1600nr14(q) (                                   \
        q==PermuteFunc ? (IntPtr)KeccakP1600nr14_Permute :      \
        cKeccakF(1600,q) )

#if !defined(NI_KECCAK) || NI_KECCAK == NI_NEVER
#define KeccakP1600_Permute KeccakP1600_Permute_ci

#elif NI_KECCAK == NI_ALWAYS
#define KeccakP1600_Permute KeccakP1600_Permute_ni

#elif NI_KECCAK == NI_RUNTIME
extern int extern_ni_keccak_conf;
#define ni_keccak_conf extern_ni_keccak_conf

#define KeccakP1600_Permute                  \
    ( ni_keccak_conf ?                       \
      KeccakP1600_Permute_ni :               \
      KeccakP1600_Permute_ci )
#endif /* NI_KECCAK */

#endif /* MySuiteA_keccak_h */
