/* DannyNiu/NJF, 2018-02-08. Public Domain. */

#ifndef MySuiteA_gimli_hash_h
#define MySuiteA_gimli_hash_h 1

// References: src/notes.txt: "Gimli". 

#include "../mysuitea-common.h"
#include "../1-symm/sponge.h"

typedef struct gimli_hash_context {
    sponge_t    sponge;
    union {
        uint8_t     u8[48];
        uint32_t    u32[12];
    } state;
} gimli_hash_t;

void Gimli_Hash_Init(gimli_hash_t *restrict x);
void Gimli_Hash_Write(gimli_hash_t *restrict x, const void *restrict data, size_t len);
void Gimli_Hash_Final(gimli_hash_t *restrict x);
void Gimli_Hash_Read(gimli_hash_t *restrict x, void *restrict data, size_t len);

#ifndef foo
# // Emacs seems to have difficulty indent correctly if nothing's here. 
#endif /* foo */

#define cGimli_Hash(q) (                                        \
        q==blockBytes ? 16 :                                    \
        q==contextBytes ? sizeof(struct gimli_hash_context) :   \
        q==InitFunc ? (intptr_t)Gimli_Hash_Init :               \
        q==WriteFunc ? (intptr_t)Gimli_Hash_Write :             \
        q==XofFinalFunc ? (intptr_t)Gimli_Hash_Final :          \
        q==ReadFunc ? (intptr_t)Gimli_Hash_Read :               \
        -1)

intptr_t iGimli_Hash(int q);

#endif /* MySuiteA_gimli_hash_h */
