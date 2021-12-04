/* DannyNiu/NJF, 2018-04-20. Public Domain. */
// more test vectors at: https://crypto.stackexchange.com/q/51025

#define ENABLE_HOSTED_HEADERS
#include "gimli-xof.h"

#define HASH_LEN 32

static const struct {
    const char *testvec;
    const char *hashval;
} testsuite[] = {
    {
        "There's plenty for the both of us, may the best Dwarf win.",
        "4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8",
    },
    {
        "If anyone was to ask for my opinion, "
        "which I note they're not, I'd say "
        "we were taking the long way around.",
        "ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c",
    },
    {
        "Speak words we can all understand!",
        "8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267",
    },
    {
        "It's true you don't see many Dwarf-women. "
        "And in fact, they are so alike in voice and appearance, "
        "that they are often mistaken for Dwarf-men. "
        "And this in turn has given rise to the belief that "
        "there are no Dwarf-women, and that Dwarves just "
        "spring out of holes in the ground! "
        "Which is, of course, ridiculous.",
        "8887a5367d961d6734ee1a0d4aee09caca7fd6b606096ff69d8ce7b9a496cd2f"
    },
    {
        "",
        "b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67",
    },
    { NULL, NULL, },
}, *testptr = testsuite;

int main()
{
    gimli_xof_t gh;
    uint8_t bin[HASH_LEN];
    char out[HASH_LEN * 2 + 1];
    int i, fail, pass;

    fail = 0;
    pass = 0;
    while( testptr->testvec )
    {
        Gimli_XOF_Init(&gh);
        Gimli_XOF_Write(&gh, testptr->testvec, strlen(testptr->testvec));
        Gimli_XOF_Final(&gh);
        Gimli_XOF_Read(&gh, bin, HASH_LEN);
    
        for(i=0; i<HASH_LEN; i++)
        {
            sprintf(out + i * 2, "%02x", bin[i]);
        }

        if( strcmp(out, testptr->hashval) )
        {
            printf("!! Gimli-XOF Test Failed +1 !!\n");
            fail++;
        }
        else pass++;
        
        testptr++;
    }
    printf("Gimli-XOF %d failed %d passed\n", fail, pass);
    
    return 0;
}
