/* DannyNiu/NJF, 2022-02-09. Public Domain. */

#define ENABLE_HOSTED_HEADERS
#include "eddsa.h"
#include "../2-ec/curves-Ed.h"
#include "../2-hash/sha.h"
#include "../2-xof/shake.h"
#include "../1-integers/vlong-dat.h"
#include "../0-exec/struct-delta.c.h"
#include "../test-utils.c.h"

typedef struct {
    EdDSA_Ctx_Hdr_t x_hdr;
    union {
        sha512_t sha512;
        shake256_t shake256;
    } hash[2];
    ecEd448_opctx_t opctx;
    ecEd448_xytz_t Points[4];
    VLONG_T(VLONG_BITS_WCNT(448)) Scalars[2];
} EdDSA_Ctx_t;

EdDSA_Ctx_t eddsaCtx, eddsaSavedCtx;

uint8_t msgbuf[1024];

typedef struct {
    char *d, *sig, *msg;
    EdDSA_Param_t params;
    bufvec_t bvec[2];
} EdDSA_Test_Vector_t;

EdDSA_Test_Vector_t testvecs[] =
{
    // Ed25519

    {
        .d =
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60",

        .sig =
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b",

        .msg = "",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = NULL,
        .bvec[1].len = 0,
    },

    {
        .d =
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb",

        .sig =
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00",

        .msg = "72",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = NULL,
        .bvec[1].len = 0,
    },

    {
        .d =
        "c5aa8df43f9f837bedb7442f31dcb7b1"
        "66d38535076f094b85ce3a2e0b4458f7",

        .sig =
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a",

        .msg = "af82",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = NULL,
        .bvec[1].len = 0,
    },

    {
        .d =
        "f5e5767cf153319517630f226876b86c"
        "8160cc583bc013744c6bf255f5cc0ee5",

        .sig =
        "0aab4c900501b3e24d7cdf4663326a3a"
        "87df5e4843b2cbdb67cbf6e460fec350"
        "aa5371b1508f9f4528ecea23c436d94b"
        "5e8fcd4f681e30a6ac00a9704a188a03",

        .msg =
        "08b8b2b733424243760fe426a4b54908"
        "632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1"
        "e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe57"
        "38829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c"
        "941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a"
        "7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b"
        "3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9"
        "a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc10"
        "3b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a4"
        "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a9"
        "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d"
        "502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bd"
        "e1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553"
        "878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089b"
        "eccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a"
        "7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b"
        "82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969b"
        "e3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8"
        "fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1"
        "ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988d"
        "cda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a8"
        "5f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927"
        "094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7"
        "984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57"
        "f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1"
        "b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac09"
        "43bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2"
        "cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041"
        "e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f161"
        "0e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d034"
        "12c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e"
        "4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8ca"
        "c60c905c15fc910840b94c00a0b9d0",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = NULL,
        .bvec[1].len = 0,
    },

    {
        .d =
        "833fe62409237b9d62ec77587520911e"
        "9a759cec1d19755b7da901b96dca3d42",

        .sig =
        "dc2a4459e7369633a52b1bf277839a00"
        "201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e030"
        "3dca179c138ac17ad9bef1177331a704",

        .msg =
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = NULL,
        .bvec[1].len = 0,
    },

    // Ed25519ctx

    {
        .d =
        "0305334e381af78f141cb666f6199f57"
        "bc3495335a256a95bd2a55bf546663f6",

        .sig =
        "55a4cc2f70a54e04288c5f4cd1e45a7b"
        "b520b36292911876cada7323198dd87a"
        "8b36950b95130022907a7fb7c4e9b2d5"
        "f6cca685a587b4b21f4b888e4e7edb0d",

        .msg =
        "f726936d19c800494e3fdaff20b276a8",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "foo",
        .bvec[1].len = 3,
    },

    {
        .d =
        "0305334e381af78f141cb666f6199f57"
        "bc3495335a256a95bd2a55bf546663f6",

        .sig =
        "fc60d5872fc46b3aa69f8b5b4351d580"
        "8f92bcc044606db097abab6dbcb1aee3"
        "216c48e8b3b66431b5b186d1d28f8ee1"
        "5a5ca2df6668346291c2043d4eb3e90d",

        .msg =
        "f726936d19c800494e3fdaff20b276a8",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "bar",
        .bvec[1].len = 3,
    },

    {
        .d =
        "0305334e381af78f141cb666f6199f57"
        "bc3495335a256a95bd2a55bf546663f6",

        .sig =
        "8b70c1cc8310e1de20ac53ce28ae6e72"
        "07f33c3295e03bb5c0732a1d20dc6490"
        "8922a8b052cf99b7c4fe107a5abb5b2c"
        "4085ae75890d02df26269d8945f84b0b",

        .msg =
        "508e9e6882b979fea900f62adceaca35",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "foo",
        .bvec[1].len = 3,
    },

    {
        .d =
        "ab9c2853ce297ddab85c993b3ae14bca"
        "d39b2c682beabc27d6d4eb20711d6560",

        .sig =
        "21655b5f1aa965996b3f97b3c849eafb"
        "a922a0a62992f73b3d1b73106a84ad85"
        "e9b86a7b6005ea868337ff2d20a7f5fb"
        "d4cd10b0be49a68da2b2e0dc0ad8960f",

        .msg =
        "f726936d19c800494e3fdaff20b276a8",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "foo",
        .bvec[1].len = 3,
    },

    // Ed25519ph

    {
        .d =
        "833fe62409237b9d62ec77587520911e"
        "9a759cec1d19755b7da901b96dca3d42",

        .sig =
        "98a70222f0b8121aa9d30f813d683f80"
        "9e462b469c7ff87639499bb94e6dae41"
        "31f85042463c2a355a2003d062adf5aa"
        "a10b8c61e636062aaad11c2a26083406",

        .msg =
        "616263",

        .params[0].info = iCurveEd25519,
        .params[1].info = iSHA512,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = EdDSA_Flags_PH,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    // Ed448

    {
        .d =
        "6c82a562cb808d10d632be89c8513ebf"
        "6c929f34ddfa8c9f63c9960ef6e348a3"
        "528c8a3fcc2f044e39a3fc5b94492f8f"
        "032e7549a20098f95b",

        .sig =
        "533a37f6bbe457251f023c0d88f976ae"
        "2dfb504a843e34d2074fd823d41a591f"
        "2b233f034f628281f2fd7a22ddd47d78"
        "28c59bd0a21bfd3980ff0d2028d4b18a"
        "9df63e006c5d1c2d345b925d8dc00b41"
        "04852db99ac5c7cdda8530a113a0f4db"
        "b61149f05a7363268c71d95808ff2e65"
        "2600",

        .msg =
        "",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "c4eab05d357007c632f3dbb48489924d"
        "552b08fe0c353a0d4a1f00acda2c463a"
        "fbea67c5e8d2877c5e3bc397a659949e"
        "f8021e954e0a12274e",

        .sig =
        "26b8f91727bd62897af15e41eb43c377"
        "efb9c610d48f2335cb0bd0087810f435"
        "2541b143c4b981b7e18f62de8ccdf633"
        "fc1bf037ab7cd779805e0dbcc0aae1cb"
        "cee1afb2e027df36bc04dcecbf154336"
        "c19f0af7e0a6472905e799f1953d2a0f"
        "f3348ab21aa4adafd1d234441cf807c0"
        "3a00",

        .msg =
        "03",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "c4eab05d357007c632f3dbb48489924d"
        "552b08fe0c353a0d4a1f00acda2c463a"
        "fbea67c5e8d2877c5e3bc397a659949e"
        "f8021e954e0a12274e",

        .sig =
        "d4f8f6131770dd46f40867d6fd5d5055"
        "de43541f8c5e35abbcd001b32a89f7d2"
        "151f7647f11d8ca2ae279fb842d60721"
        "7fce6e042f6815ea000c85741de5c8da"
        "1144a6a1aba7f96de42505d7a7298524"
        "fda538fccbbb754f578c1cad10d54d0d"
        "5428407e85dcbc98a49155c13764e66c"
        "3c00",

        .msg =
        "03",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "foo",
        .bvec[1].len = 3,
    },

    {
        .d =
        "cd23d24f714274e744343237b93290f5"
        "11f6425f98e64459ff203e8985083ffd"
        "f60500553abc0e05cd02184bdb89c4cc"
        "d67e187951267eb328",

        .sig =
        "1f0a8888ce25e8d458a21130879b840a"
        "9089d999aaba039eaf3e3afa090a09d3"
        "89dba82c4ff2ae8ac5cdfb7c55e94d5d"
        "961a29fe0109941e00b8dbdeea6d3b05"
        "1068df7254c0cdc129cbe62db2dc957d"
        "bb47b51fd3f213fb8698f064774250a5"
        "028961c9bf8ffd973fe5d5c206492b14"
        "0e00",

        .msg =
        "0c3e544074ec63b0265e0c",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "258cdd4ada32ed9c9ff54e63756ae582"
        "fb8fab2ac721f2c8e676a72768513d93"
        "9f63dddb55609133f29adf86ec9929dc"
        "cb52c1c5fd2ff7e21b",

        .sig =
        "7eeeab7c4e50fb799b418ee5e3197ff6"
        "bf15d43a14c34389b59dd1a7b1b85b4a"
        "e90438aca634bea45e3a2695f1270f07"
        "fdcdf7c62b8efeaf00b45c2c96ba457e"
        "b1a8bf075a3db28e5c24f6b923ed4ad7"
        "47c3c9e03c7079efb87cb110d3a99861"
        "e72003cbae6d6b8b827e4e6c143064ff"
        "3c00",

        .msg =
        "64a65f3cdedcdd66811e2915",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "7ef4e84544236752fbb56b8f31a23a10"
        "e42814f5f55ca037cdcc11c64c9a3b29"
        "49c1bb60700314611732a6c2fea98eeb"
        "c0266a11a93970100e",

        .sig =
        "6a12066f55331b6c22acd5d5bfc5d712"
        "28fbda80ae8dec26bdd306743c5027cb"
        "4890810c162c027468675ecf645a8317"
        "6c0d7323a2ccde2d80efe5a1268e8aca"
        "1d6fbc194d3f77c44986eb4ab4177919"
        "ad8bec33eb47bbb5fc6e28196fd1caf5"
        "6b4e7e0ba5519234d047155ac727a105"
        "3100",

        .msg =
        "64a65f3cdedcdd66811e2915e7",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "d65df341ad13e008567688baedda8e9d"
        "cdc17dc024974ea5b4227b6530e339bf"
        "f21f99e68ca6968f3cca6dfe0fb9f4fa"
        "b4fa135d5542ea3f01",

        .sig =
        "554bc2480860b49eab8532d2a533b7d5"
        "78ef473eeb58c98bb2d0e1ce488a98b1"
        "8dfde9b9b90775e67f47d4a1c3482058"
        "efc9f40d2ca033a0801b63d45b3b722e"
        "f552bad3b4ccb667da350192b61c508c"
        "f7b6b5adadc2c8d9a446ef003fb05cba"
        "5f30e88e36ec2703b349ca229c267083"
        "3900",

        .msg =
        "bd0f6a3747cd561bdddf4640a332461a"
        "4a30a12a434cd0bf40d766d9c6d458e5"
        "512204a30c17d1f50b5079631f64eb31"
        "12182da3005835461113718d1a5ef944",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "2ec5fe3c17045abdb136a5e6a913e32a"
        "b75ae68b53d2fc149b77e504132d3756"
        "9b7e766ba74a19bd6162343a21c8590a"
        "a9cebca9014c636df5",

        .sig =
        "c650ddbb0601c19ca11439e1640dd931"
        "f43c518ea5bea70d3dcde5f4191fe53f"
        "00cf966546b72bcc7d58be2b9badef28"
        "743954e3a44a23f880e8d4f1cfce2d7a"
        "61452d26da05896f0a50da66a239a8a1"
        "88b6d825b3305ad77b73fbac0836ecc6"
        "0987fd08527c1a8e80d5823e65cafe2a"
        "3d00",

        .msg =
        "15777532b0bdd0d1389f636c5f6b9ba7"
        "34c90af572877e2d272dd078aa1e567c"
        "fa80e12928bb542330e8409f31745041"
        "07ecd5efac61ae7504dabe2a602ede89"
        "e5cca6257a7c77e27a702b3ae39fc769"
        "fc54f2395ae6a1178cab4738e543072f"
        "c1c177fe71e92e25bf03e4ecb72f47b6"
        "4d0465aaea4c7fad372536c8ba516a60"
        "39c3c2a39f0e4d832be432dfa9a706a6"
        "e5c7e19f397964ca4258002f7c0541b5"
        "90316dbc5622b6b2a6fe7a4abffd9610"
        "5eca76ea7b98816af0748c10df048ce0"
        "12d901015a51f189f3888145c03650aa"
        "23ce894c3bd889e030d565071c59f409"
        "a9981b51878fd6fc110624dcbcde0bf7"
        "a69ccce38fabdf86f3bef6044819de11",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "872d093780f5d3730df7c212664b37b8"
        "a0f24f56810daa8382cd4fa3f77634ec"
        "44dc54f1c2ed9bea86fafb7632d8be19"
        "9ea165f5ad55dd9ce8",

        .sig =
        "e301345a41a39a4d72fff8df69c98075"
        "a0cc082b802fc9b2b6bc503f926b65bd"
        "df7f4c8f1cb49f6396afc8a70abe6d8a"
        "ef0db478d4c6b2970076c6a0484fe76d"
        "76b3a97625d79f1ce240e7c576750d29"
        "5528286f719b413de9ada3e8eb78ed57"
        "3603ce30d8bb761785dc30dbc320869e"
        "1a00",

        .msg =
        "6ddf802e1aae4986935f7f981ba3f035"
        "1d6273c0a0c22c9c0e8339168e675412"
        "a3debfaf435ed651558007db4384b650"
        "fcc07e3b586a27a4f7a00ac8a6fec2cd"
        "86ae4bf1570c41e6a40c931db27b2faa"
        "15a8cedd52cff7362c4e6e23daec0fbc"
        "3a79b6806e316efcc7b68119bf46bc76"
        "a26067a53f296dafdbdc11c77f7777e9"
        "72660cf4b6a9b369a6665f02e0cc9b6e"
        "dfad136b4fabe723d2813db3136cfde9"
        "b6d044322fee2947952e031b73ab5c60"
        "3349b307bdc27bc6cb8b8bbd7bd32321"
        "9b8033a581b59eadebb09b3c4f3d2277"
        "d4f0343624acc817804728b25ab79717"
        "2b4c5c21a22f9c7839d64300232eb66e"
        "53f31c723fa37fe387c7d3e50bdf9813"
        "a30e5bb12cf4cd930c40cfb4e1fc6225"
        "92a49588794494d56d24ea4b40c89fc0"
        "596cc9ebb961c8cb10adde976a5d602b"
        "1c3f85b9b9a001ed3c6a4d3b1437f520"
        "96cd1956d042a597d561a596ecd3d173"
        "5a8d570ea0ec27225a2c4aaff26306d1"
        "526c1af3ca6d9cf5a2c98f47e1c46db9"
        "a33234cfd4d81f2c98538a09ebe76998"
        "d0d8fd25997c7d255c6d66ece6fa56f1"
        "1144950f027795e653008f4bd7ca2dee"
        "85d8e90f3dc315130ce2a00375a318c7"
        "c3d97be2c8ce5b6db41a6254ff264fa6"
        "155baee3b0773c0f497c573f19bb4f42"
        "40281f0b1f4f7be857a4e59d416c06b4"
        "c50fa09e1810ddc6b1467baeac5a3668"
        "d11b6ecaa901440016f389f80acc4db9"
        "77025e7f5924388c7e340a732e554440"
        "e76570f8dd71b7d640b3450d1fd5f041"
        "0a18f9a3494f707c717b79b4bf75c984"
        "00b096b21653b5d217cf3565c9597456"
        "f70703497a078763829bc01bb1cbc8fa"
        "04eadc9a6e3f6699587a9e75c94e5bab"
        "0036e0b2e711392cff0047d0d6b05bd2"
        "a588bc109718954259f1d86678a579a3"
        "120f19cfb2963f177aeb70f2d4844826"
        "262e51b80271272068ef5b3856fa8535"
        "aa2a88b2d41f2a0e2fda7624c2850272"
        "ac4a2f561f8f2f7a318bfd5caf969614"
        "9e4ac824ad3460538fdc25421beec2cc"
        "6818162d06bbed0c40a387192349db67"
        "a118bada6cd5ab0140ee273204f628aa"
        "d1c135f770279a651e24d8c14d75a605"
        "9d76b96a6fd857def5e0b354b27ab937"
        "a5815d16b5fae407ff18222c6d1ed263"
        "be68c95f32d908bd895cd76207ae7264"
        "87567f9a67dad79abec316f683b17f2d"
        "02bf07e0ac8b5bc6162cf94697b3c27c"
        "d1fea49b27f23ba2901871962506520c"
        "392da8b6ad0d99f7013fbc06c2c17a56"
        "9500c8a7696481c1cd33e9b14e40b82e"
        "79a5f5db82571ba97bae3ad3e0479515"
        "bb0e2b0f3bfcd1fd33034efc6245eddd"
        "7ee2086ddae2600d8ca73e214e8c2b0b"
        "db2b047c6a464a562ed77b73d2d841c4"
        "b34973551257713b753632efba348169"
        "abc90a68f42611a40126d7cb21b58695"
        "568186f7e569d2ff0f9e745d0487dd2e"
        "b997cafc5abf9dd102e62ff66cba87",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = 0,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "833fe62409237b9d62ec77587520911e"
        "9a759cec1d19755b7da901b96dca3d42"
        "ef7822e0d5104127dc05d6dbefde69e3"
        "ab2cec7c867c6e2c49",

        .sig =
        "822f6901f7480f3d5f562c592994d969"
        "3602875614483256505600bbc281ae38"
        "1f54d6bce2ea911574932f52a4e6cadd"
        "78769375ec3ffd1b801a0d9b3f4030cd"
        "433964b6457ea39476511214f97469b5"
        "7dd32dbc560a9a94d00bff07620464a3"
        "ad203df7dc7ce360c3cd3696d9d9fab9"
        "0f00",

        .msg =
        "616263",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = EdDSA_Flags_PH,
        .bvec[1].dat = "",
        .bvec[1].len = 0,
    },

    {
        .d =
        "833fe62409237b9d62ec77587520911e"
        "9a759cec1d19755b7da901b96dca3d42"
        "ef7822e0d5104127dc05d6dbefde69e3"
        "ab2cec7c867c6e2c49",

        .sig =
        "c32299d46ec8ff02b54540982814dce9"
        "a05812f81962b649d528095916a2aa48"
        "1065b1580423ef927ecf0af5888f90da"
        "0f6a9a85ad5dc3f280d91224ba9911a3"
        "653d00e484e2ce232521481c8658df30"
        "4bb7745a73514cdb9bf3e15784ab7128"
        "4f8d0704a608c54a6b62d97beb511d13"
        "2100",

        .msg =
        "616263",

        .params[0].info = iCurveEd448,
        .params[1].info = iSHAKE256,
        .params[0].aux = 0,
        .params[1].aux = 0,

        .bvec[0].info = EdDSA_Flags_PH,
        .bvec[1].dat = "foo",
        .bvec[1].len = 3,
    },

    {0},
};

void FixedPRNG(void const *restrict randstr, void *restrict out, size_t len)
{
    scanhex(out, len, randstr);
}

int main(void) // (int argc, char *argv[])
{
    uint8_t H[128];
    uint8_t G[128];
    int fails = 0;

    EdDSA_Test_Vector_t *testvec = testvecs;
    unsigned pbits, plen;
    size_t len, msglen;
    bool verification;

    UpdateFunc_t updatefunc;
    void *hctx;

    while( testvec->msg )
    {
        // printf("test %ld\n", testvec - testvecs);
        pbits = ((ecEd_curve_t *)
                 testvec->params[0].info
                 (ecEd_PtrCurveDef))->pbits;

        plen = (pbits + 8) / 8;

        EdDSA_Keygen(
            &eddsaCtx.x_hdr, testvec->params,
            (GenFunc_t)FixedPRNG, testvec->d);

        if( !EdDSA_Verify_Xctrl(
                &eddsaCtx.x_hdr, EdDSA_set_ctxstr,
                testvec->bvec+1, 1, 0) )
        {
            printf("context control function failed!\n");
            fails ++;
        }

        msglen = strlen(testvec->msg) / 2;
        scanhex(msgbuf, msglen, testvec->msg);

        if( testvec->bvec[0].info & EdDSA_Flags_PH )
        {
            hctx = EdDSA_IncSign_Init(&eddsaCtx.x_hdr, &updatefunc);
            updatefunc(hctx, msgbuf, msglen);
            EdDSA_IncSign_Final(&eddsaCtx.x_hdr, NULL, NULL);
        }
        else
        {
            EdDSA_Sign(
                &eddsaCtx.x_hdr,
                msgbuf, msglen,
                NULL, NULL);
        }

        len = plen * 2;
        scanhex(H, len, testvec->sig);
        EdDSA_Encode_Signature(&eddsaCtx.x_hdr, G, &len);
        if( memcmp(G, H, len) != 0 )
        {
            printf("signer produced wrong signature!\n");
            fails ++;
        }

        EdDSA_Decode_Signature(&eddsaCtx.x_hdr, H, len);

        eddsaCtx.x_hdr.status = 0;
        memcpy(&eddsaSavedCtx, &eddsaCtx, sizeof(EdDSA_Ctx_t));

        if( testvec->bvec[0].info & EdDSA_Flags_PH )
        {
            hctx = EdDSA_IncVerify_Init(&eddsaCtx.x_hdr, &updatefunc);
            updatefunc(hctx, "!", 1);
            verification = EdDSA_IncVerify_Final(&eddsaCtx.x_hdr);
        }
        else verification = EdDSA_Verify(&eddsaCtx.x_hdr, "!", 1);

        if( verification )
        {
            printf("forgery undetected: Ed:%u!\n", pbits);
            fails ++;
        }

        memcpy(&eddsaCtx, &eddsaSavedCtx, sizeof(EdDSA_Ctx_t));

        if( testvec->bvec[0].info & EdDSA_Flags_PH )
        {
            hctx = EdDSA_IncVerify_Init(&eddsaCtx.x_hdr, &updatefunc);
            updatefunc(hctx, msgbuf, msglen);
            verification = EdDSA_IncVerify_Final(&eddsaCtx.x_hdr);
        }
        else verification = EdDSA_Verify(&eddsaCtx.x_hdr, msgbuf, msglen);

        if( !verification )
        {
            printf("rejected mistakenly: Ed:%u!\n", pbits);
            fails ++;
        }

        testvec++;
    }

    if( fails ) return EXIT_FAILURE; else return EXIT_SUCCESS;
}
