/* DannyNiu/NJF, 2020-07-26. Public Domain. */

#include <stdint.h>

static inline uint8_t sbox(uint8_t x, uint8_t const sbox_table[256])
{
    int i;
    uint8_t ret = 0;
    uint16_t mask = 0;

    for(i=0; i<256; i++)
    {
        mask = i ^ x;
        mask = (mask - 1) >> 8;
        ret |= sbox_table[i] & mask;
    }

    return ret;
}

static inline uint8_t invsbox(uint8_t x, uint8_t const sbox_table[256])
{
    int i;
    uint8_t ret = 0;
    uint16_t mask = 0;

    for(i=0; i<256; i++)
    {
        mask = sbox_table[i] ^ x;
        mask = (mask - 1) >> 8;
        ret |= i & mask;
    }

    return ret;
}

#define SBOX_WIDENER(                                                   \
    X,                                                                  \
    u00, u01, u02, u03, u04, u05, u06, u07,                             \
    u08, u09, u0A, u0B, u0C, u0D, u0E, u0F,                             \
    u10, u11, u12, u13, u14, u15, u16, u17,                             \
    u18, u19, u1A, u1B, u1C, u1D, u1E, u1F,                             \
    u20, u21, u22, u23, u24, u25, u26, u27,                             \
    u28, u29, u2A, u2B, u2C, u2D, u2E, u2F,                             \
    u30, u31, u32, u33, u34, u35, u36, u37,                             \
    u38, u39, u3A, u3B, u3C, u3D, u3E, u3F,                             \
    u40, u41, u42, u43, u44, u45, u46, u47,                             \
    u48, u49, u4A, u4B, u4C, u4D, u4E, u4F,                             \
    u50, u51, u52, u53, u54, u55, u56, u57,                             \
    u58, u59, u5A, u5B, u5C, u5D, u5E, u5F,                             \
    u60, u61, u62, u63, u64, u65, u66, u67,                             \
    u68, u69, u6A, u6B, u6C, u6D, u6E, u6F,                             \
    u70, u71, u72, u73, u74, u75, u76, u77,                             \
    u78, u79, u7A, u7B, u7C, u7D, u7E, u7F,                             \
    u80, u81, u82, u83, u84, u85, u86, u87,                             \
    u88, u89, u8A, u8B, u8C, u8D, u8E, u8F,                             \
    u90, u91, u92, u93, u94, u95, u96, u97,                             \
    u98, u99, u9A, u9B, u9C, u9D, u9E, u9F,                             \
    uA0, uA1, uA2, uA3, uA4, uA5, uA6, uA7,                             \
    uA8, uA9, uAA, uAB, uAC, uAD, uAE, uAF,                             \
    uB0, uB1, uB2, uB3, uB4, uB5, uB6, uB7,                             \
    uB8, uB9, uBA, uBB, uBC, uBD, uBE, uBF,                             \
    uC0, uC1, uC2, uC3, uC4, uC5, uC6, uC7,                             \
    uC8, uC9, uCA, uCB, uCC, uCD, uCE, uCF,                             \
    uD0, uD1, uD2, uD3, uD4, uD5, uD6, uD7,                             \
    uD8, uD9, uDA, uDB, uDC, uDD, uDE, uDF,                             \
    uE0, uE1, uE2, uE3, uE4, uE5, uE6, uE7,                             \
    uE8, uE9, uEA, uEB, uEC, uED, uEE, uEF,                             \
    uF0, uF1, uF2, uF3, uF4, uF5, uF6, uF7,                             \
    uF8, uF9, uFA, uFB, uFC, uFD, uFE, uFF)                             \
    {       X(u00, 0x00), X(u01, 0x01), X(u02, 0x02), X(u03, 0x03),     \
            X(u04, 0x04), X(u05, 0x05), X(u06, 0x06), X(u07, 0x07),     \
            X(u08, 0x08), X(u09, 0x09), X(u0A, 0x0A), X(u0B, 0x0B),     \
            X(u0C, 0x0C), X(u0D, 0x0D), X(u0E, 0x0E), X(u0F, 0x0F),     \
            X(u10, 0x10), X(u11, 0x11), X(u12, 0x12), X(u13, 0x13),     \
            X(u14, 0x14), X(u15, 0x15), X(u16, 0x16), X(u17, 0x17),     \
            X(u18, 0x18), X(u19, 0x19), X(u1A, 0x1A), X(u1B, 0x1B),     \
            X(u1C, 0x1C), X(u1D, 0x1D), X(u1E, 0x1E), X(u1F, 0x1F),     \
            X(u20, 0x20), X(u21, 0x21), X(u22, 0x22), X(u23, 0x23),     \
            X(u24, 0x24), X(u25, 0x25), X(u26, 0x26), X(u27, 0x27),     \
            X(u28, 0x28), X(u29, 0x29), X(u2A, 0x2A), X(u2B, 0x2B),     \
            X(u2C, 0x2C), X(u2D, 0x2D), X(u2E, 0x2E), X(u2F, 0x2F),     \
            X(u30, 0x30), X(u31, 0x31), X(u32, 0x32), X(u33, 0x33),     \
            X(u34, 0x34), X(u35, 0x35), X(u36, 0x36), X(u37, 0x37),     \
            X(u38, 0x38), X(u39, 0x39), X(u3A, 0x3A), X(u3B, 0x3B),     \
            X(u3C, 0x3C), X(u3D, 0x3D), X(u3E, 0x3E), X(u3F, 0x3F),     \
            X(u40, 0x40), X(u41, 0x41), X(u42, 0x42), X(u43, 0x43),     \
            X(u44, 0x44), X(u45, 0x45), X(u46, 0x46), X(u47, 0x47),     \
            X(u48, 0x48), X(u49, 0x49), X(u4A, 0x4A), X(u4B, 0x4B),     \
            X(u4C, 0x4C), X(u4D, 0x4D), X(u4E, 0x4E), X(u4F, 0x4F),     \
            X(u50, 0x50), X(u51, 0x51), X(u52, 0x52), X(u53, 0x53),     \
            X(u54, 0x54), X(u55, 0x55), X(u56, 0x56), X(u57, 0x57),     \
            X(u58, 0x58), X(u59, 0x59), X(u5A, 0x5A), X(u5B, 0x5B),     \
            X(u5C, 0x5C), X(u5D, 0x5D), X(u5E, 0x5E), X(u5F, 0x5F),     \
            X(u60, 0x60), X(u61, 0x61), X(u62, 0x62), X(u63, 0x63),     \
            X(u64, 0x64), X(u65, 0x65), X(u66, 0x66), X(u67, 0x67),     \
            X(u68, 0x68), X(u69, 0x69), X(u6A, 0x6A), X(u6B, 0x6B),     \
            X(u6C, 0x6C), X(u6D, 0x6D), X(u6E, 0x6E), X(u6F, 0x6F),     \
            X(u70, 0x70), X(u71, 0x71), X(u72, 0x72), X(u73, 0x73),     \
            X(u74, 0x74), X(u75, 0x75), X(u76, 0x76), X(u77, 0x77),     \
            X(u78, 0x78), X(u79, 0x79), X(u7A, 0x7A), X(u7B, 0x7B),     \
            X(u7C, 0x7C), X(u7D, 0x7D), X(u7E, 0x7E), X(u7F, 0x7F),     \
            X(u80, 0x80), X(u81, 0x81), X(u82, 0x82), X(u83, 0x83),     \
            X(u84, 0x84), X(u85, 0x85), X(u86, 0x86), X(u87, 0x87),     \
            X(u88, 0x88), X(u89, 0x89), X(u8A, 0x8A), X(u8B, 0x8B),     \
            X(u8C, 0x8C), X(u8D, 0x8D), X(u8E, 0x8E), X(u8F, 0x8F),     \
            X(u90, 0x90), X(u91, 0x91), X(u92, 0x92), X(u93, 0x93),     \
            X(u94, 0x94), X(u95, 0x95), X(u96, 0x96), X(u97, 0x97),     \
            X(u98, 0x98), X(u99, 0x99), X(u9A, 0x9A), X(u9B, 0x9B),     \
            X(u9C, 0x9C), X(u9D, 0x9D), X(u9E, 0x9E), X(u9F, 0x9F),     \
            X(uA0, 0xA0), X(uA1, 0xA1), X(uA2, 0xA2), X(uA3, 0xA3),     \
            X(uA4, 0xA4), X(uA5, 0xA5), X(uA6, 0xA6), X(uA7, 0xA7),     \
            X(uA8, 0xA8), X(uA9, 0xA9), X(uAA, 0xAA), X(uAB, 0xAB),     \
            X(uAC, 0xAC), X(uAD, 0xAD), X(uAE, 0xAE), X(uAF, 0xAF),     \
            X(uB0, 0xB0), X(uB1, 0xB1), X(uB2, 0xB2), X(uB3, 0xB3),     \
            X(uB4, 0xB4), X(uB5, 0xB5), X(uB6, 0xB6), X(uB7, 0xB7),     \
            X(uB8, 0xB8), X(uB9, 0xB9), X(uBA, 0xBA), X(uBB, 0xBB),     \
            X(uBC, 0xBC), X(uBD, 0xBD), X(uBE, 0xBE), X(uBF, 0xBF),     \
            X(uC0, 0xC0), X(uC1, 0xC1), X(uC2, 0xC2), X(uC3, 0xC3),     \
            X(uC4, 0xC4), X(uC5, 0xC5), X(uC6, 0xC6), X(uC7, 0xC7),     \
            X(uC8, 0xC8), X(uC9, 0xC9), X(uCA, 0xCA), X(uCB, 0xCB),     \
            X(uCC, 0xCC), X(uCD, 0xCD), X(uCE, 0xCE), X(uCF, 0xCF),     \
            X(uD0, 0xD0), X(uD1, 0xD1), X(uD2, 0xD2), X(uD3, 0xD3),     \
            X(uD4, 0xD4), X(uD5, 0xD5), X(uD6, 0xD6), X(uD7, 0xD7),     \
            X(uD8, 0xD8), X(uD9, 0xD9), X(uDA, 0xDA), X(uDB, 0xDB),     \
            X(uDC, 0xDC), X(uDD, 0xDD), X(uDE, 0xDE), X(uDF, 0xDF),     \
            X(uE0, 0xE0), X(uE1, 0xE1), X(uE2, 0xE2), X(uE3, 0xE3),     \
            X(uE4, 0xE4), X(uE5, 0xE5), X(uE6, 0xE6), X(uE7, 0xE7),     \
            X(uE8, 0xE8), X(uE9, 0xE9), X(uEA, 0xEA), X(uEB, 0xEB),     \
            X(uEC, 0xEC), X(uED, 0xED), X(uEE, 0xEE), X(uEF, 0xEF),     \
            X(uF0, 0xF0), X(uF1, 0xF1), X(uF2, 0xF2), X(uF3, 0xF3),     \
            X(uF4, 0xF4), X(uF5, 0xF5), X(uF6, 0xF6), X(uF7, 0xF7),     \
            X(uF8, 0xF8), X(uF9, 0xF9), X(uFA, 0xFA), X(uFB, 0xFB),     \
            X(uFC, 0xFC), X(uFD, 0xFD), X(uFE, 0xFE), X(uFF, 0xFF),     \
            }

#define SBOX_WIDENER2(                                                  \
    X,                                                                  \
    u00, u01, u02, u03, u04, u05, u06, u07,                             \
    u08, u09, u0A, u0B, u0C, u0D, u0E, u0F,                             \
    u10, u11, u12, u13, u14, u15, u16, u17,                             \
    u18, u19, u1A, u1B, u1C, u1D, u1E, u1F,                             \
    u20, u21, u22, u23, u24, u25, u26, u27,                             \
    u28, u29, u2A, u2B, u2C, u2D, u2E, u2F,                             \
    u30, u31, u32, u33, u34, u35, u36, u37,                             \
    u38, u39, u3A, u3B, u3C, u3D, u3E, u3F,                             \
    u40, u41, u42, u43, u44, u45, u46, u47,                             \
    u48, u49, u4A, u4B, u4C, u4D, u4E, u4F,                             \
    u50, u51, u52, u53, u54, u55, u56, u57,                             \
    u58, u59, u5A, u5B, u5C, u5D, u5E, u5F,                             \
    u60, u61, u62, u63, u64, u65, u66, u67,                             \
    u68, u69, u6A, u6B, u6C, u6D, u6E, u6F,                             \
    u70, u71, u72, u73, u74, u75, u76, u77,                             \
    u78, u79, u7A, u7B, u7C, u7D, u7E, u7F,                             \
    u80, u81, u82, u83, u84, u85, u86, u87,                             \
    u88, u89, u8A, u8B, u8C, u8D, u8E, u8F,                             \
    u90, u91, u92, u93, u94, u95, u96, u97,                             \
    u98, u99, u9A, u9B, u9C, u9D, u9E, u9F,                             \
    uA0, uA1, uA2, uA3, uA4, uA5, uA6, uA7,                             \
    uA8, uA9, uAA, uAB, uAC, uAD, uAE, uAF,                             \
    uB0, uB1, uB2, uB3, uB4, uB5, uB6, uB7,                             \
    uB8, uB9, uBA, uBB, uBC, uBD, uBE, uBF,                             \
    uC0, uC1, uC2, uC3, uC4, uC5, uC6, uC7,                             \
    uC8, uC9, uCA, uCB, uCC, uCD, uCE, uCF,                             \
    uD0, uD1, uD2, uD3, uD4, uD5, uD6, uD7,                             \
    uD8, uD9, uDA, uDB, uDC, uDD, uDE, uDF,                             \
    uE0, uE1, uE2, uE3, uE4, uE5, uE6, uE7,                             \
    uE8, uE9, uEA, uEB, uEC, uED, uEE, uEF,                             \
    uF0, uF1, uF2, uF3, uF4, uF5, uF6, uF7,                             \
    uF8, uF9, uFA, uFB, uFC, uFD, uFE, uFF,                             \
    v00, v01, v02, v03, v04, v05, v06, v07,                             \
    v08, v09, v0A, v0B, v0C, v0D, v0E, v0F,                             \
    v10, v11, v12, v13, v14, v15, v16, v17,                             \
    v18, v19, v1A, v1B, v1C, v1D, v1E, v1F,                             \
    v20, v21, v22, v23, v24, v25, v26, v27,                             \
    v28, v29, v2A, v2B, v2C, v2D, v2E, v2F,                             \
    v30, v31, v32, v33, v34, v35, v36, v37,                             \
    v38, v39, v3A, v3B, v3C, v3D, v3E, v3F,                             \
    v40, v41, v42, v43, v44, v45, v46, v47,                             \
    v48, v49, v4A, v4B, v4C, v4D, v4E, v4F,                             \
    v50, v51, v52, v53, v54, v55, v56, v57,                             \
    v58, v59, v5A, v5B, v5C, v5D, v5E, v5F,                             \
    v60, v61, v62, v63, v64, v65, v66, v67,                             \
    v68, v69, v6A, v6B, v6C, v6D, v6E, v6F,                             \
    v70, v71, v72, v73, v74, v75, v76, v77,                             \
    v78, v79, v7A, v7B, v7C, v7D, v7E, v7F,                             \
    v80, v81, v82, v83, v84, v85, v86, v87,                             \
    v88, v89, v8A, v8B, v8C, v8D, v8E, v8F,                             \
    v90, v91, v92, v93, v94, v95, v96, v97,                             \
    v98, v99, v9A, v9B, v9C, v9D, v9E, v9F,                             \
    vA0, vA1, vA2, vA3, vA4, vA5, vA6, vA7,                             \
    vA8, vA9, vAA, vAB, vAC, vAD, vAE, vAF,                             \
    vB0, vB1, vB2, vB3, vB4, vB5, vB6, vB7,                             \
    vB8, vB9, vBA, vBB, vBC, vBD, vBE, vBF,                             \
    vC0, vC1, vC2, vC3, vC4, vC5, vC6, vC7,                             \
    vC8, vC9, vCA, vCB, vCC, vCD, vCE, vCF,                             \
    vD0, vD1, vD2, vD3, vD4, vD5, vD6, vD7,                             \
    vD8, vD9, vDA, vDB, vDC, vDD, vDE, vDF,                             \
    vE0, vE1, vE2, vE3, vE4, vE5, vE6, vE7,                             \
    vE8, vE9, vEA, vEB, vEC, vED, vEE, vEF,                             \
    vF0, vF1, vF2, vF3, vF4, vF5, vF6, vF7,                             \
    vF8, vF9, vFA, vFB, vFC, vFD, vFE, vFF)                             \
    {       X(u00, v00, 0x00), X(u01, v01, 0x01), X(u02, v02, 0x02), X(u03, v03, 0x03),     \
            X(u04, v04, 0x04), X(u05, v05, 0x05), X(u06, v06, 0x06), X(u07, v07, 0x07),     \
            X(u08, v08, 0x08), X(u09, v09, 0x09), X(u0A, v0A, 0x0A), X(u0B, v0B, 0x0B),     \
            X(u0C, v0C, 0x0C), X(u0D, v0D, 0x0D), X(u0E, v0E, 0x0E), X(u0F, v0F, 0x0F),     \
            X(u10, v10, 0x10), X(u11, v11, 0x11), X(u12, v12, 0x12), X(u13, v13, 0x13),     \
            X(u14, v14, 0x14), X(u15, v15, 0x15), X(u16, v16, 0x16), X(u17, v17, 0x17),     \
            X(u18, v18, 0x18), X(u19, v19, 0x19), X(u1A, v1A, 0x1A), X(u1B, v1B, 0x1B),     \
            X(u1C, v1C, 0x1C), X(u1D, v1D, 0x1D), X(u1E, v1E, 0x1E), X(u1F, v1F, 0x1F),     \
            X(u20, v20, 0x20), X(u21, v21, 0x21), X(u22, v22, 0x22), X(u23, v23, 0x23),     \
            X(u24, v24, 0x24), X(u25, v25, 0x25), X(u26, v26, 0x26), X(u27, v27, 0x27),     \
            X(u28, v28, 0x28), X(u29, v29, 0x29), X(u2A, v2A, 0x2A), X(u2B, v2B, 0x2B),     \
            X(u2C, v2C, 0x2C), X(u2D, v2D, 0x2D), X(u2E, v2E, 0x2E), X(u2F, v2F, 0x2F),     \
            X(u30, v30, 0x30), X(u31, v31, 0x31), X(u32, v32, 0x32), X(u33, v33, 0x33),     \
            X(u34, v34, 0x34), X(u35, v35, 0x35), X(u36, v36, 0x36), X(u37, v37, 0x37),     \
            X(u38, v38, 0x38), X(u39, v39, 0x39), X(u3A, v3A, 0x3A), X(u3B, v3B, 0x3B),     \
            X(u3C, v3C, 0x3C), X(u3D, v3D, 0x3D), X(u3E, v3E, 0x3E), X(u3F, v3F, 0x3F),     \
            X(u40, v40, 0x40), X(u41, v41, 0x41), X(u42, v42, 0x42), X(u43, v43, 0x43),     \
            X(u44, v44, 0x44), X(u45, v45, 0x45), X(u46, v46, 0x46), X(u47, v47, 0x47),     \
            X(u48, v48, 0x48), X(u49, v49, 0x49), X(u4A, v4A, 0x4A), X(u4B, v4B, 0x4B),     \
            X(u4C, v4C, 0x4C), X(u4D, v4D, 0x4D), X(u4E, v4E, 0x4E), X(u4F, v4F, 0x4F),     \
            X(u50, v50, 0x50), X(u51, v51, 0x51), X(u52, v52, 0x52), X(u53, v53, 0x53),     \
            X(u54, v54, 0x54), X(u55, v55, 0x55), X(u56, v56, 0x56), X(u57, v57, 0x57),     \
            X(u58, v58, 0x58), X(u59, v59, 0x59), X(u5A, v5A, 0x5A), X(u5B, v5B, 0x5B),     \
            X(u5C, v5C, 0x5C), X(u5D, v5D, 0x5D), X(u5E, v5E, 0x5E), X(u5F, v5F, 0x5F),     \
            X(u60, v60, 0x60), X(u61, v61, 0x61), X(u62, v62, 0x62), X(u63, v63, 0x63),     \
            X(u64, v64, 0x64), X(u65, v65, 0x65), X(u66, v66, 0x66), X(u67, v67, 0x67),     \
            X(u68, v68, 0x68), X(u69, v69, 0x69), X(u6A, v6A, 0x6A), X(u6B, v6B, 0x6B),     \
            X(u6C, v6C, 0x6C), X(u6D, v6D, 0x6D), X(u6E, v6E, 0x6E), X(u6F, v6F, 0x6F),     \
            X(u70, v70, 0x70), X(u71, v71, 0x71), X(u72, v72, 0x72), X(u73, v73, 0x73),     \
            X(u74, v74, 0x74), X(u75, v75, 0x75), X(u76, v76, 0x76), X(u77, v77, 0x77),     \
            X(u78, v78, 0x78), X(u79, v79, 0x79), X(u7A, v7A, 0x7A), X(u7B, v7B, 0x7B),     \
            X(u7C, v7C, 0x7C), X(u7D, v7D, 0x7D), X(u7E, v7E, 0x7E), X(u7F, v7F, 0x7F),     \
            X(u80, v80, 0x80), X(u81, v81, 0x81), X(u82, v82, 0x82), X(u83, v83, 0x83),     \
            X(u84, v84, 0x84), X(u85, v85, 0x85), X(u86, v86, 0x86), X(u87, v87, 0x87),     \
            X(u88, v88, 0x88), X(u89, v89, 0x89), X(u8A, v8A, 0x8A), X(u8B, v8B, 0x8B),     \
            X(u8C, v8C, 0x8C), X(u8D, v8D, 0x8D), X(u8E, v8E, 0x8E), X(u8F, v8F, 0x8F),     \
            X(u90, v90, 0x90), X(u91, v91, 0x91), X(u92, v92, 0x92), X(u93, v93, 0x93),     \
            X(u94, v94, 0x94), X(u95, v95, 0x95), X(u96, v96, 0x96), X(u97, v97, 0x97),     \
            X(u98, v98, 0x98), X(u99, v99, 0x99), X(u9A, v9A, 0x9A), X(u9B, v9B, 0x9B),     \
            X(u9C, v9C, 0x9C), X(u9D, v9D, 0x9D), X(u9E, v9E, 0x9E), X(u9F, v9F, 0x9F),     \
            X(uA0, vA0, 0xA0), X(uA1, vA1, 0xA1), X(uA2, vA2, 0xA2), X(uA3, vA3, 0xA3),     \
            X(uA4, vA4, 0xA4), X(uA5, vA5, 0xA5), X(uA6, vA6, 0xA6), X(uA7, vA7, 0xA7),     \
            X(uA8, vA8, 0xA8), X(uA9, vA9, 0xA9), X(uAA, vAA, 0xAA), X(uAB, vAB, 0xAB),     \
            X(uAC, vAC, 0xAC), X(uAD, vAD, 0xAD), X(uAE, vAE, 0xAE), X(uAF, vAF, 0xAF),     \
            X(uB0, vB0, 0xB0), X(uB1, vB1, 0xB1), X(uB2, vB2, 0xB2), X(uB3, vB3, 0xB3),     \
            X(uB4, vB4, 0xB4), X(uB5, vB5, 0xB5), X(uB6, vB6, 0xB6), X(uB7, vB7, 0xB7),     \
            X(uB8, vB8, 0xB8), X(uB9, vB9, 0xB9), X(uBA, vBA, 0xBA), X(uBB, vBB, 0xBB),     \
            X(uBC, vBC, 0xBC), X(uBD, vBD, 0xBD), X(uBE, vBE, 0xBE), X(uBF, vBF, 0xBF),     \
            X(uC0, vC0, 0xC0), X(uC1, vC1, 0xC1), X(uC2, vC2, 0xC2), X(uC3, vC3, 0xC3),     \
            X(uC4, vC4, 0xC4), X(uC5, vC5, 0xC5), X(uC6, vC6, 0xC6), X(uC7, vC7, 0xC7),     \
            X(uC8, vC8, 0xC8), X(uC9, vC9, 0xC9), X(uCA, vCA, 0xCA), X(uCB, vCB, 0xCB),     \
            X(uCC, vCC, 0xCC), X(uCD, vCD, 0xCD), X(uCE, vCE, 0xCE), X(uCF, vCF, 0xCF),     \
            X(uD0, vD0, 0xD0), X(uD1, vD1, 0xD1), X(uD2, vD2, 0xD2), X(uD3, vD3, 0xD3),     \
            X(uD4, vD4, 0xD4), X(uD5, vD5, 0xD5), X(uD6, vD6, 0xD6), X(uD7, vD7, 0xD7),     \
            X(uD8, vD8, 0xD8), X(uD9, vD9, 0xD9), X(uDA, vDA, 0xDA), X(uDB, vDB, 0xDB),     \
            X(uDC, vDC, 0xDC), X(uDD, vDD, 0xDD), X(uDE, vDE, 0xDE), X(uDF, vDF, 0xDF),     \
            X(uE0, vE0, 0xE0), X(uE1, vE1, 0xE1), X(uE2, vE2, 0xE2), X(uE3, vE3, 0xE3),     \
            X(uE4, vE4, 0xE4), X(uE5, vE5, 0xE5), X(uE6, vE6, 0xE6), X(uE7, vE7, 0xE7),     \
            X(uE8, vE8, 0xE8), X(uE9, vE9, 0xE9), X(uEA, vEA, 0xEA), X(uEB, vEB, 0xEB),     \
            X(uEC, vEC, 0xEC), X(uED, vED, 0xED), X(uEE, vEE, 0xEE), X(uEF, vEF, 0xEF),     \
            X(uF0, vF0, 0xF0), X(uF1, vF1, 0xF1), X(uF2, vF2, 0xF2), X(uF3, vF3, 0xF3),     \
            X(uF4, vF4, 0xF4), X(uF5, vF5, 0xF5), X(uF6, vF6, 0xF6), X(uF7, vF7, 0xF7),     \
            X(uF8, vF8, 0xF8), X(uF9, vF9, 0xF9), X(uFA, vFA, 0xFA), X(uFB, vFB, 0xFB),     \
            X(uFC, vFC, 0xFC), X(uFD, vFD, 0xFD), X(uFE, vFE, 0xFE), X(uFF, vFF, 0xFF),     \
            }

static inline uint32_t wsbox(uint32_t w, uint32_t const wsbox_table[512])
{
    int i;
    uint32_t ret = 0;
    uint32_t mask = 0;

    for(i=0; i<512; i+=2)
    {
        mask = wsbox_table[i ^ 1] ^ w;

        mask |= mask >> 4;
        mask |= mask >> 2;
        mask |= mask >> 1;
        mask &= 0x01010101;
        mask *= 255;
        mask = ~mask;

        ret |= wsbox_table[i] & mask;
    }

    return ret;
}

static inline uint32_t invwsbox(uint32_t w, uint32_t const wsbox_table[512])
{
    int i;
    uint32_t ret = 0;
    uint32_t mask = 0;

    for(i=0; i<512; i+=2)
    {
        mask = wsbox_table[i] ^ w;

        mask |= mask >> 4;
        mask |= mask >> 2;
        mask |= mask >> 1;
        mask &= 0x01010101;
        mask *= 255;
        mask = ~mask;

        ret |= wsbox_table[i ^ 1] & mask;
    }

    return ret;
}
