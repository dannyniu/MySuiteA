# DannyNiu/NJF, 2023-03-17. Public Domain.

OBJ_COMMON = \
    src/mysuitea-common.o

OBJ_ENDIAN = \
    src/0-datum/endian.o

OBJ_INTEGERS = \
    src/1-integers/vlong.o \
    src/1-integers/vlong-dat.o

OBJ_OSLIB = \
    src/1-oslib/TCrew.o \
    src/1-oslib/TCrew-Stub.o

OBJ_SYMM = \
    src/1-symm/chacha.o \
    src/1-symm/fips-180.o \
    src/1-symm/galois128.o \
    src/1-symm/gimli.o \
    src/1-symm/keccak-f-1600.o \
    src/1-symm/poly1305.o \
    src/1-symm/rijndael.o \
    src/1-symm/sponge.o

OBJ_SYMM_X86 = \
    src/1-symm/fips-180-x86.o \
    src/1-symm/galois128-x86.o \
    src/1-symm/rijndael-x86.o

CFLAGS_SYMM_X86 = \
    -maes -mpclmul -msha -mssse3 \
    -DGENSRC_WILLBE_INCLUDED \
    -DNI_AES=NI_RUNTIME \
    -DNI_FIPS180=NI_RUNTIME \
    -DNI_GALOIS128=NI_RUNTIME

OBJ_SYMM_ARM = \
    src/1-symm/fips-180-arm.o \
    src/1-symm/galois128-arm.o \
    src/1-symm/keccak-f-1600-arm.o \
    src/1-symm/rijndael-arm.o

CFLAGS_SYMM_ARM = \
    -march=armv8.2-a+crypto+sha3 \
    -DGENSRC_WILLBE_INCLUDED \
    -DNI_AES=NI_RUNTIME \
    -DNI_FIPS180=NI_RUNTIME \
    -DNI_GALOIS128=NI_RUNTIME \
    -DNI_KECCAK=NI_RUNTIME

OBJ_SYMM_PPC = \
    src/1-symm/galois128-ppc.o \
    src/1-symm/rijndael-ppc.o

CFLAGS_SYMM_PPC = \
    -mcpu=power8 \
    -DGENSRC_WILLBE_INCLUDED \
    -DNI_AES=NI_RUNTIME \
    -DNI_FIPS180=NI_RUNTIME

OBJ_SYMM_ShangMi = \
    src/1-symm-national/gbt-32905.o \
    src/1-symm-national/sm4.o

OBJ_SYMM_ShangMi_ARM = \
    src/1-symm-national/gbt-32905-arm.o \
    src/1-symm-national/sm4-arm.o

CFLAGS_SYMM_ShangMi_ARM = \
    -march=armv8.2-a+crypto+sm4 \
    -DGENSRC_WILLBE_INCLUDED \
    -DNI_SM3=NI_RUNTIME \
    -DNI_SM4=NI_RUNTIME

OBJ_SYMM_KoreaJapan = \
    src/1-symm-national/aria.o \
    src/1-symm-national/camellia.o \
    src/1-symm-national/seed.o

OBJ_ASN1 = \
    src/2-asn1/der-codec.o

OBJ_ECC_SECG_IMPL = \
    src/2-ec/ec-common.o \
    src/2-ec/ecp-pubkey-codec.o \
    src/2-ec/ecp-xyz.o

OBJ_ECC_SECG_CRV = \
    src/2-ec/curve-secp256r1.o \
    src/2-ec/curve-secp384r1.o

OBJ_ECC_CFRG_IMPL = \
    src/2-ec/ecEd.o \
    src/2-ec/ecMt.o

OBJ_ECC_CFRG_CRV = \
    src/2-ec/modp25519.o \
    src/2-ec/modp448.o \
    src/2-ec/curve-Ed25519.o \
    src/2-ec/curve-Ed448.o \
    src/2-ec/curve25519.o \
    src/2-ec/curve448.o

# OBJ_ECC_ShangMi_IMPL = ${OBJ_ECC_SECG_IMPL}

OBJ_ECC_ShangMi_CRV = \
    src/2-ec/curveSM2.o

OBJ_CIPHERS = \
    src/2-encryption/gcm.o \
    src/2-encryption/ccm.o \
    src/2-encryption/chacha20-poly1305.o \
    src/2-encryption/gcm-aes.o \
    src/2-encryption/ccm-aes.o

OBJ_HASH = \
    src/2-hash/hash-dgst-oid-table.o \
    src/2-hash/sha.o \
    src/2-hash/sha3.o \
    src/2-hash/blake2.o \
    src/2-hash/blake3.o \
    src/2-hash/KangarooTwelve.o

OBJ_HASH_ShangMi = \
    src/2-hash/sm3.o

OBJ_MAC = \
    src/2-mac/cmac.o \
    src/2-mac/hmac.o \
    src/2-mac/kmac.o \
    src/2-mac/cmac-aes.o \
    src/2-mac/hmac-sha.o \
    src/2-mac/hmac-sha3.o

OBJ_NUMBER_THEORY = \
    src/2-numbertheory/EGCD.o \
    src/2-numbertheory/MillerRabin.o

OBJ_PRNG = \
    src/2-prng/ctr-drbg.o \
    src/2-prng/ctr-drbg-aes.o \
    src/2-prng/hmac-drbg.o \
    src/2-prng/hmac-drbg-sha.o

OBJ_RSA = \
    src/2-rsa/pkcs1-padding.o \
    src/2-rsa/rsa-enc.o \
    src/2-rsa/rsa-fastdec.o \
    src/2-rsa/rsa-keygen.o \
    src/2-rsa/rsa-privkey-parser-der.o \
    src/2-rsa/rsa-privkey-writer-der.o \
    src/2-rsa/rsa-pubkey-export-der.o \
    src/2-rsa/rsa-pubkey-parser-der.o \
    src/2-rsa/rsa-pubkey-writer-der.o

OBJ_XOF = \
    src/2-xof/gimli-xof.o \
    src/2-xof/shake.o

OBJ_ECC_COMMON = \
    src/3-ecc-common/ecc-common.o

OBJ_PKCS1 = \
    src/3-pkcs1/pkcs1-paramset-common.o \
    src/3-pkcs1/pkcs1.o \
    src/3-pkcs1/rsaes-oaep-dec.o \
    src/3-pkcs1/rsaes-oaep-enc.o \
    src/3-pkcs1/rsaes-oaep-paramset.o \
    src/3-pkcs1/rsaes-oaep.o \
    src/3-pkcs1/rsaes-pkcs1-v1_5-dec.o \
    src/3-pkcs1/rsaes-pkcs1-v1_5-enc.o \
    src/3-pkcs1/rsaes-pkcs1-v1_5-paramset.o \
    src/3-pkcs1/rsaes-pkcs1-v1_5.o \
    src/3-pkcs1/rsassa-pkcs1-v1_5-paramset.o \
    src/3-pkcs1/rsassa-pkcs1-v1_5-sign.o \
    src/3-pkcs1/rsassa-pkcs1-v1_5-verify.o \
    src/3-pkcs1/rsassa-pkcs1-v1_5.o \
    src/3-pkcs1/rsassa-pss-paramset.o \
    src/3-pkcs1/rsassa-pss-sign.o \
    src/3-pkcs1/rsassa-pss-verify.o \
    src/3-pkcs1/rsassa-pss.o

OBJ_ECPKC_CFRG = \
    src/3-rfc-7748,8032/eddsa-paramset.o \
    src/3-rfc-7748,8032/eddsa-misc.o \
    src/3-rfc-7748,8032/eddsa.o \
    src/3-rfc-7748,8032/rfc-7748-paramset.o \
    src/3-rfc-7748,8032/rfc-7748.o

OBJ_ECPKC_SECG = \
    src/3-sec1/ecdh-kem-paramset.o \
    src/3-sec1/ecdh-kem.o \
    src/3-sec1/ecdsa-paramset.o \
    src/3-sec1/ecdsa.o

OBJ_ECPKC_ShangMi = \
    src/3-sm2/sm2sig-paramset.o \
    src/3-sm2/sm2sig.o

OBJ_PQ_CRYSTALS = \
    src/1-pq-crystals/m256-codec.o \
    src/2-pq-crystals/dilithium-aux.o \
    src/2-pq-crystals/kyber-aux.o \
    src/3-pq-crystals/mldsa-paramset.o \
    src/3-pq-crystals/mldsa.o \
    src/3-pq-crystals/mlkem-paramset.o \
    src/3-pq-crystals/mlkem.o

OBJ_SPHINCS = \
    src/3-sphincs/slhdsa-paramset.o \
    src/3-sphincs/slhdsa.o \
    src/3-sphincs/sphincs-hash-params-family-sha2-common.o \
    src/3-sphincs/sphincs-hash-params-family-sha256.o \
    src/3-sphincs/sphincs-hash-params-family-sha512.o \
    src/3-sphincs/sphincs-hash-params-family-shake.o \
    src/3-sphincs/sphincs-subroutines-fors.o \
    src/3-sphincs/sphincs-subroutines-hypertree.o \
    src/3-sphincs/sphincs-subroutines-wots.o \
    src/3-sphincs/sphincs-subroutines-xmss.o

OBJS_GROUP_ALL = \
    ${OBJ_COMMON} ${OBJ_ENDIAN} ${OBJ_INTEGERS} ${OBJ_OSLIB} \
    ${OBJ_SYMM} ${OBJ_SYMM_ShangMi} ${OBJ_SYMM_KoreaJapan} \
    ${OBJ_ASN1} \
    ${OBJ_ECC_SECG_IMPL} ${OBJ_ECC_SECG_CRV} \
    ${OBJ_ECC_CFRG_IMPL} ${OBJ_ECC_CFRG_CRV} \
    ${OBJ_ECC_ShangMi_CRV} \
    ${OBJ_CIPHERS} ${OBJ_HASH} ${OBJ_HASH_ShangMi} \
    ${OBJ_MAC} ${OBJ_NUMBER_THEORY} \
    ${OBJ_PRNG} ${OBJ_RSA} ${OBJ_XOF} ${OBJ_ECC_COMMON} \
    ${OBJ_PKCS1} ${OBJ_ECPKC_CFRG} ${OBJ_ECPKC_SECG} ${OBJ_ECPKC_ShangMi} \
    ${OBJ_PQ_CRYSTALS} ${OBJ_SPHINCS}

OBJS_GROUP_X86_ADDITION = \
    ${OBJ_SYMM_X86}

CFLAGS_GROUP_X86 = \
    ${CFLAGS_SYMM_X86}

OBJS_GROUP_ARM_ADDITION = \
    ${OBJ_SYMM_ARM} ${OBJ_SYMM_ShangMi_ARM}

CFLAGS_GROUP_ARM = \
    ${CFLAGS_SYMM_ARM} ${CFLAGS_SYMM_ShangMi_ARM}

OBJS_GROUP_PPC_ADDITION = \
    ${OBJ_SYMM_PPC}

CFLAGS_GROUP_PPC = \
    ${CFLAGS_SYMM_PPC}
