#!/usr/bin/env python3

import sys, hashlib, secrets

sys.path += ["../src/1-integers", "../src/2-rsa"]

from int2os import *
from mgf import MGF1, bytesXor

# public modulus from "tests/rsa-1440-3primes.der".
N = 0xCB968CF375D8304E6DF402C5154A2E73F9D416C5C8465E489AE65376CF9F032FF12EE1CF474671208059AFC46566CDC7C80B89690795C5DE1C2FBC50EE2BB4EB9A13D3E139733CD7D0BC63CE18F1275D4384543268F5CBCA61A41C04C470E24AE2A66EF1502DC07BB86D74654140F50E5BABFA3A6CD1AC6D36ACFE807C4F34A8C79C3AEA66837B231C710151928DBFE0076EB92B58A67BE2F1E5DAEA4680543438DCD3C271D7A9D29EFC48A8D824D2AEF16C99BF

e = 65537
k = 1440 // 8
hName = "sha256"
hLen = hashlib.new(hName).digest_size
mgf = MGF1

# Alter some of the following expresssions
# for testing decryption failure.

msg = bytes(sys.argv[1], encoding="ascii")
lHash = hashlib.new(hName).digest()
PS = b'\0' * (k - len(msg) - 2 * hLen - 2)
DB = lHash + PS + b'\x01' + msg
seed = secrets.token_bytes(hLen)
dbMask = mgf(seed, hName, k - hLen - 1)
maskedDB = bytesXor(DB, dbMask)
seedMask = mgf(maskedDB, hName, hLen)
maskedSeed = bytesXor(seed, seedMask)

EM = b'\x00' + maskedSeed + maskedDB
m = os2int(EM)
c = pow(m, e, N)
C = int2os(c, k)
sys.stdout.buffer.write(C)
