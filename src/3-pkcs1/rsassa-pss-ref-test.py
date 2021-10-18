#!/usr/bin/env python3

import sys, hashlib, secrets

sys.path += ["../src/1-integers", "../src/2-rsa"]

from int2os import *
from mgf import MGF1, bytesXor

# public modulus from "tests/rsa-1440-3primes.der".
N = 0xCB968CF375D8304E6DF402C5154A2E73F9D416C5C8465E489AE65376CF9F032FF12EE1CF474671208059AFC46566CDC7C80B89690795C5DE1C2FBC50EE2BB4EB9A13D3E139733CD7D0BC63CE18F1275D4384543268F5CBCA61A41C04C470E24AE2A66EF1502DC07BB86D74654140F50E5BABFA3A6CD1AC6D36ACFE807C4F34A8C79C3AEA66837B231C710151928DBFE0076EB92B58A67BE2F1E5DAEA4680543438DCD3C271D7A9D29EFC48A8D824D2AEF16C99BF

d = 0x531AA16EC02BFF8C045616CB5C656B90EBEA276194DF249D7E9D8674794BEF81227280BA9BDDA5501F147D2B2E3948C6C461F1356E6334E1F59F86BE74B447D21E62B9B8B96DC5AD3DBC6B5DF4CC3CC74312EE36B0B8BACDE94C6BF0E34FCBF7EDFB190C4DF9C3492BC15DAB1EFD5440A76A43C36C5EFCA1E260891F505C831383937341010D7C58B589DB557CE43023AE896BE14687A84CE00BD8505B905D966C5CE2A0F834F292FA6D12D9892F26809B382C01
emBits = 1440 - 1
emLen = (emBits + 7) // 8
hName = "sha256"
hLen = hashlib.new(hName).digest_size
sLen = 32
mgf = MGF1

msg = bytes(sys.argv[1], encoding="ascii")
mHash = hashlib.new(hName, msg).digest()
salt = secrets.token_bytes(sLen)
pepper = secrets.token_bytes(sLen) # the fake salt.
M_ = b'\0\0\0\0\0\0\0\0' + mHash + salt
H = hashlib.new(hName, M_).digest()
PLen = emLen - sLen - hLen - 2
PS = b'\0' * PLen
PV = secrets.token_bytes(PLen) # the fake padding string.

## Change PS to PV to test for mismatched padding string.
## Change b'\x01' to anything else to test for decoding failure.
## Change ``salt'' to ``pepper'' to test for mismatched salt.
DB = PS + b'\x01' + salt
dbMask = mgf(H, hName, emLen - hLen - 1)
maskedDB = bytesXor(DB, dbMask)

## Comment these out to test for top-most bits' decoding failure.
t = 8 * emLen - emBits
maskedDB = bytes([maskedDB[0] & (0xFF >> t)]) + maskedDB[1:]

## Change b'\xbc' to anything else to test for decoding failure.
EM = maskedDB + H + b'\xbc'

## Change ``m'' to some other integer to test for value overflow failure.
m = os2int(EM)
c = pow(m, d, N)
C = int2os(c, emLen)
sys.stdout.buffer.write(C)
