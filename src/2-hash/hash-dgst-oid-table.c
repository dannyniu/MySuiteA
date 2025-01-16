/* DannyNiu/NJF, 2024-10-22. Public Domain. */

#include "hash-dgst-oid-table.h"
#include "../0-datum/endian.h"

static hash_dgst_oid_row_t table[] = {
    { .lo = 0xda39a3ee5e6b4b0d, .hi = 0x3255bfef95601890, // SHA-1.
      .oid = "\x06\x05\x2b\x0e\x03\x02\x1a", .oidlen = 7 },

    { .lo = 0xe3b0c44298fc1c14, .hi = 0x9afbf4c8996fb924, // SHA-256.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", .oidlen = 11 },

    { .lo = 0x38b060a751ac9638, .hi = 0x4cd9327eb1b1e36a, // SHA-384.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02", .oidlen = 11 },

    { .lo = 0xcf83e1357eefb8bd, .hi = 0xf1542850d66d8007, // SHA-512.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", .oidlen = 11 },

    { .lo = 0xd14a028c2a3a2bc9, .hi = 0x476102bb288234c4, // SHA-224.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04", .oidlen = 11 },

    { .lo = 0x6ed0dd02806fa89e, .hi = 0x25de060c19d3ac86, // SHA-512/224.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05", .oidlen = 11 },

    { .lo = 0xc672b8d1ef56ed28, .hi = 0xab87c3622c511406, // SHA-512/256.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06", .oidlen = 11 },

    { .lo = 0x6b4e03423667dbb7, .hi = 0x3b6e15454f0eb1ab, // SHA3-224.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07", .oidlen = 11 },

    { .lo = 0xa7ffc6f8bf1ed766, .hi = 0x51c14756a061d662, // SHA3-256.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08", .oidlen = 11 },

    { .lo = 0x0c63a75b845e4f7d, .hi = 0x01107d852e4c2485, // SHA3-384.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09", .oidlen = 11 },

    { .lo = 0xa69f73cca23a9ac5, .hi = 0xc8b567dc185a756e, // SHA3-512.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a", .oidlen = 11 },

    { .lo = 0x7f9c2ba4e88f827d, .hi = 0x616045507605853e, // SHAKE-128.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b", .oidlen = 11 },

    { .lo = 0x46b9dd2b0ba88d13, .hi = 0x233b3feb743eeb24, // SHAKE-256.
      .oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c", .oidlen = 11 },

    {0}
};

hash_dgst_oid_row_t *hash_dgst_oids = table;

int MsgHash_FindOID(hash_funcs_set_t *hfnx, void *hctx)
{
    if( !hfnx->initfunc ) { return 0; } else
    {
        uint64_t dgst[2];
        int ind;

        hfnx->initfunc(hctx);
        if( hfnx->xfinalfunc )
            hfnx->xfinalfunc(hctx);
        hfnx->hfinalfunc(hctx, dgst, 16);

        for(ind = 0; hash_dgst_oids[ind].oid; ind++)
        {
            if( be64toh(dgst[0]) != hash_dgst_oids[ind].lo ) continue;
            if( be64toh(dgst[1]) != hash_dgst_oids[ind].hi ) continue;
            break;
        }

        if( !hash_dgst_oids[ind].oid ) return -1;
        else return ind;
    }
}
