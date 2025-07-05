/* DannyNiu/NJF, 2025-06-15. Public Domain. */

#include "pkc-xfmt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *base64url_text = "MTIzNDU2Nzg5YWJjZGVmCg";
char *base64url_data = "123456789abcdef\n";
bool base64url_decode(char *args[])
{
    pkc_xfmt_accel_t accel = {};
    char str[16];
    int c, i;
    int tailcut = 0; // set this to test length handling.
    (void)args;

    for(c=0,i=0; i<16 && c>=0; c>=0 && i++)
    {
        c = XfmtReadByteFromBase64URL(
            base64url_text, strlen(base64url_text)-tailcut,
            &accel, 0, i, NULL);
        str[i] = c;
    }
    // printf("i==%d\n", i);
    return memcmp(str, base64url_data, i) == 0;
}

bool json_array_indexing(char *args[])
{
    json_io_t args_in = { .str = args[1], .limit = strlen(args[1]) };
    json_io_t val, end;
    val = XfmtJson_FindIndexInArray(args_in, atoi(args[2]));
    val = XfmtJson_SkipWhitespace(val);
    end = XfmtJson_Skip1Value(val);
    fwrite(val.str+val.offset, 1, end.offset-val.offset, stdout);
    return true;
}

bool json_object_indexing(char *args[])
{
    json_io_t args_in = { .str = args[1], .limit = strlen(args[1]) };
    json_io_t val, end;
    val = XfmtJson_ScanObjectForKey(args_in, args[2]);
    val = XfmtJson_SkipWhitespace(val);
    end = XfmtJson_Skip1Value(val);
    fwrite(val.str+val.offset, 1, end.offset-val.offset, stdout);
    return true;
}

bool json_object_linting(char *args[])
{
    json_io_t args_in = { .str = args[1], .limit = strlen(args[1]) };
    return XfmtJson_LintObject(args_in);
}

char *ber_integer_1 = "\x02\x12""0123456789abcdefgh\xff\xff";
char *ber_integer_2 = "\x02\x81\x83"
    "1234567812345678""1234567812345678"
    "1234567812345678""1234567812345678"
    "1234567812345678""1234567812345678"
    "1234567812345678""1234567812345678""123"
    "\xff\xff";
bool ber_integer_decode(char *args[])
{
    pkc_xfmt_accel_t accel;
    size_t len;
    int c, i;
    (void)args;

    accel = (pkc_xfmt_accel_t){};
    len = strlen(ber_integer_1);
    i = 0;
    while( true )
    {
        c = XfmtReadByteFromBERInteger(
            ber_integer_1, len, &accel, 0, i, NULL);
        if( (c == -1) == (i < 18) ) return false;
        if( c == -1 ) break;
        if( c != ber_integer_1[i + 2] ) return false;
        i++;
    }
    if( (unsigned char)ber_integer_1[i + 2] != 255 ) return false;

    accel = (pkc_xfmt_accel_t){};
    len = strlen(ber_integer_2);
    i = 0;
    while( true )
    {
        c = XfmtReadByteFromBERInteger(
            ber_integer_2, len, &accel, 0, i, NULL);
        if( (c == -1) == (i < 128+3) ) return false;
        if( c == -1 ) break;
        if( c != ber_integer_2[i + 3] ) return false;
        i++;
    }
    if( (unsigned char)ber_integer_2[i + 3] != 255 ) return false;

    return true;
}

bool (*testcases[])(char *args[]) = {
    base64url_decode,
    json_array_indexing,
    json_object_indexing,
    json_object_linting,
    ber_integer_decode,
};

int main(int argc, char *argv[])
{
    // fprintf(stderr, "%ld\n", __STDC_VERSION__);
    return testcases[atoi(argv[1])](argv+1) ? EXIT_SUCCESS : EXIT_FAILURE;
}
