/* DannyNiu/NJF, 2018-01-09. Public Domain. */

#include "../mysuitea-common.h"
#include "asn1.h"

#include <stdio.h>
#include <stdlib.h>

static asn1_term_t at_x509[] = {
    /*0*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  0,  1, }, // 1: Certificate
    /*1*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0, 15,  1, }, // 2:  tbsCertificate
    /*2*/{ 2, 1, 0,  0,  NULL, { NULL }, 0, { NULL }, 0,  2,  1, }, // 3:   [0]
    /*3*/{ 0, 0, 0,  2,  NULL, { NULL }, 0, { NULL }, 0,  0,  0, }, // 4:    version
    /*2*/{ 0, 0, 0,  2,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, // 5:   serialNumber
    /*2*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  3,  1, }, // 6:   signature
    /*3*/{ 0, 0, 0,  6,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, // 7:    algorithm
    /*3*/{ 256,0,1,  0,  NULL, { NULL }, 0, { NULL }, 0,  0,  0, }, // o:    parameters
    /*2*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, // 8:   issuer
    /*2*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, // 25:  validity
    /*2*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, // 28:  subject
    /*2*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  0,  1, }, // 65:  subjectPublicKeyInfo
    /*3*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  3,  1, }, // 66:   algorithm
    /*4*/{ 0, 0, 0,  6,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, // 67:    algorithm
    /*4*/{ 256,0,1,  0,  NULL, { NULL }, 0, { NULL }, 0,  0,  0, }, // o:     parameters
    /*3*/{ 0, 0, 0,  3,  NULL, { NULL }, 0, { NULL }, 0,  0,  0, }, // 69:   subjectPublicKey
    /*1*/{ 0, 1, 0, 16,  NULL, { NULL }, 0, { NULL }, 0,  3,  1, }, //104: signatureAlgorithm
    /*2*/{ 0, 0, 0,  6,  NULL, { NULL }, 0, { NULL }, 0,  1,  0, }, //105:  algorithm
    /*2*/{ 256,0,1,  0,  NULL, { NULL }, 0, { NULL }, 0,  0,  0, }, // o:   parameters
    /*1*/{ 0, 0, 0,  3,  NULL, { NULL }, 0, { NULL }, 0,  0,  0, }, //106: signatureValue
};

static uint8_t danglings[] = {
    0x30, 0x10,
    /**/  0x02, 0x01, 0x90, 
    /**/  0x02, 0x01, 0x90,
    /**/  0,0,  0,0,0,0, 0,0,0,0,
};

static asn1_term_t dangles[] = {
    { 0, 1, 0, 16, NULL, { NULL }, 0, { NULL }, 0, 0, 1, }, 
    { 0, 0, 0,  2, NULL, { NULL }, 0, { NULL }, 0, 1, 0, }, 
    { 0, 0, 0,  2, NULL, { NULL }, 0, { NULL }, 0, 0, 0, },
};

void printhex(const uint8_t *data, size_t len)
{
    size_t i;
    printf("%zd,%p: ", len, data);
    
    if( len > 12 )
    {
        for(i=0; i<8; i++) printf("%02X ", data[i]);

        printf("... ");
        
        for(i=0; i<4; i++) printf("%02X ", data[i+len-4]);
    }
    else for(i=0; i<len; i++) printf("%02X ", data[i]);

    printf("\n");
}

void printterm(const asn1_term_t *t, int depth)
{
    do
    {
        printf("%-3d %-5d %-5d %-5d %-5d \n", depth, t->class, t->pc, t->optional, t->tag);
        printf("\t"); printhex(t->ptr, t->length_tlv);
        printf("\t"); printhex(t->content, t->length_content);
        if( t->firstchild ) printterm(t + t->firstchild, depth+1);
    }
    while( t->next && (t += t->next) );
}

int main()
{
    long len;
    void *buf;

    fseek(stdin, 0, SEEK_END);
    len = ftell(stdin);
    fseek(stdin, 0, SEEK_SET);
    
    buf = malloc(len);
    fread(buf, 1, len, stdin);

    len = asn1_der_parse(at_x509, buf, len);
    // len = asn1_der_parse(dangles, danglings, 18);
    printf("return code: %ld\n", len);
    printterm(at_x509, 0);
    // printterm(dangles, 0);
    free(buf);
}
