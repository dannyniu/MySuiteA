/* DannyNiu/NJF, 2018-01-09. Public Domain. */

#include "asn1.h"

#define READC(label)    fsm_core = label; goto input; case label:
#define YIELD           goto core

long asn1_der_parse(asn1_term_t *restrict t, const void *restrict buf, size_t len)
{
    const uint8_t *data = buf;
    size_t left = len;
    int c;

    int fsm_core = 0; // finite state machines. 
    long terms_parsed = 0;
    
    short t_class, t_pc; int tag_value;
    
    size_t t_length, hdrlen; int t_metalength;

core:
    // TODO(2019-01-10): handle malformed encodings such as
    // length longer than buffer,
    // dangling bytes.
    
    switch( fsm_core )
    {
    case 0:
        hdrlen = 0;

        // identifier octet(s). 
        READC(1);
        t_class =   c >> 6 & 03;
        t_pc =      c >> 5 & 01;
        tag_value = c     & 037;
        
        if( tag_value == 037 )
        {
            tag_value = 0;
            do
            {
                READC(2);
                tag_value = tag_value << 7 | (c & 0177);
            }
            while( c & 0200 );
        }

        // length octet(s). 
        READC(3);
        t_length = c;
        if( t_length & 0200 )
        {
            t_metalength = t_length & 127;
            t_length = 0;
            
            while( t_metalength-- )
            {
                READC(4);
                t_length = t_length << 8 | c;
            }
        }

    tagcmp: // compare and match tag. 
        c = 1 && t->class == t_class;
        c = c && t->pc    == t_pc;
        c = c && t->tag   == tag_value;
        c = c || t->class == 256; // expecting ANY/CHOICE type.
        
        if( !c )
        {
            if( t->optional ){
                // OPTIONAL or DEFAULT keyword present,
                // count as parsed.
                terms_parsed++;
                
                if( t->next ) {
                    t += t->next;
                    goto tagcmp;
                } else return terms_parsed;
                
            } else {
                // Assume unrecognizable parts to be
                // extensions from the next version(s).
                
                if( t_length > left ){
                    data += left;
                    left = 0;    
                } else {
                    data += t_length;
                    left -= t_length;
                }
                
                break;
            }
        }

        t->class = t_class;
        t->pc    = t_pc;
        t->tag   = tag_value;
        t->ptr            = data - hdrlen;
        t->length_tlv     = hdrlen + t_length;
        t->content        = data;
        t->length_content = t_length;

        terms_parsed++;
        data += t_length;
        left -= t_length;

        if( t->firstchild )
        {
            terms_parsed += asn1_der_parse(
                t + t->firstchild,
                t->content,
                t->length_content);
        }

        if( t->next )
        {
            t += t->next;
            break;
        }
        else return terms_parsed;
    }
    fsm_core = 0;
    goto core;

input:
    if( left > 0 )
    {
        c = *data++, left--, hdrlen++;
        YIELD;
    }
    else return terms_parsed;
}
