/* DannyNiu/NJF, 2018-01-09. Public Domain. */

#include "asn1.h"

#define READC(label)    fsm = label; goto input; case label:
#define YIELD           goto core

int asn1_der_parse(asn1_term_t *restrict t, const void *restrict buf, size_t len)
{
    const uint8_t *data = buf;
    size_t left = len;
    int c;

    int fsm = 0; // finite state machines. 
    
    short t_class, t_pc; int tag_value;
    
    size_t t_length, hdrlen; int t_metalength;

core:
    // TODO(2019-01-10): handle malformed encodings such as
    // length longer than buffer,
    // dangling bytes.
    
    switch( fsm )
    {
    case 0:
        hdrlen = 0;

        // identifier octet(s). 
        READC(1);
        t_class =   c >> 6 & 03;
        t_pc =      c >> 5 & 01;
        tag_value = c      & 31;
        
        if( tag_value == 31 )
        {
            tag_value = 0;
            do
            {
                READC(2);
                tag_value = tag_value << 7 | (c & 127);
            }
            while( c & 128 );
        }

        // length octet(s). 
        READC(3);
        t_length = c;
        if( t_length & 128 )
        {
            t_metalength = t_length & 127;
            t_length = 0;
            
            while( t_metalength-- )
            {
                READC(4);
                t_length = t_length << 8 | c;
            }
        }

        // checking content length and buffer length.
        // report errors to caller. 
        if( t_length > left ) return -1;
        
        if( !t ) goto skipder;

    tagcmp: // compare and match tag. 
        c = 1 && t->class == t_class;
        c = c && t->pc    == t_pc;
        c = c && t->tag   == tag_value;
        c = c || t->class == 256; // expecting ANY/CHOICE type.
        
        if( !c )
        {
            if( t->optional ){
                // OPTIONAL or DEFAULT keyword present. 
                
                if( t->next ) {
                    t += t->next;
                    goto tagcmp;
                }

                else { // parsed all terms, extensions present.
                    t = NULL;
                    goto skipder; // verify integrity then ignore. 
                }
                
            } else {
                // Assume unrecognizable parts to be
                // extensions from the next version(s).
                goto skipder; // jump to parse next term in DER. 
            }
        }

        t->class = t_class;
        t->pc    = t_pc;
        t->tag   = tag_value;
        t->ptr            = data - hdrlen;
        t->length_tlv     = hdrlen + t_length;
        t->content        = data;
        t->length_content = t_length;

        if( t->firstchild )
        {
            c = asn1_der_parse(
                t + t->firstchild,
                t->content,
                t->length_content);

            if( c == -1 ) return -1; // propagate error. 
        }

        if( t->next ) t += t->next;
        else t = NULL;

    skipder:
        data += t_length;
        left -= t_length;
        if( !t && !left ) return 0;
    }
    fsm = 0;
    goto core;

input:
    // This clause automatically eats up
    // any erroneous dangling bytes
    // and reports to caller. 
    if( left > 0 )
    {
        c = *data++, left--, hdrlen++;
        YIELD;
    }
    if( t && t->optional )
    {
        c = 0;
        YIELD;
    }
    else return -1;
}
