/* DannyNiu/NJF, 2023-11-17. Public Domain. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*readhex_callback_t)(
    const char *label, void *datptr, size_t datlen);

void readhex(FILE *fp, readhex_callback_t cb)
{
    char label[64] = {0};
    uint8_t buf[64];
    uint8_t *data = NULL;
    size_t len = 0, filled = 0, i;
    int c;

next:
    data = NULL;
    len = filled = 0;

    for(i=0; i<sizeof(label); i++)
        label[i] = 0;

    for(i=0; (c = getc(fp)) != EOF && i<sizeof(label); i++)
    {
        label[i] = tolower(c);
        if( c == ':' || c == '#' || c == '\n' ) break;
    }

    if( i >= sizeof(label) )
    {
        fprintf(stderr, "buffer overflow: label\n");
        exit(EXIT_FAILURE);
    }

    if( c == '#' )
        while( (c = getc(fp)) != EOF )
            if( c == '\n' )
                break;

    if( c == '\n' )
        goto next;

    if( i == 0 )
        return; // nothing meaningful read.

    while( (c = getc(fp)) != EOF )
    {
        if( c == '\n' || filled >= sizeof(buf) )
        {
        buf_flush:
            data = realloc(data, len + filled);
            for(i=0; i<filled; i++)
                data[len ++] = buf[i];
            filled = 0;

            if( c == '\n' )
            {
                cb(label, data, len);
                goto next;
            }
        }

        ungetc(c, fp);
        fscanf(fp, " %2hhx", buf + (filled++));
    }

    c = '\n';
    goto buf_flush;
}
