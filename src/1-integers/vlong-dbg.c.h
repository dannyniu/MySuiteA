/* DannyNiu/NJF, 2022-02-06. Public Domain. */

void printl(vlong_t const *x)
{
    printf("0x");
    for(vlong_size_t t = x->c; t--; ) printf("%08x", x->v[t]);
}

void randoml(vlong_t *ff)
{
    memset(ff->v, 0, sizeof(*ff->v) * ff->c);
    fread(ff->v, 1, sizeof(*ff->v) * (ff->c - 2), stdin);
}
