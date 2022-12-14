if [ X"$optimize" = Xdebug ] ; then
    cflags0="$cflags0 -D ENABLE_HOSTED_HEADERS="
fi

cflags_proj="-ffreestanding"
