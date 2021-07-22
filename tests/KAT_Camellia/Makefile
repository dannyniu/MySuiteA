# DannyNiu/NJF, 2021-07-15. Public Domain.

.PHONY: all clean

all: ECB128.rsp ECB192.rsp ECB256.rsp
clean:; rm -f ../../bin/Camellia-GenKAT ECB*.rsp

ECB128.rsp ECB192.rsp ECB256.rsp: ../../bin/Camellia-GenKAT
	../../bin/Camellia-GenKAT < /dev/urandom

../../bin/Camellia-GenKAT: Camellia-GenKAT.c camellia.c
	$(CC) -o ../../bin/Camellia-GenKAT Camellia-GenKAT.c
