#!/bin/sh
# build statically linked monkeyvpn client.

if [ -f ./monkeyvpn ]; then
	rm ./monkeyvpn
fi

#build PC client, uncomment this.
#CC=/usr/bin/gcc

# build openwrt client, uncomment this.
. ../env-openwrt.sh
CC=mips-openwrt-linux-gcc

$CC -I../3rdparty -I. -o monkeyvpn main.c tun_alloc.c
