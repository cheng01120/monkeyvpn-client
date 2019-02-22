Setup
=====
> tunctl
> ifconfig tap0 192.168.2.1/24 up

On OpenWrt /etc/config/network remove any bridges on interface tap0


iptables
========

#!/bin/sh

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -t nat -F
iptables -X

iptables --policy FORWARD ACCEPT
iptables -t nat -A PREROUTING  -p tcp --dport 3128 -j DNAT --to-destination 192.168.2.1:3128
iptables -t nat -A POSTROUTING -p tcp  --dst 192.168.2.1 --dport 3128 -j MASQUERADE


Build
=====

Server:  Compile boost C++ library first, then edit server/CMakeLists.txt

> mkdir build
> cd build
> cmake ../libmonkeyvpn
> rm -fr *
> cmake ../server
> sqlite3 /etc/mvpn.db < ./utils/createdb.sql
> ./mvpn -h

Client: Compile boost C++ library, wxWidgets first, then edit client-win/CMakeLists.txt

Windows:
> mkdir build
> cd build
> cmake ..\libmonkeyvpn -G "NMake Makefiles"
> cp monkeyvpn.lib ..\libmonkeyvpn
> rm -fr *
> cmake ..\client-win -G "NMake Makefiles"
