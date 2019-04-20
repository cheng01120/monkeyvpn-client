Setup
=====
> tunctl
> ifconfig tap0 192.168.2.1/24 up

On OpenWrt /etc/config/network remove any bridges on interface tap0


iptables
========

#redirect traffic to openwrt port 3128 to vpn server port 3128

#!/bin/sh

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -t nat -F
iptables -X

iptables --policy FORWARD ACCEPT
iptables -t nat -A PREROUTING  -p tcp --dport 3128 -j DNAT --to-destination 192.168.2.1:3128
iptables -t nat -A POSTROUTING -p tcp  --dst 192.168.2.1 --dport 3128 -j MASQUERADE


github
======
git pull github master --allow-unrelated-histories
