# Setup
> tunctl  <br/>
> ifconfig tap0 192.168.2.1/24 up<br/>

On OpenWrt /etc/config/network remove any bridges on interface tap0


# OpenWrt and squid

#redirect traffic to openwrt port 3128 to vpn server port 3128 <br/>

#!/bin/sh  

echo 1 > /proc/sys/net/ipv4/ip_forward  

iptables -F  
iptables -t nat -F  
iptables -X  

iptables --policy FORWARD ACCEPT  
iptables -t nat -A PREROUTING  -p tcp --dport 3128 -j DNAT --to-destination 192.168.2.1:3128  
iptables -t nat -A POSTROUTING -p tcp  --dst 192.168.2.1 --dport 3128 -j MASQUERADE  


# github

> git pull github master --allow-unrelated-histories

# Client setup

To forward all traffic via VPN:
**First add a host route to your vpn server** so when you delete the default gateway you can
still contact your vpn server. Second delete the original default gateway and add the default
gateway pointing to your vpn server.


# VPN server setup

if public ip is 1.2.3.4 on eth0, vpn is 192.168.2.1 on tap0: <br/>

> sysctl -w net.ipv4.ip_forward=1 <br/>
> iptables -t nat -A POSTROUTING ! -d 192.168.0.0/16 -o eth0 -j SNAT --to-source 1.2.3.4<br/>
