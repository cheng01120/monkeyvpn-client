#ifndef _alloc_h_
#define _alloc_h_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/param.h>
#include <ifaddrs.h>
#include <errno.h>
#include <linux/if_packet.h>

int  tun_alloc(char *, int);
void find_mac(const char *if_name, unsigned char *mac);
void print_mac(const unsigned char *mac);
void set_ip_address(const char *if_name, const char *ip_address);

#endif
