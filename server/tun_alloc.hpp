#ifndef _alloc_hpp_
#define _alloc_hpp_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __linux__

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

int tun_alloc(char *, int);

#endif

#ifdef __cplusplus
}
#endif


#endif
