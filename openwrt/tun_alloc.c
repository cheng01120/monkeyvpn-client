#include "tun_alloc.h"
#include <errno.h>

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  /*
  if( (err = ioctl(fd, TUNSETPERSIST, 0x1)) < 0) {
	  perror("ioctl(TUNSETIFF)");
	  close(fd);
	  return err;
  }
  */

  strcpy(dev, ifr.ifr_name);

  return fd;
}

// Find the correspondent hw address of dev.
void find_mac(const char *if_name, unsigned char *mac)
{
		struct ifaddrs *if_addrs, *if_start;
		int status;
		int i;

		if(getifaddrs(&if_start) == -1) {
			printf("Error in getifaddrs(): %d %s", errno, strerror(errno));
			return;
		}
		if_addrs = if_start;
		while(if_addrs) {
			if(strncmp(if_name, if_addrs->ifa_name, strlen(if_name)) == 0) {
				// Find interface with name 'dev'
				if(if_addrs->ifa_addr->sa_family == AF_PACKET) {
					struct sockaddr_ll * ll;

					ll = (struct sockaddr_ll *) if_addrs->ifa_addr;
					memcpy(mac, ll->sll_addr, 6);
				} // AF_LINK
			} // strncmp
			if_addrs = if_addrs->ifa_next;
		} // while
		freeifaddrs(if_start);
}

void print_mac(const unsigned char *mac)
{
	int i;
	for(i = 0; i < 5; i++) {
		printf("%02x:", mac[i] & 0xff);
	}
	printf("%02x\n", mac[5]);
}

void set_ip_address(const char *if_name, const char *ip_address)
{
	struct ifreq ifr;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

	//struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
  //inet_pton(AF_INET, "10.12.0.1", &addr->sin_addr);

  ifr.ifr_addr.sa_family = AF_INET;
  inet_pton(AF_INET, ip_address, ifr.ifr_addr.sa_data + 2);
  ioctl(fd, SIOCSIFADDR, &ifr);

  inet_pton(AF_INET, "255.255.255.0", ifr.ifr_addr.sa_data + 2);
  ioctl(fd, SIOCSIFNETMASK, &ifr);

  ioctl(fd, SIOCGIFFLAGS, &ifr);
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  ioctl(fd, SIOCSIFFLAGS, &ifr);
}
