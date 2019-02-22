#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <net/if.h>
#include <linux/if_tun.h>

MODULE = MonkeyVPN		PACKAGE = MonkeyVPN		

TYPEMAP: <<END
const char *    T_PV
const uint8_t *    T_PV
uint8_t * T_PV
END

void 
crypt_xor(SV *sv_string, SV *sv_secret)
	CODE:
		STRLEN string_size, secret_size;
		uint8_t *string = (uint8_t *)SvPVbyte(sv_string, string_size);
		uint8_t *secret = (uint8_t *)SvPVbyte(sv_secret, secret_size);
		// xor encrypt the buffer
		int m, n;
		for(m = 0; m < string_size; m++) {
			n = m % secret_size;
			string[m] ^= secret[n];
		}

PerlIO *
tun_alloc(char *dev)
	CODE:
		struct ifreq ifr;
		int fd, err;
		const char *clonedev = "/dev/net/tun";

		if( (fd = open(clonedev , O_RDWR)) < 0 ) {
			perror("Opening /dev/net/tun");
			RETVAL =  NULL;
		}
		else {
			memset(&ifr, 0, sizeof(ifr));

			ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

			if (*dev) {
				strncpy(ifr.ifr_name, dev, IFNAMSIZ);
			}

			if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
				perror("ioctl(TUNSETIFF)");
				close(fd);
				RETVAL =  NULL;
			}
			else {

				/*
				if( (err = ioctl(fd, TUNSETPERSIST, 0x1)) < 0) {
				  perror("ioctl(TUNSETIFF)");
				  close(fd);
				  return err;
				}
				*/

				strcpy(dev, ifr.ifr_name);

				RETVAL =  PerlIO_fdopen(fd, "r+");
			}
		}
	OUTPUT:
		RETVAL
