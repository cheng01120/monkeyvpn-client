#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "lzf.h"
#include "lzf_c.c"
#include "lzf_d.c"


MODULE = LZF		PACKAGE = LZF		

TYPEMAP: <<END
const char *    T_PV
const uint8_t *    T_PV
uint8_t * T_PV
END

SV *
compress(SV *sv_in_data)
	CODE:
		STRLEN in_data_size;
		char *in_data = (char *)SvPVbyte(sv_in_data, in_data_size);

		char out_data[2048]; // max lzf chunk 2048
		unsigned int out_len;
		SV *d;

		out_len = lzf_compress(in_data, in_data_size, out_data, 2048);
		d = newSVpv(out_data, out_len);
		RETVAL = d;
	OUTPUT:
		RETVAL

SV *
decompress(SV *sv_in_data)
	CODE:
		STRLEN in_data_size;
		char *in_data = (char *)SvPVbyte(sv_in_data, in_data_size);

		char out_data[2048];
		unsigned int out_len;
		SV* d;

		out_len = lzf_decompress(in_data, in_data_size, out_data, 2048);
		d = newSVpv(out_data, out_len);
		RETVAL = d;
	OUTPUT:
		RETVAL
