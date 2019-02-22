#ifndef _trace_hpp_
#define _trace_hpp_

#define VL_TRACE 0
#define VL_INFO  1
#define VL_ERROR 2

#define TRACE_LEVEL VL_INFO

#define ec2str(ec) ec.message().c_str()

#include <cstdio>

void TRACE(int priority, const char *format, ...)
{
	if(priority < TRACE_LEVEL) return;
	char message[4096] = "";

	va_list args;
	va_start(args, format);
	vsnprintf(message, 4096 - 1, format, args);
	va_end(args);

	printf("%s\n", message);
}

#endif
