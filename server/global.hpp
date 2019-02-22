#ifndef _global_hpp_
#define _global_hpp_

#include <deque>
#include <set>
#include <list>
#include <memory>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <regex>

extern "C" {
#include <stdio.h>
#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#ifdef __FreeBSD__
#include <net/if_dl.h>
#include <net/if_types.h>
#elif __linux__
#include <linux/if_packet.h>
#endif
}

#include "tun_alloc.hpp"
#include "vl_packet.hpp"
#include "monkeyvpn/uECC.h"
#include "monkeyvpn/aes.h"
#include "monkeyvpn/lzf.h"
#include "auth_sqlite3.hpp"

#include "trace.hpp"

#define uECC_CURVE uECC_secp256k1()

// server ECDH key.

// server ->  hub  -> session (port)
using boost::asio::ip::tcp;
using boost::system::error_code;
namespace ba = boost::asio;

#endif
