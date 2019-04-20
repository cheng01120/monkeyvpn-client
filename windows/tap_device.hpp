#ifndef _tap_device_
#define _tap_device_

#include "uECC.h"
#include "lzf.h"

#include <wx/wx.h>
#include <wx/msw/registry.h>
#include <wx/string.h>

#include <winioctl.h>
#define _TAP_IOCTL(nr) CTL_CODE(FILE_DEVICE_UNKNOWN, nr, METHOD_BUFFERED, \
                FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               _TAP_IOCTL(1)
#define TAP_IOCTL_GET_VERSION           _TAP_IOCTL(2)
#define TAP_IOCTL_GET_MTU               _TAP_IOCTL(3)
#define TAP_IOCTL_GET_INFO              _TAP_IOCTL(4)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT _TAP_IOCTL(5)
#define TAP_IOCTL_SET_MEDIA_STATUS      _TAP_IOCTL(6)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      _TAP_IOCTL(7)
#define TAP_IOCTL_GET_LOG_LINE          _TAP_IOCTL(8)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   _TAP_IOCTL(9)
#define TAP_IOCTL_CONFIG_TUN            _TAP_IOCTL(10)

wxString GetDeviceGuid(void);
HANDLE OpenDevice();
void GetMacAddress(HANDLE, unsigned char *);
void EnableDevice(HANDLE h);
// to set interface ipaddress see
// https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-addipaddress


#endif
