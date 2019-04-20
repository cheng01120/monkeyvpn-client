#include "tap_device.hpp"
#define KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

wxString GetDeviceGuid(void) {
	wxString guid;

	wxRegKey key(wxRegKey::HKLM, KEY);
	key.Open(wxRegKey::AccessMode::Read);

	size_t subkeys;
	long l;
	key.GetKeyInfo(&subkeys, NULL, NULL, NULL);
	wxString key_name;
	key.GetFirstKey(key_name, l);
	for(size_t i = 0; i < subkeys; i++) {
		wxString component_id;
		wxRegKey subkey(key, key_name);
		subkey.QueryValue("ComponentId", component_id);
		if(component_id.IsSameAs("tap0901") || component_id.IsSameAs("tap0801")) {
			subkey.QueryValue("NetCfgInstanceId", guid);
			break;
		}

		key.GetNextKey(key_name, l);
	}

	return guid;
}

HANDLE OpenDevice() {
	wxString guid = GetDeviceGuid();

	wxString devName = wxString::Format("\\\\.\\Global\\%s.tap", guid);
  HANDLE handle = CreateFile(devName,
			  GENERIC_READ | GENERIC_WRITE,
			  FILE_SHARE_READ | FILE_SHARE_WRITE,
			  NULL, 
				OPEN_EXISTING,
			  FILE_ATTRIBUTE_SYSTEM |  FILE_FLAG_OVERLAPPED ,
			  NULL
		  );

	return handle;
}

void GetMacAddress(HANDLE h, unsigned char *mac) {
	DWORD len;
	DeviceIoControl(h, TAP_IOCTL_GET_MAC, mac, 6, mac, 6, &len, NULL);
}

void EnableDevice(HANDLE h) {
	DWORD len;
	int enable = 1;
	DeviceIoControl(h, TAP_IOCTL_SET_MEDIA_STATUS, &enable, sizeof(enable), &enable, sizeof(enable), &len, NULL);
}
