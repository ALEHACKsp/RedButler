#pragma once

#define DEVICE_NAME             L"\\Device\\RedButler"
#define DOS_DEVICES_LINK_NAME   L"\\DosDevices\\RedButler"
#define DEVICE_WIN32_NAME       L"\\\\.\\RedButler"

#define BUT_IOCTL_SET_DRIVER_STATE		CTL_CODE (FILE_DEVICE_UNKNOWN, (0x1234 +  0), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BUT_IOCTL_GET_DRIVER_STATE		CTL_CODE (FILE_DEVICE_UNKNOWN, (0x1234 +  1), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define BUT_IOCTL_CHANGE_PROCESS_PROTECTION		CTL_CODE (FILE_DEVICE_UNKNOWN, (0x1234 +  10), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BUT_IOCTL_CHANGE_PROCESS_EXCLUSION		CTL_CODE (FILE_DEVICE_UNKNOWN, (0x1234 +  11), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BUT_IOCTL_CLEAR_PROCESS_ATTRIBUTES		CTL_CODE (FILE_DEVICE_UNKNOWN, (0x1234 +  12), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


#pragma pack(push, 4)

// Used by the driver to return data to userland
typedef struct _but_status_packet {
	NTSTATUS ntStatus;
	SIZE_T szAdditionalDataSize;
	union {
		BOOLEAN bState;
	} info;
} BUT_STATUS_PACKET, * PBUT_STATUS_PACKET;

typedef struct _but_process_state_packet {
	DWORD32 dwProcessId;
	BOOLEAN bProtected;
	BOOLEAN bExcluded;
} BUT_PROCESS_STATE_PACKET, * PBUT_PROCESS_STATE_PACKET;

#pragma pack(pop)