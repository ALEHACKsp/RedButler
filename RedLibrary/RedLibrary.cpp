#include "RedLibrary.h"
#include "../RedDriver/DeviceAPI.h"

#include <Windows.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <wchar.h>

using namespace Red;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_RELATIVE_NAME {
	UNICODE_STRING RelativeName;
	HANDLE         ContainingDirectory;
	void* CurDirRef;
} RTL_RELATIVE_NAME, * PRTL_RELATIVE_NAME;

typedef BOOLEAN(NTAPI* RtlDosPathNameToRelativeNtPathName_U_Prototype)(
	_In_       PCWSTR DosFileName,
	_Out_      PUNICODE_STRING NtFileName,
	_Out_opt_  PWSTR* FilePath,
	_Out_opt_  PRTL_RELATIVE_NAME RelativeName
	);

bool ConvertToNtPath(const wchar_t* path, wchar_t* normalized, size_t normalizedLen) {
	UNICODE_STRING ntPath;
	DWORD size;
	bool result = false;

	size = GetFullPathNameW(path, (DWORD)normalizedLen, normalized, NULL);
	if (size == 0)
		return false;

	memset(&ntPath, 0, sizeof(ntPath));

	RtlDosPathNameToRelativeNtPathName_U_Prototype RtlDosPathNameToRelativeNtPathName_U = nullptr;
	*(FARPROC*)&RtlDosPathNameToRelativeNtPathName_U = GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"),
		"RtlDosPathNameToRelativeNtPathName_U"
	);

	if (RtlDosPathNameToRelativeNtPathName_U(normalized, &ntPath, NULL, NULL) == FALSE)
		return false;

	if (normalizedLen * sizeof(wchar_t) > ntPath.Length) {
		memcpy(normalized, ntPath.Buffer, ntPath.Length);
		normalized[ntPath.Length / sizeof(wchar_t)] = L'\0';
		result = true;
	}

	HeapFree(GetProcessHeap(), 0, ntPath.Buffer);

	return result;
}

NTSTATUS AllocNormalizedPath(const wchar_t* path, wchar_t** normalized) {
	enum { NORMALIZATION_OVERHEAD = 32 };
	wchar_t* buf;
	size_t len;

	len = wcslen(path) + NORMALIZATION_OVERHEAD;

	buf = (wchar_t*)malloc(len * sizeof(wchar_t));
	if (!buf)
		return ERROR_NOT_ENOUGH_MEMORY;

	if (!ConvertToNtPath(path, buf, len)) {
		free(buf);
		return ERROR_INVALID_DATA;
	}

	*normalized = buf;
	return ERROR_SUCCESS;
}

// ====================================================================

Exception::Exception(unsigned int code, const wchar_t* format, ...) : errorCode(code) {
	wchar_t buffer[256];

	va_list args;
	va_start(args, format);
	_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
	va_end(args);

	errorMessage = buffer;
}

const wchar_t* Exception::What() {
	return errorMessage.c_str();
}

unsigned int Exception::Code() {
	return errorCode;
}

Butler::Butler() : hDriver(NULL) {
	deviceName = DEVICE_WIN32_NAME;
}

Butler::Butler(std::wstring deviceName) : hDriver(NULL) {
	deviceName = deviceName;
}

bool Butler::IsOpen() {
	return hDriver != NULL;
}

void Butler::Open() {
	if (IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection already in place.");
	}

	hDriver = CreateFileW(
		deviceName.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDriver == INVALID_HANDLE_VALUE) {
		hDriver = NULL;
		throw Red::Exception(STATUS_INVALID_HANDLE, L"Failed to set up driver connection.");
	}
}

void Butler::Close() {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	CloseHandle(hDriver);
	hDriver = NULL;
}

void Butler::SetState(bool state) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	DWORD dwReturned;
	BOOLEAN bState = state ? TRUE : FALSE;
	if (!DeviceIoControl(hDriver, BUT_IOCTL_SET_DRIVER_STATE, &bState,
		sizeof(BOOLEAN), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to set driver state.");
	}
}

bool Butler::GetState() {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	DWORD dwReturned;
	if (!DeviceIoControl(hDriver, BUT_IOCTL_GET_DRIVER_STATE, &result,
		sizeof(BUT_STATUS_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to get driver state.");
	}

	return result.info.bState;
}

void Butler::ProtectProcess(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.bProtected = TRUE;
	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_CHANGE_PROCESS_PROTECTION, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to protect target process.");
	}
}

void Butler::UnprotectProcess(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.bProtected = FALSE;
	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_CHANGE_PROCESS_PROTECTION, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to unprotect target process.");
	}
}

bool Butler::IsProtected(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_GET_PROCESS_ATTRIBUTES, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to get process protection state.");
	}

	return packet.bProtected == TRUE;
}

void Butler::ExcludeProcess(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.bExcluded = TRUE;
	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_CHANGE_PROCESS_EXCLUSION, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to exclude target process.");
	}
}

void Butler::UnexcludeProcess(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.bExcluded = FALSE;
	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_CHANGE_PROCESS_EXCLUSION, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to unexclude target process.");
	}
}

bool Butler::IsExcluded(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_GET_PROCESS_ATTRIBUTES, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to get process exclusion state.");
	}

	return packet.bExcluded == TRUE;
}

void Butler::ClearProcessAttributes(DWORD dwProcessId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_PROCESS_STATE_PACKET packet;
	DWORD dwReturned;

	packet.dwProcessId = dwProcessId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_CLEAR_PROCESS_ATTRIBUTES, &packet,
		sizeof(BUT_PROCESS_STATE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to clear target process attributes.");
	}
}

void Butler::InjectDLL(DWORD dwProcessId, std::wstring dllPath) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_DLL_INJECTION_PACKET packet;
	DWORD dwReturned;

	packet.dwProcessId = dwProcessId;
	wchar_t* normalized;

	AllocNormalizedPath(dllPath.c_str(), &normalized);
	wcscpy(packet.wDllPath, normalized);

	if (!DeviceIoControl(hDriver, BUT_IOCTL_INJECT_DLL, &packet,
		sizeof(BUT_DLL_INJECTION_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to inject DLL in target process.");
	}
}

ULONG Butler::HideFile(std::wstring filePath) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_HIDE_FILE_PACKET packet;
	DWORD dwReturned;
	wchar_t* normalized;

	AllocNormalizedPath(filePath.c_str(), &normalized);
	wcscpy(packet.wFullPath, normalized);

	if (!DeviceIoControl(hDriver, BUT_IOCTL_HIDE_FILE, &packet,
		sizeof(BUT_HIDE_FILE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to hide target file.");
	}

	return packet.uObjectId;
}

void Butler::UnhideFile(ULONG uObjectId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_UNHIDE_FILE_PACKET packet;
	DWORD dwReturned;

	packet.uObjectId = uObjectId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_UNHIDE_FILE, &packet,
		sizeof(BUT_UNHIDE_FILE_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to unhide target file.");
	}
}

void Butler::UnhideAllFiles() {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	DWORD dwReturned;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_UNHIDE_ALL_FILES, NULL, 0,
		&result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {
		throw Red::Exception(result.ntStatus, L"Failed to unhide all files.");
	}
}

ULONG Butler::HideDirectory(std::wstring directoryPath) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_HIDE_DIRECTORY_PACKET packet;
	DWORD dwReturned;

	wchar_t* normalized;

	AllocNormalizedPath(directoryPath.c_str(), &normalized);
	wcscpy(packet.wFullPath, normalized);

	if (!DeviceIoControl(hDriver, BUT_IOCTL_HIDE_DIRECTORY, &packet,
		sizeof(BUT_HIDE_DIRECTORY_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to hide target directory.");
	}

	return packet.uObjectId;
}

void Butler::UnhideDirectory(ULONG uObjectId) {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	BUT_UNHIDE_DIRECTORY_PACKET packet;
	DWORD dwReturned;

	packet.uObjectId = uObjectId;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_UNHIDE_DIRECTORY, &packet,
		sizeof(BUT_UNHIDE_DIRECTORY_PACKET), &result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {

		throw Red::Exception(result.ntStatus, L"Failed to unhide target directory.");
	}
}

void Butler::UnhideAllDirectories() {
	if (!IsOpen()) {
		throw Red::Exception(STATUS_INTERRUPTED, L"Driver connection not in place.");
	}

	BUT_STATUS_PACKET result;
	DWORD dwReturned;

	if (!DeviceIoControl(hDriver, BUT_IOCTL_UNHIDE_ALL_DIRECTORIES, NULL, 0,
		&result, sizeof(BUT_STATUS_PACKET), &dwReturned, NULL)) {
		throw Red::Exception(result.ntStatus, L"Failed to unhide all directories.");
	}
}
