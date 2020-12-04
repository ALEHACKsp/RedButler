#include "Helper.h"
#include "Logging.h"

#define HELPER_ALLOC_TAG 'rplH'

// ====================================================================

NTSTATUS ResolveSymbolicLink(PUNICODE_STRING pLink, PUNICODE_STRING pResolved) {
	OBJECT_ATTRIBUTES attribs;
	HANDLE hsymLink;
	ULONG written;
	NTSTATUS status = STATUS_SUCCESS;

	// Open symlink
	InitializeObjectAttributes(&attribs, pLink, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenSymbolicLinkObject(&hsymLink, GENERIC_READ, &attribs);
	if (!NT_SUCCESS(status))
		return status;

	// Query original name
	status = ZwQuerySymbolicLinkObject(hsymLink, pResolved, &written);
	ZwClose(hsymLink);
	if (!NT_SUCCESS(status))
		return status;

	return status;
}

NTSTATUS NormalizeDevicePath(PCUNICODE_STRING pPath, PUNICODE_STRING pNormalized) {
	UNICODE_STRING globalPrefix, dvcPrefix, sysrootPrefix;
	NTSTATUS status;

	RtlInitUnicodeString(&globalPrefix, L"\\??\\");
	RtlInitUnicodeString(&dvcPrefix, L"\\Device\\");
	RtlInitUnicodeString(&sysrootPrefix, L"\\SystemRoot\\");

	if (RtlPrefixUnicodeString(&globalPrefix, pPath, TRUE)) {
		OBJECT_ATTRIBUTES attribs;
		UNICODE_STRING subPath;
		HANDLE hsymLink;
		ULONG i, written, size;

		subPath.Buffer = (PWCH)((PUCHAR)pPath->Buffer + globalPrefix.Length);
		subPath.Length = pPath->Length - globalPrefix.Length;

		for (i = 0; i < subPath.Length; i++) {
			if (subPath.Buffer[i] == L'\\') {
				subPath.Length = (USHORT)(i * sizeof(WCHAR));
				break;
			}
		}

		if (subPath.Length == 0)
			return STATUS_INVALID_PARAMETER_1;

		subPath.Buffer = pPath->Buffer;
		subPath.Length += globalPrefix.Length;
		subPath.MaximumLength = subPath.Length;

		// Open symlink
		InitializeObjectAttributes(&attribs, &subPath, OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwOpenSymbolicLinkObject(&hsymLink, GENERIC_READ, &attribs);
		if (!NT_SUCCESS(status))
			return status;

		// Query original name
		status = ZwQuerySymbolicLinkObject(hsymLink, pNormalized, &written);
		ZwClose(hsymLink);
		if (!NT_SUCCESS(status))
			return status;

		// Construct new variable
		size = pPath->Length - subPath.Length + pNormalized->Length;
		if (size > pNormalized->MaximumLength)
			return STATUS_BUFFER_OVERFLOW;

		subPath.Buffer = (PWCH)((PUCHAR)pPath->Buffer + subPath.Length);
		subPath.Length = pPath->Length - subPath.Length;
		subPath.MaximumLength = subPath.Length;

		status = RtlAppendUnicodeStringToString(pNormalized, &subPath);
		if (!NT_SUCCESS(status))
			return status;
	} else if (RtlPrefixUnicodeString(&dvcPrefix, pPath, TRUE)) {
		pNormalized->Length = 0;
		status = RtlAppendUnicodeStringToString(pNormalized, pPath);
		if (!NT_SUCCESS(status))
			return status;
	} else if (RtlPrefixUnicodeString(&sysrootPrefix, pPath, TRUE)) {
		UNICODE_STRING subPath, resolvedLink, winDir;
		WCHAR buffer[64];
		SHORT i;

		// Open symlink
		subPath.Buffer = sysrootPrefix.Buffer;
		subPath.MaximumLength = subPath.Length = sysrootPrefix.Length - sizeof(WCHAR);

		resolvedLink.Buffer = buffer;
		resolvedLink.Length = 0;
		resolvedLink.MaximumLength = sizeof(buffer);

		status = ResolveSymbolicLink(&subPath, &resolvedLink);
		if (!NT_SUCCESS(status))
			return status;

		// \Device\Harddisk0\Partition0\Windows -> \Device\Harddisk0\Partition0
		// Win10: \Device\BootDevice\Windows -> \Device\BootDevice
		winDir.Length = 0;
		for (i = (resolvedLink.Length - sizeof(WCHAR)) / sizeof(WCHAR); i >= 0; i--)
		{
			if (resolvedLink.Buffer[i] == L'\\')
			{
				winDir.Buffer = resolvedLink.Buffer + i;
				winDir.Length = resolvedLink.Length - (i * sizeof(WCHAR));
				winDir.MaximumLength = winDir.Length;
				resolvedLink.Length = (i * sizeof(WCHAR));
				break;
			}
		}

		// \Device\Harddisk0\Partition0 -> \Device\HarddiskVolume1
		// Win10: \Device\BootDevice -> \Device\HarddiskVolume2
		status = ResolveSymbolicLink(&resolvedLink, pNormalized);
		if (!NT_SUCCESS(status))
			return status;

		// Construct new variable
		subPath.Buffer = (PWCHAR)((PCHAR)pPath->Buffer + sysrootPrefix.Length - sizeof(WCHAR));
		subPath.MaximumLength = subPath.Length = pPath->Length - sysrootPrefix.Length + sizeof(WCHAR);

		status = RtlAppendUnicodeStringToString(pNormalized, &winDir);
		if (!NT_SUCCESS(status))
			return status;

		status = RtlAppendUnicodeStringToString(pNormalized, &subPath);
		if (!NT_SUCCESS(status))
			return status;
	} else {
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

NTSTATUS QuerySystemInformation(SYSTEM_INFORMATION_CLASS infoClass, PVOID* pInfoBuffer, PSIZE_T pInfoSize) {
	PVOID info = NULL;
	NTSTATUS status;
	ULONG size = 0, written = 0;

	// Query required size
	status = ZwQuerySystemInformation(infoClass, 0, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return status;

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		size += written; // We should allocate little bit more space

		if (info)
			ExFreePoolWithTag(info, HELPER_ALLOC_TAG);

		info = ExAllocatePoolWithTag(NonPagedPool, size, HELPER_ALLOC_TAG);
		if (!info)
			break;

		status = ZwQuerySystemInformation(infoClass, info, size, &written);
	}

	if (!info)
		return STATUS_ACCESS_DENIED;

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(info, HELPER_ALLOC_TAG);
		return status;
	}

	*pInfoBuffer = info;
	*pInfoSize = size;

	return status;
}

NTSTATUS QueryProcessInformation(PROCESSINFOCLASS peClass, HANDLE hProcess,
	PVOID* pInfoBuffer, PSIZE_T pInfoSize) {

	PVOID info = NULL;
	NTSTATUS status;
	ULONG size = 0, written = 0;

	// Query required size
	status = ZwQueryInformationProcess(hProcess, peClass, 0, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return status;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		size += written; // We should allocate little bit more space

		if (info)
			ExFreePoolWithTag(info, HELPER_ALLOC_TAG);

		info = ExAllocatePoolWithTag(NonPagedPool, size, HELPER_ALLOC_TAG);
		if (!info)
			break;

		status = ZwQueryInformationProcess(hProcess, peClass, info, size, &written);
	}

	if (!info)
		return STATUS_ACCESS_DENIED;

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(info, HELPER_ALLOC_TAG);
		return status;
	}

	*pInfoBuffer = info;
	*pInfoSize = size;

	return status;
}

NTSTATUS GetProcessImageName(HANDLE hProcessId, PUNICODE_STRING pImageName) {
	HANDLE hProcess;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES attribs;
	PUNICODE_STRING procName;
	NTSTATUS status;
	SIZE_T szSize = 0;

	InitializeObjectAttributes(&attribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	clientId.UniqueProcess = hProcessId;
	clientId.UniqueThread = 0;

	status = ZwOpenProcess(&hProcess, 0x1000, &attribs, &clientId);
	if (!NT_SUCCESS(status)) {
		LogError("Can't open process (pid: %p) failed with code %08x", hProcessId, status);
		return status;
	}

	status = QueryProcessInformation(ProcessImageFileName, hProcess, &procName, &szSize);
	ZwClose(hProcess);

	if (!NT_SUCCESS(status)) {
		LogError("Query process information(pid: %p) failed with code %08x", hProcessId, status);
		return status;
	}

	RtlCopyUnicodeString(pImageName, procName);
	return STATUS_SUCCESS;
}

VOID FreeInformation(PVOID pBuffer) {
	ExFreePoolWithTag(pBuffer, HELPER_ALLOC_TAG);
}