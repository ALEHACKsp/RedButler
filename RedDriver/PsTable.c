#include <ntddk.h>
#include "PsTable.h"
#include "Logging.h"
#include "Helper.h"

#define PSTREE_ALLOC_TAG 'rTsP'

RTL_AVL_TABLE  g_processTable;

_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS ComparePROCESS_TABLE_ENTRY(struct _RTL_AVL_TABLE* table, PVOID pFirstStruct, PVOID pSecondStruct) {
	PPROCESS_TABLE_ENTRY first = (PPROCESS_TABLE_ENTRY)pFirstStruct;
	PPROCESS_TABLE_ENTRY second = (PPROCESS_TABLE_ENTRY)pSecondStruct;

	UNREFERENCED_PARAMETER(table);

	if (first->hProcessId > second->hProcessId)
		return GenericGreaterThan;

	if (first->hProcessId < second->hProcessId)
		return GenericLessThan;

	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocatePROCESS_TABLE_ENTRY(struct _RTL_AVL_TABLE* table, CLONG lByteSize) {
	UNREFERENCED_PARAMETER(table);
	return ExAllocatePoolWithTag(NonPagedPool, lByteSize, PSTREE_ALLOC_TAG);
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreePROCESS_TABLE_ENTRY(struct _RTL_AVL_TABLE* table, PVOID pBuffer) {
	UNREFERENCED_PARAMETER(table);
	ExFreePoolWithTag(pBuffer, PSTREE_ALLOC_TAG);
}

BOOLEAN AddProcessToProcessTable(PPROCESS_TABLE_ENTRY pEntry) {
	BOOLEAN result = FALSE;

	if (RtlInsertElementGenericTableAvl(&g_processTable, pEntry, sizeof(PROCESS_TABLE_ENTRY), &result) == NULL)
		return FALSE;

	return result;
}

BOOLEAN RemoveProcessFromProcessTable(PPROCESS_TABLE_ENTRY pEntry) {
	return RtlDeleteElementGenericTableAvl(&g_processTable, pEntry);
}

BOOLEAN GetProcessInProcessTable(PPROCESS_TABLE_ENTRY pEntry) {
	PPROCESS_TABLE_ENTRY entry2;

	entry2 = (PPROCESS_TABLE_ENTRY)RtlLookupElementGenericTableAvl(&g_processTable, pEntry);
	if (entry2)
		RtlCopyMemory(pEntry, entry2, sizeof(PROCESS_TABLE_ENTRY));

	return (entry2 ? TRUE : FALSE);
}

BOOLEAN UpdateProcessInProcessTable(PPROCESS_TABLE_ENTRY pEntry) {
	PPROCESS_TABLE_ENTRY entry2;

	entry2 = (PPROCESS_TABLE_ENTRY)RtlLookupElementGenericTableAvl(&g_processTable, pEntry);

	if (entry2)
		RtlCopyMemory(entry2, pEntry, sizeof(PROCESS_TABLE_ENTRY));

	return (entry2 ? TRUE : FALSE);
}

NTSTATUS InitializeProcessTable(VOID(*InitProcessEntryCallback)(PPROCESS_TABLE_ENTRY, PCUNICODE_STRING)) {
	LogTrace("Initializing process table...");

	PSYSTEM_PROCESS_INFORMATION processInfo = NULL, first;
	NTSTATUS status;
	SIZE_T size = 0, offset;

	RtlInitializeGenericTableAvl(&g_processTable, ComparePROCESS_TABLE_ENTRY, AllocatePROCESS_TABLE_ENTRY, FreePROCESS_TABLE_ENTRY, NULL);

	status = QuerySystemInformation(SystemProcessInformation, &processInfo, &size);
	if (!NT_SUCCESS(status)) {
		LogError("Query system information (pslist) failed with code %08x.", status);
		return status;
	}

	offset = 0;
	first = processInfo;
	do {
		PROCESS_TABLE_ENTRY entry;
		PUNICODE_STRING procName;
		CLIENT_ID clientId;
		OBJECT_ATTRIBUTES attribs;
		HANDLE hProcess;

		// Get process path
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + offset);

		if (processInfo->ProcessId == 0) {
			offset = processInfo->NextEntryOffset;
			continue;
		}

		InitializeObjectAttributes(&attribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		clientId.UniqueProcess = processInfo->ProcessId;
		clientId.UniqueThread = 0;

		status = ZwOpenProcess(&hProcess, 0x1000, &attribs, &clientId);
		if (!NT_SUCCESS(status)) {
			LogWarning("Can't open process (pid %p) failed with code %08x.", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		status = QueryProcessInformation(ProcessImageFileName, hProcess, &procName, &size);
		ZwClose(hProcess);

		if (!NT_SUCCESS(status)) {
			LogWarning("Query process information (pid %p) failed with code %08x.", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		// Add process in process table
		RtlZeroMemory(&entry, sizeof(entry));
		entry.hProcessId = processInfo->ProcessId;

		LogTrace("New process: %p, %wZ.", processInfo->ProcessId, procName);

		InitProcessEntryCallback(&entry, procName, processInfo->InheritedFromProcessId);
		if (!AddProcessToProcessTable(&entry))
			LogWarning("Can't add process (pid %p) to process table.", processInfo->ProcessId);

		FreeInformation(procName);
		offset = processInfo->NextEntryOffset;
	} while (offset);

	FreeInformation(first);
	LogTrace("Initialization completed.");
	return status;
}

VOID DestroyProcessTable() {
	LogTrace("Destroying process table...");

	PPROCESS_TABLE_ENTRY entry;
	PVOID restartKey = NULL;

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey);
		entry != NULL;
		entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey)) {
		if (!RtlDeleteElementGenericTableAvl(&g_processTable, entry))
			LogWarning("Can't remove element from process table, looks like memory leak.");

		restartKey = NULL;
	}

	LogTrace("Destruction completed.");
}