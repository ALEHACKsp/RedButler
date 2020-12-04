#include <ntddk.h>

#include "Logging.h"
#include "Helper.h"
#include "RedDriver.h"
#include "PsTable.h"
#include "PsMonitor.h"

#define PSMON_ALLOC_TAG 'nMsP'
#define CSRSS_PATH_BUFFER_SIZE 256
#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000

BOOLEAN						g_psMonitorInitialized = FALSE;
PVOID						g_obRegCallback = NULL;

OB_OPERATION_REGISTRATION	g_regOperation[2];
OB_CALLBACK_REGISTRATION	g_regCallback;

FAST_MUTEX					g_processTableLock;

UNICODE_STRING				g_csrssPath;
WCHAR						g_csrssPathBuffer[CSRSS_PATH_BUFFER_SIZE];

// ====================================================================

BOOLEAN CheckProtectedOperation(HANDLE hSource, HANDLE hDestination) {
	PROCESS_TABLE_ENTRY srcInfo, dstInfo;
	BOOLEAN bResult;

	if (hSource == hDestination) {
		return FALSE;
	}

	srcInfo.hProcessId = hSource;
	ExAcquireFastMutex(&g_processTableLock);
	bResult = GetProcessInProcessTable(&srcInfo);
	ExReleaseFastMutex(&g_processTableLock);

	dstInfo.hProcessId = hDestination;
	ExAcquireFastMutex(&g_processTableLock);
	bResult = GetProcessInProcessTable(&dstInfo);
	ExReleaseFastMutex(&g_processTableLock);

	if (!bResult) {
		return FALSE;
	}

	if (srcInfo.bSubsystem) {
		return FALSE;
	}

	if (dstInfo.bProtected && !srcInfo.bExcluded) {
		return TRUE;
	}

	return FALSE;
}

VOID CheckProcessFlags(PPROCESS_TABLE_ENTRY pEntry, PCUNICODE_STRING pImgPath) {
	PROCESS_TABLE_ENTRY lookup;

	RtlZeroMemory(&lookup, sizeof(lookup));

	if (pEntry->hProcessId == (HANDLE)4)
		pEntry->bSubsystem = TRUE;
	else
		pEntry->bSubsystem = RtlEqualUnicodeString(&g_csrssPath, pImgPath, TRUE);

	pEntry->bProtected = FALSE;
	pEntry->bExcluded = FALSE;
}

// ====================================================================

OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID pRegistrationContext,
	POB_PRE_OPERATION_INFORMATION pOperationInformation) {

	UNREFERENCED_PARAMETER(pRegistrationContext);

	if (!IsDriverEnabled()) {
		return OB_PREOP_SUCCESS;
	}

	if (pOperationInformation->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}

	LogInfo("Process object operation, destPid: %p, srcTid: %p, oper: %s, space: %s",
		PsGetProcessId(pOperationInformation->Object), PsGetCurrentThreadId(),
		(pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(pOperationInformation->KernelHandle ? "kernel" : "user")
	);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetProcessId(pOperationInformation->Object))) {
		return OB_PREOP_SUCCESS;
	}

	LogTrace("Disallowed protected process access from %d to %d",
		(ULONG)PsGetCurrentProcessId(), (ULONG)PsGetProcessId(pOperationInformation->Object));

	if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
	else
		pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ThreadPreCallback(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation) {
	UNREFERENCED_PARAMETER(pRegistrationContext);
	if (!IsDriverEnabled())
		return OB_PREOP_SUCCESS;

	if (pOperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	LogInfo("Thread object operation, destPid: %d, destTid:%d, srcPid:%d, oper:%s, space:%s",
		(ULONG)PsGetThreadProcessId(pOperationInformation->Object),
		(ULONG)PsGetThreadId(pOperationInformation->Object),
		(ULONG)PsGetCurrentProcessId(),
		(pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(pOperationInformation->KernelHandle ? "kernel" : "user")
	);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetThreadProcessId(pOperationInformation->Object))) {
		return OB_PREOP_SUCCESS;
	}

	LogTrace("Disallowed protected thread access from %d to %d",
		(ULONG)PsGetCurrentProcessId(), (ULONG)PsGetThreadProcessId(pOperationInformation->Object));

	if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	else
		pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	return OB_PREOP_SUCCESS;
}

VOID CreateProcessNotifyCallback(PEPROCESS peProcess, HANDLE hProcessId, PPS_CREATE_NOTIFY_INFO pCreateInfo) {
	UNREFERENCED_PARAMETER(peProcess);

	if (pCreateInfo) {
		LogInfo(
			"Create process, pid: %p, srcPid: %p, srcTid: %p",
			hProcessId,
			PsGetCurrentProcessId(),
			PsGetCurrentThreadId()
		);

		PROCESS_TABLE_ENTRY entry;
		entry.hProcessId = hProcessId;
		CheckProcessFlags(&entry, pCreateInfo->ImageFileName);

		ExAcquireFastMutex(&g_processTableLock);
		AddProcessToProcessTable(&entry);
		ExReleaseFastMutex(&g_processTableLock);
	} else {
		LogInfo(
			"Destroy process, pid: %p, srcPid: %p, srcTid: %p",
			hProcessId,
			PsGetCurrentProcessId(),
			PsGetCurrentThreadId()
		);

		PROCESS_TABLE_ENTRY entry;
		entry.hProcessId = hProcessId;

		ExAcquireFastMutex(&g_processTableLock);
		RemoveProcessFromProcessTable(&entry);
		ExReleaseFastMutex(&g_processTableLock);
	}
}

// ====================================================================

NTSTATUS SetProcessProtection(HANDLE hProcessId, BOOLEAN bProtected) {
	PROCESS_TABLE_ENTRY entry;

	entry.hProcessId = hProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	if (!GetProcessInProcessTable(&entry)) {
		ExReleaseFastMutex(&g_processTableLock);
		return STATUS_UNSUCCESSFUL;
	}

	entry.bProtected = bProtected;
	UpdateProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);
	return STATUS_SUCCESS;
}

NTSTATUS SetProcessExclusion(HANDLE hProcessId, BOOLEAN bExcluded) {
	PROCESS_TABLE_ENTRY entry;

	entry.hProcessId = hProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	if (!GetProcessInProcessTable(&entry)) {
		ExReleaseFastMutex(&g_processTableLock);
		return STATUS_UNSUCCESSFUL;
	}

	entry.bExcluded = bExcluded;
	UpdateProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);
	return STATUS_SUCCESS;
}

NTSTATUS GetProcessAttributes(HANDLE hProcessId, PPROCESS_TABLE_ENTRY pEntry) {
	PROCESS_TABLE_ENTRY entry;

	entry.hProcessId = hProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	if (!GetProcessInProcessTable(&entry)) {
		ExReleaseFastMutex(&g_processTableLock);
		return STATUS_UNSUCCESSFUL;
	}
	ExReleaseFastMutex(&g_processTableLock);
	*pEntry = entry;

	return STATUS_SUCCESS;
}

NTSTATUS ClearProcessAttributes(HANDLE hProcessId) {
	NTSTATUS status;
	PROCESS_TABLE_ENTRY entry;

	entry.hProcessId = hProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	if (!GetProcessInProcessTable(&entry)) {
		ExReleaseFastMutex(&g_processTableLock);
		return STATUS_UNSUCCESSFUL;
	}

	entry.bProtected = FALSE;

	UpdateProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);
	return STATUS_SUCCESS;
}

// ====================================================================

NTSTATUS DestroyPsMonitor() {
	if (!g_psMonitorInitialized)
		return STATUS_ALREADY_DISCONNECTED;

	if (g_obRegCallback) {
		ObUnRegisterCallbacks(g_obRegCallback);
		g_obRegCallback = NULL;
	}

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);

	DestroyProcessTable();

	g_psMonitorInitialized = FALSE;

	LogTrace("Destruction completed.");
	return STATUS_SUCCESS;
}

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	NTSTATUS status;
	UNICODE_STRING csrss;

	RtlZeroMemory(g_csrssPathBuffer, sizeof(g_csrssPathBuffer));
	g_csrssPath.Buffer = g_csrssPathBuffer;
	g_csrssPath.Length = 0;
	g_csrssPath.MaximumLength = sizeof(g_csrssPathBuffer);

	RtlInitUnicodeString(&csrss, L"\\SystemRoot\\System32\\csrss.exe");
	status = NormalizeDevicePath(&csrss, &g_csrssPath);
	if (!NT_SUCCESS(status)) {
		LogError("Subsystem path normalization failed with code %08x.", status);
		return status;
	}

	LogTrace("Subsystem path @ %wZ.", &g_csrssPath);

	ExInitializeFastMutex(&g_processTableLock);

	// Register callbacks
	g_regOperation[0].ObjectType = PsProcessType;
	g_regOperation[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	g_regOperation[0].PreOperation = ProcessPreCallback;
	g_regOperation[0].PostOperation = NULL;

	g_regOperation[1].ObjectType = PsThreadType;
	g_regOperation[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	g_regOperation[1].PreOperation = ThreadPreCallback;
	g_regOperation[1].PostOperation = NULL;

	g_regCallback.Version = OB_FLT_REGISTRATION_VERSION;
	g_regCallback.OperationRegistrationCount = 2;
	g_regCallback.RegistrationContext = NULL;
	g_regCallback.OperationRegistration = g_regOperation;
	RtlInitUnicodeString(&g_regCallback.Altitude, L"1000");

	status = ObRegisterCallbacks(&g_regCallback, &g_obRegCallback);
	if (!NT_SUCCESS(status)) {
		LogError("Object filter registration failed with code %08x.", status);
		DestroyPsMonitor();
		return status;
	}

	status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		LogError("Error, process notify registartion failed with code %08x.", status);
		DestroyPsMonitor();
		return status;
	}

	InitializeProcessTable(CheckProcessFlags);

	g_psMonitorInitialized = TRUE;

	LogTrace("Initialization completed.");
	return status;
}