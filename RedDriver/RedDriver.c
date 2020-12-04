#include "Logging.h"
#include "Device.h"
#include "FsFilter.h"
#include "PsMonitor.h"
#include "RedDriver.h"

volatile LONG	g_driverActive = TRUE;

// ====================================================================

VOID ChangeDriverState(BOOLEAN bStatus) {
	InterlockedExchange(&g_driverActive, (LONG)bStatus);
}

BOOLEAN IsDriverEnabled() {
	return TRUE == g_driverActive;
}

// ====================================================================

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	NTSTATUS ntStatus;

	LogTrace("Unloading driver...");

	ntStatus = DestroyDevice();
	if (!NT_SUCCESS(ntStatus)) {
		LogError("Failed to destroy device object.");
	}

	ntStatus = DestroyPsMonitor();
	if (!NT_SUCCESS(ntStatus)) {
		LogError("Failed to destroy PsMonitor.");
	}

	ntStatus = DestroyFSMiniFilter();
	if (!NT_SUCCESS(ntStatus)) {
		LogError("Failed to destroy device object.");
	}

	LogTrace("Driver unloading completed.");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS ntStatus;

	LogTrace("Initializing driver...");

	ntStatus = InitializeDevice(pDriverObject);
	if (!NT_SUCCESS(ntStatus)) {
		LogError("Failed to initialize device object.");
	}

	ntStatus = InitializePsMonitor(pDriverObject);
	if (!NT_SUCCESS(ntStatus)) {
		LogError("Failed to initialize PsMonitor.");
	}

	ntStatus = InitializeFSMiniFilter(pDriverObject);
	if (!NT_SUCCESS(ntStatus)) {
		LogError("Failed to initialize FS minifilter.");
	}
	
	pDriverObject->DriverUnload = DriverUnload;

	LogTrace("Driver initialization completed.");
	return ntStatus;
}
