#include <fltKernel.h>
#include "Logging.h"
#include "RedDriver.h"
#include "FsFilter.h"

#define FSFILTER_ALLOC_TAG 'DHlF'

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS pFltObjects, FLT_INSTANCE_SETUP_FLAGS flags, 
	DEVICE_TYPE volumeDeviceType, FLT_FILESYSTEM_TYPE volumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS FltCreatePreOperation(PFLT_CALLBACK_DATA pData, PCFLT_RELATED_OBJECTS pFltObjects, PVOID* pCompletionContext);
FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA pData, PCFLT_RELATED_OBJECTS pFltObjects, PVOID* pCompletionContext);
FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA pData, 
	PCFLT_RELATED_OBJECTS pFltObjects, PVOID pCompletionContext, FLT_POST_OPERATION_FLAGS flags);

// ====================================================================

CONST FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, FltCreatePreOperation, NULL },
	{ IRP_MJ_DIRECTORY_CONTROL, 0, FltDirCtrlPreOperation, FltDirCtrlPostOperation },
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION), 							//  Size
	FLT_REGISTRATION_VERSION, 							//  Version
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,     //  Flags
	Contexts,											//  Context
	Callbacks,											//  Operation callbacks
	NULL,												//  MiniFilterUnload
	FilterSetup,										//  InstanceSetup
	NULL,												//  InstanceQueryTeardown
	NULL,                     							//  InstanceTeardownStart
	NULL,                     							//  InstanceTeardownComplete
	NULL,                     							//  GenerateFileName
	NULL,                     							//  GenerateDestinationFileName
	NULL                     							//  NormalizeNameComponent
};

PFLT_FILTER					g_filterHandle;
BOOLEAN						g_fsMonitorInitialized;

// ====================================================================

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS pFltObjects, FLT_INSTANCE_SETUP_FLAGS flags, 
	DEVICE_TYPE volumeDeviceType, FLT_FILESYSTEM_TYPE volumeFilesystemType) {

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(flags);
	UNREFERENCED_PARAMETER(volumeDeviceType);
	UNREFERENCED_PARAMETER(volumeFilesystemType);

	LogTrace("Attached to a new device (flags: %x, device: %d, fs: %d).", 
		(ULONG)flags, (ULONG)volumeDeviceType, (ULONG)volumeFilesystemType);

	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FltCreatePreOperation(PFLT_CALLBACK_DATA pData, 
	PCFLT_RELATED_OBJECTS pFltObjects, PVOID* pCompletionContext) {

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	if (!IsDriverEnabled())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	LogInfo("%wZ (options: %x)", &pData->Iopb->TargetFileObject->FileName, pData->Iopb->Parameters.Create.Options);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA pData,
	PCFLT_RELATED_OBJECTS pFltObjects, PVOID* pCompletionContext) {

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	LogInfo("%wZ", &pData->Iopb->TargetFileObject->FileName);

	if (pData->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	switch (pData->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass) {
		case FileIdFullDirectoryInformation:
		case FileIdBothDirectoryInformation:
		case FileBothDirectoryInformation:
		case FileDirectoryInformation:
		case FileFullDirectoryInformation:
		case FileNamesInformation:
			break;
		default:
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA pData,
	PCFLT_RELATED_OBJECTS pFltObjects, PVOID pCompletionContext,
	FLT_POST_OPERATION_FLAGS flags) {

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(flags);

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(pData->IoStatus.Status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	LogInfo("%wZ", &pData->Iopb->TargetFileObject->FileName);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

// ====================================================================

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT pDriverObject) {
	LogTrace("Initializing FS minifilter...");

	NTSTATUS status;
	status = FltRegisterFilter(pDriverObject, &FilterRegistration, &g_filterHandle);
	if (NT_SUCCESS(status)) {
		status = FltStartFiltering(g_filterHandle);
		if (!NT_SUCCESS(status)) {
			LogError("FltStartFiltering failed with code %08x.", status);
			FltUnregisterFilter(g_filterHandle);
		}
	} else {
		LogError("FltRegisterFilter failed with code %08x.", status);
	}

	if (NT_SUCCESS(status)) {
		g_fsMonitorInitialized = TRUE;
	}

	LogTrace("Initialization completed.");
	return status;
}

NTSTATUS DestroyFSMiniFilter() {
	if (!g_fsMonitorInitialized)
		return STATUS_NOT_FOUND;

	LogTrace("Destroying FS minifilter...");

	FltUnregisterFilter(g_filterHandle);
	g_filterHandle = NULL;

	g_fsMonitorInitialized = FALSE;

	LogTrace("Deitialization completed.");
	return STATUS_SUCCESS;
}
