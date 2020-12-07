#include <fltKernel.h>
#include "Logging.h"
#include "RedDriver.h"
#include "PsMonitor.h"
#include "ExclusionList.h"
#include "Helper.h"
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

ExcludeContext				g_excludedFilesContext;
ExcludeContext				g_excludedDirectoriesContext;

// ====================================================================

NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION pInfo, PFLT_FILE_NAME_INFORMATION pFltName) {
	PFILE_FULL_DIR_INFORMATION pNextInfo, pPrevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 uOffset, uMoveLength;
	BOOLEAN bMatched, bSearch;
	NTSTATUS status = STATUS_SUCCESS;

	uOffset = 0;
	bSearch = TRUE;

	do {
		fileName.Buffer = pInfo->FileName;
		fileName.Length = (USHORT)pInfo->FileNameLength;
		fileName.MaximumLength = (USHORT)pInfo->FileNameLength;

		if (pInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			bMatched = CheckExclusionListDirFile(g_excludedDirectoriesContext, &pFltName->Name, &fileName);
		else
			bMatched = CheckExclusionListDirFile(g_excludedFilesContext, &pFltName->Name, &fileName);

		if (bMatched) {
			BOOLEAN retn = FALSE;

			if (pPrevInfo != NULL) {
				if (pInfo->NextEntryOffset != 0) {
					pPrevInfo->NextEntryOffset += pInfo->NextEntryOffset;
					uOffset = pInfo->NextEntryOffset;
				} else {
					pPrevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(pInfo, sizeof(FILE_FULL_DIR_INFORMATION), 0);
			} else {
				if (pInfo->NextEntryOffset != 0) {
					pNextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
					uMoveLength = 0;
					while (pNextInfo->NextEntryOffset != 0) {
						uMoveLength += pNextInfo->NextEntryOffset;
						pNextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)pNextInfo + pNextInfo->NextEntryOffset);
					}

					uMoveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + pNextInfo->FileNameLength;
					RtlMoveMemory(pInfo, (PUCHAR)pInfo + pInfo->NextEntryOffset, uMoveLength);//continue
				} else {
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &pFltName->Name, &fileName);

			if (retn)
				return status;

			pInfo = (PFILE_FULL_DIR_INFORMATION)((PCHAR)pInfo + uOffset);
			continue;
		}

		uOffset = pInfo->NextEntryOffset;
		pPrevInfo = pInfo;
		pInfo = (PFILE_FULL_DIR_INFORMATION)((PCHAR)pInfo + uOffset);

		if (uOffset == 0)
			bSearch = FALSE;
	} while (bSearch);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION pInfo, PFLT_FILE_NAME_INFORMATION pFltName) {
	PFILE_BOTH_DIR_INFORMATION pNextInfo, pPrevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 uOffset, uMoveLength;
	BOOLEAN bMatched, bSearch;
	NTSTATUS status = STATUS_SUCCESS;

	uOffset = 0;
	bSearch = TRUE;

	do {
		fileName.Buffer = pInfo->FileName;
		fileName.Length = (USHORT)pInfo->FileNameLength;
		fileName.MaximumLength = (USHORT)pInfo->FileNameLength;

		if (pInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			bMatched = CheckExclusionListDirFile(g_excludedDirectoriesContext, &pFltName->Name, &fileName);
		else
			bMatched = CheckExclusionListDirFile(g_excludedFilesContext, &pFltName->Name, &fileName);

		if (bMatched) {
			BOOLEAN retn = FALSE;

			if (pPrevInfo != NULL) {
				if (pInfo->NextEntryOffset != 0) {
					pPrevInfo->NextEntryOffset += pInfo->NextEntryOffset;
					uOffset = pInfo->NextEntryOffset;
				} else {
					pPrevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(pInfo, sizeof(FILE_BOTH_DIR_INFORMATION), 0);
			} else {
				if (pInfo->NextEntryOffset != 0) {
					pNextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
					uMoveLength = 0;
					while (pNextInfo->NextEntryOffset != 0) {
						uMoveLength += pNextInfo->NextEntryOffset;
						pNextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)pNextInfo + pNextInfo->NextEntryOffset);
					}

					uMoveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + pNextInfo->FileNameLength;
					RtlMoveMemory(pInfo, (PUCHAR)pInfo + pInfo->NextEntryOffset, uMoveLength);//continue
				} else {
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ\n", &pFltName->Name, &fileName);

			if (retn)
				return status;

			pInfo = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)pInfo + uOffset);
			continue;
		}

		uOffset = pInfo->NextEntryOffset;
		pPrevInfo = pInfo;
		pInfo = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)pInfo + uOffset);

		if (uOffset == 0)
			bSearch = FALSE;
	} while (bSearch);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION pInfo, PFLT_FILE_NAME_INFORMATION pFltName) {
	PFILE_DIRECTORY_INFORMATION pNextInfo, pPrevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 uOffset, uMoveLength;
	BOOLEAN bMatched, bSearch;
	NTSTATUS status = STATUS_SUCCESS;

	uOffset = 0;
	bSearch = TRUE;

	do {
		fileName.Buffer = pInfo->FileName;
		fileName.Length = (USHORT)pInfo->FileNameLength;
		fileName.MaximumLength = (USHORT)pInfo->FileNameLength;

		if (pInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			bMatched = CheckExclusionListDirFile(g_excludedDirectoriesContext, &pFltName->Name, &fileName);
		else
			bMatched = CheckExclusionListDirFile(g_excludedFilesContext, &pFltName->Name, &fileName);

		if (bMatched) {
			BOOLEAN retn = FALSE;

			if (pPrevInfo != NULL) {
				if (pInfo->NextEntryOffset != 0) {
					pPrevInfo->NextEntryOffset += pInfo->NextEntryOffset;
					uOffset = pInfo->NextEntryOffset;
				} else {
					pPrevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(pInfo, sizeof(FILE_DIRECTORY_INFORMATION), 0);
			} else {
				if (pInfo->NextEntryOffset != 0) {
					pNextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
					uMoveLength = 0;
					while (pNextInfo->NextEntryOffset != 0) {
						uMoveLength += pNextInfo->NextEntryOffset;
						pNextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)pNextInfo + pNextInfo->NextEntryOffset);
					}

					uMoveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + pNextInfo->FileNameLength;
					RtlMoveMemory(pInfo, (PUCHAR)pInfo + pInfo->NextEntryOffset, uMoveLength);//continue
				} else {
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &pFltName->Name, &fileName);

			if (retn)
				return status;

			pInfo = (PFILE_DIRECTORY_INFORMATION)((PCHAR)pInfo + uOffset);
			continue;
		}

		uOffset = pInfo->NextEntryOffset;
		pPrevInfo = pInfo;
		pInfo = (PFILE_DIRECTORY_INFORMATION)((PCHAR)pInfo + uOffset);

		if (uOffset == 0)
			bSearch = FALSE;
	} while (bSearch);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION pInfo, PFLT_FILE_NAME_INFORMATION pFltName) {
	PFILE_ID_FULL_DIR_INFORMATION pNextInfo, pPrevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 uOffset, uMoveLength;
	BOOLEAN bMatched, bSearch;
	NTSTATUS status = STATUS_SUCCESS;

	uOffset = 0;
	bSearch = TRUE;

	do {
		fileName.Buffer = pInfo->FileName;
		fileName.Length = (USHORT)pInfo->FileNameLength;
		fileName.MaximumLength = (USHORT)pInfo->FileNameLength;

		if (pInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			bMatched = CheckExclusionListDirFile(g_excludedDirectoriesContext, &pFltName->Name, &fileName);
		else
			bMatched = CheckExclusionListDirFile(g_excludedFilesContext, &pFltName->Name, &fileName);

		if (bMatched) {
			BOOLEAN retn = FALSE;

			if (pPrevInfo != NULL) {
				if (pInfo->NextEntryOffset != 0) {
					pPrevInfo->NextEntryOffset += pInfo->NextEntryOffset;
					uOffset = pInfo->NextEntryOffset;
				} else {
					pPrevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(pInfo, sizeof(FILE_ID_FULL_DIR_INFORMATION), 0);
			} else {
				if (pInfo->NextEntryOffset != 0) {
					pNextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
					uMoveLength = 0;
					while (pNextInfo->NextEntryOffset != 0) {
						uMoveLength += pNextInfo->NextEntryOffset;
						pNextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)pNextInfo + pNextInfo->NextEntryOffset);
					}

					uMoveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + pNextInfo->FileNameLength;
					RtlMoveMemory(pInfo, (PUCHAR)pInfo + pInfo->NextEntryOffset, uMoveLength);//continue
				} else {
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &pFltName->Name, &fileName);

			if (retn)
				return status;

			pInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)pInfo + uOffset);
			continue;
		}

		uOffset = pInfo->NextEntryOffset;
		pPrevInfo = pInfo;
		pInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)pInfo + uOffset);

		if (uOffset == 0)
			bSearch = FALSE;
	} while (bSearch);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION pInfo, PFLT_FILE_NAME_INFORMATION pFltName) {
	PFILE_ID_BOTH_DIR_INFORMATION pNextInfo, pPrevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 uOffset, uMoveLength;
	BOOLEAN bMatched, bSearch;
	NTSTATUS status = STATUS_SUCCESS;

	uOffset = 0;
	bSearch = TRUE;

	do {
		fileName.Buffer = pInfo->FileName;
		fileName.Length = (USHORT)pInfo->FileNameLength;
		fileName.MaximumLength = (USHORT)pInfo->FileNameLength;

		if (pInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			bMatched = CheckExclusionListDirFile(g_excludedDirectoriesContext, &pFltName->Name, &fileName);
		else
			bMatched = CheckExclusionListDirFile(g_excludedFilesContext, &pFltName->Name, &fileName);

		if (bMatched) {
			BOOLEAN retn = FALSE;

			if (pPrevInfo != NULL) {
				if (pInfo->NextEntryOffset != 0) {
					pPrevInfo->NextEntryOffset += pInfo->NextEntryOffset;
					uOffset = pInfo->NextEntryOffset;
				} else {
					pPrevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(pInfo, sizeof(FILE_ID_BOTH_DIR_INFORMATION), 0);
			} else {
				if (pInfo->NextEntryOffset != 0) {
					pNextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
					uMoveLength = 0;
					while (pNextInfo->NextEntryOffset != 0) {
						uMoveLength += pNextInfo->NextEntryOffset;
						pNextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)pNextInfo + pNextInfo->NextEntryOffset);
					}

					uMoveLength += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + pNextInfo->FileNameLength;
					RtlMoveMemory(pInfo, (PUCHAR)pInfo + pInfo->NextEntryOffset, uMoveLength);//continue
				} else {
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ\n", &pFltName->Name, &fileName);

			if (retn)
				return status;

			pInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)pInfo + uOffset);
			continue;
		}

		uOffset = pInfo->NextEntryOffset;
		pPrevInfo = pInfo;
		pInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)pInfo + uOffset);

		if (uOffset == 0)
			bSearch = FALSE;
	} while (bSearch);

	return status;
}

NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION pInfo, PFLT_FILE_NAME_INFORMATION pFltName) {
	PFILE_NAMES_INFORMATION pNextInfo, pPrevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do {
		fileName.Buffer = pInfo->FileName;
		fileName.Length = (USHORT)pInfo->FileNameLength;
		fileName.MaximumLength = (USHORT)pInfo->FileNameLength;

		if (CheckExclusionListDirFile(g_excludedFilesContext, &pFltName->Name, &fileName)) {
			BOOLEAN retn = FALSE;

			if (pPrevInfo != NULL) {
				if (pInfo->NextEntryOffset != 0) {
					pPrevInfo->NextEntryOffset += pInfo->NextEntryOffset;
					offset = pInfo->NextEntryOffset;
				} else {
					pPrevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(pInfo, sizeof(FILE_NAMES_INFORMATION), 0);
			} else {
				if (pInfo->NextEntryOffset != 0) {
					pNextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
					moveLength = 0;
					while (pNextInfo->NextEntryOffset != 0) {
						moveLength += pNextInfo->NextEntryOffset;
						pNextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)pNextInfo + pNextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + pNextInfo->FileNameLength;
					RtlMoveMemory(pInfo, (PUCHAR)pInfo + pInfo->NextEntryOffset, moveLength);//continue
				} else {
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &pFltName->Name, &fileName);

			if (retn)
				return status;

			pInfo = (PFILE_NAMES_INFORMATION)((PCHAR)pInfo + offset);
			continue;
		}

		offset = pInfo->NextEntryOffset;
		pPrevInfo = pInfo;
		pInfo = (PFILE_NAMES_INFORMATION)((PCHAR)pInfo + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

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

	UINT32 uDisposition, uOptions;
	PFLT_FILE_NAME_INFORMATION pFltName;
	NTSTATUS status;
	BOOLEAN neededPrevent = FALSE;

	if (!IsDriverEnabled())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (IsProcessExcluded(PsGetCurrentProcessId()))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	uOptions = pData->Iopb->Parameters.Create.Options & 0x00FFFFFF;
	uDisposition = (pData->Iopb->Parameters.Create.Options & 0xFF000000) >> 24;

	status = FltGetFileNameInformation(pData, FLT_FILE_NAME_NORMALIZED, &pFltName);
	if (!NT_SUCCESS(status)) {
		if (status != STATUS_OBJECT_PATH_NOT_FOUND)
			LogWarning("FltGetFileNameInformation() failed with code %08x.", status);

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!(uOptions & FILE_DIRECTORY_FILE)) {
		// If it is create file event
		if (CheckExclusionListDirectory(g_excludedFilesContext, &pFltName->Name))
			neededPrevent = TRUE;
	}

	// If it is create directory/file event
	if (!neededPrevent && CheckExclusionListDirectory(g_excludedDirectoriesContext, &pFltName->Name))
		neededPrevent = TRUE;

	FltReleaseFileNameInformation(pFltName);

	if (neededPrevent) {
		LogTrace("Operation has been cancelled for %wZ.", &pData->Iopb->TargetFileObject->FileName);
		pData->IoStatus.Status = STATUS_NO_SUCH_FILE;
		return FLT_PREOP_COMPLETE;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA pData,
	PCFLT_RELATED_OBJECTS pFltObjects, PVOID* pCompletionContext) {

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

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

	PFLT_PARAMETERS pParams = &pData->Iopb->Parameters;
	PFLT_FILE_NAME_INFORMATION pFltName;
	NTSTATUS status;

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(pData->IoStatus.Status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (IsProcessExcluded(PsGetCurrentProcessId())) {
		LogTrace("Operation is skipped for excluded process.");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	status = FltGetFileNameInformation(pData, FLT_FILE_NAME_NORMALIZED, &pFltName);
	if (!NT_SUCCESS(status)) {
		LogWarning("FltGetFileNameInformation() failed with code %08x.", status);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	__try {
		status = STATUS_SUCCESS;

		switch (pParams->DirectoryControl.QueryDirectory.FileInformationClass) {
			case FileFullDirectoryInformation:
				status = CleanFileFullDirectoryInformation((PFILE_FULL_DIR_INFORMATION)pParams->DirectoryControl.QueryDirectory.DirectoryBuffer, pFltName);
				break;
			case FileBothDirectoryInformation:
				status = CleanFileBothDirectoryInformation((PFILE_BOTH_DIR_INFORMATION)pParams->DirectoryControl.QueryDirectory.DirectoryBuffer, pFltName);
				break;
			case FileDirectoryInformation:
				status = CleanFileDirectoryInformation((PFILE_DIRECTORY_INFORMATION)pParams->DirectoryControl.QueryDirectory.DirectoryBuffer, pFltName);
				break;
			case FileIdFullDirectoryInformation:
				status = CleanFileIdFullDirectoryInformation((PFILE_ID_FULL_DIR_INFORMATION)pParams->DirectoryControl.QueryDirectory.DirectoryBuffer, pFltName);
				break;
			case FileIdBothDirectoryInformation:
				status = CleanFileIdBothDirectoryInformation((PFILE_ID_BOTH_DIR_INFORMATION)pParams->DirectoryControl.QueryDirectory.DirectoryBuffer, pFltName);
				break;
			case FileNamesInformation:
				status = CleanFileNamesInformation((PFILE_NAMES_INFORMATION)pParams->DirectoryControl.QueryDirectory.DirectoryBuffer, pFltName);
				break;
		}

		pData->IoStatus.Status = status;
	} 
	
	__finally {
		FltReleaseFileNameInformation(pFltName);
	}


	return FLT_POSTOP_FINISHED_PROCESSING;
}

// ====================================================================

NTSTATUS AddHiddenFile(PUNICODE_STRING pFilePath, PULONGLONG pObjId) {
	const USHORT uMaxBufSize = pFilePath->Length + NORMALIZE_INCREMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, uMaxBufSize, FSFILTER_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = uMaxBufSize;

	if (!normalized.Buffer) {
		LogWarning("Error, can't allocate buffer.");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(pFilePath, &normalized);
	if (!NT_SUCCESS(status)) {
		LogWarning("Path normalization failed with code %08x, path %wZ.", status, pFilePath);
		ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);
		return status;
	}

	status = AddExclusionListFile(g_excludedFilesContext, &normalized, pObjId, 0);
	if (NT_SUCCESS(status))
		LogTrace("Added hidden file %wZ.", &normalized);
	else
		LogTrace("Adding hidden file failed with code %08x, path %wZ.", status, &normalized);

	ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);

	return status;
}

NTSTATUS RemoveHiddenFile(ULONGLONG objId) {
	NTSTATUS status = RemoveExclusionListEntry(g_excludedFilesContext, objId);
	if (NT_SUCCESS(status))
		LogTrace("Hidden file is removed, id %lld.", objId);
	else
		LogTrace("Can't remove hidden file, code %08x, id %lld.", status, objId);

	return status;
}

NTSTATUS RemoveAllHiddenFiles() {
	NTSTATUS status = RemoveAllExclusionListEntries(g_excludedFilesContext);
	if (NT_SUCCESS(status))
		LogTrace("All hidden files are removed.");
	else
		LogTrace("Can't remove all hidden files, code %08x.", status);

	return status;
}

NTSTATUS AddHiddenDir(PUNICODE_STRING pDirPath, PULONGLONG pObjId) {
	const USHORT maxBufSize = pDirPath->Length + NORMALIZE_INCREMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, FSFILTER_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer) {
		LogWarning("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(pDirPath, &normalized);
	if (!NT_SUCCESS(status)) {
		LogWarning("Path normalization failed with code %08x, path %wZ.", status, pDirPath);
		ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);
		return status;
	}

	status = AddExclusionListDirectory(g_excludedDirectoriesContext, &normalized, pObjId, 0);
	if (NT_SUCCESS(status))
		LogTrace("Added hidden dir %wZ.", &normalized);
	else
		LogTrace("Adding hidden dir failed with code %08x, path %wZ.", status, &normalized);

	ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);

	return status;
}

NTSTATUS RemoveHiddenDir(ULONGLONG objId) {
	NTSTATUS status = RemoveExclusionListEntry(g_excludedDirectoriesContext, objId);
	if (NT_SUCCESS(status))
		LogTrace("Hidden dir is removed, id %lld.", objId);
	else
		LogTrace("Can't remove hidden dir, code %08x, id %lld.", status, objId);

	return status;
}

NTSTATUS RemoveAllHiddenDirs() {
	NTSTATUS status = RemoveAllExclusionListEntries(g_excludedDirectoriesContext);
	if (NT_SUCCESS(status))
		LogTrace("All hidden dirs are removed.");
	else
		LogTrace("Can't remove all hidden dirs, code %08x.", status);

	return status;
}

// ====================================================================

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT pDriverObject) {
	LogTrace("Initializing FS minifilter...");

	NTSTATUS status;

	status = InitializeExclusionListContext(&g_excludedFilesContext, ExcludeFile);
	if (!NT_SUCCESS(status)) {
		LogError("Excluded file list initialization failed with code %08x", status);
		return status;
	}

	status = InitializeExclusionListContext(&g_excludedDirectoriesContext, ExcludeDirectory);
	if (!NT_SUCCESS(status)) {
		LogError("Excluded directories list initialization failed with code %08x", status);
		DestroyExclusionListContext(g_excludedFilesContext);
		return status;
	}

	status = FltRegisterFilter(pDriverObject, &FilterRegistration, &g_filterHandle);
	if (NT_SUCCESS(status)) {
		status = FltStartFiltering(g_filterHandle);
		if (!NT_SUCCESS(status)) {
			LogError("FltStartFiltering failed with code %08x.", status);
			FltUnregisterFilter(g_filterHandle);
		}
	} else {
		LogError("FltRegisterFilter failed with code %08x.", status);
		DestroyExclusionListContext(g_excludedFilesContext);
		DestroyExclusionListContext(g_excludedDirectoriesContext);
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

	DestroyExclusionListContext(g_excludedFilesContext);
	DestroyExclusionListContext(g_excludedDirectoriesContext);

	g_fsMonitorInitialized = FALSE;

	LogTrace("Deitialization completed.");
	return STATUS_SUCCESS;
}
