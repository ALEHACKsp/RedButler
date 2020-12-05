#pragma once
#include <Ntddk.h>

enum ExcludeObjectType {
	ExcludeFile,
	ExcludeDirectory,
	ExcludeMaxType,
};

typedef PVOID ExcludeContext;
typedef ExcludeContext* PExcludeContext;

typedef ULONGLONG ExcludeEntryId;
typedef ExcludeEntryId* PExcludeEntryId;

typedef ULONGLONG ExcludeEnumId;
typedef ExcludeEnumId* PExcludeEnumId;

// ====================================================================

NTSTATUS AddExclusionListFile(ExcludeContext context, PUNICODE_STRING pFilePath, PExcludeEntryId pEntryId, ExcludeEntryId parentId);
NTSTATUS AddExclusionListDirectory(ExcludeContext context, PUNICODE_STRING pDirPath, PExcludeEntryId pEntryId, ExcludeEntryId parentId);

NTSTATUS RemoveExclusionListEntry(ExcludeContext context, ExcludeEntryId entryId);
NTSTATUS RemoveAllExclusionListEntries(ExcludeContext context);

BOOLEAN CheckExclusionListFile(ExcludeContext context, PCUNICODE_STRING pPath);
BOOLEAN CheckExclusionListDirectory(ExcludeContext context, PCUNICODE_STRING pPath);
BOOLEAN CheckExclusionListDirFile(ExcludeContext context, PCUNICODE_STRING pDir, PCUNICODE_STRING pFile);

NTSTATUS InitializeExclusionListContext(PExcludeContext pContext, UINT32 uType);
VOID DestroyExclusionListContext(ExcludeContext context);
