#pragma once

NTSTATUS AddHiddenFile(PUNICODE_STRING pFilePath, PULONGLONG pObjId);
NTSTATUS RemoveHiddenFile(ULONGLONG objId);
NTSTATUS RemoveAllHiddenFiles();

NTSTATUS AddHiddenDir(PUNICODE_STRING pDirPath, PULONGLONG pObjId);
NTSTATUS RemoveHiddenDir(ULONGLONG objId);
NTSTATUS RemoveAllHiddenDirs();

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT pDriverObject);
NTSTATUS DestroyFSMiniFilter();
