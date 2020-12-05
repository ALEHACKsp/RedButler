#pragma once
#include "PsTable.h"

BOOLEAN IsProcessExcluded(HANDLE hProcessId);
BOOLEAN IsProcessProtected(HANDLE hProcessId);

NTSTATUS SetProcessProtection(HANDLE hProcessId, BOOLEAN bProtected);
NTSTATUS SetProcessExclusion(HANDLE hProcessId, BOOLEAN bExcluded);
NTSTATUS ClearProcessAttributes(HANDLE hProcessId);
NTSTATUS GetProcessAttributes(HANDLE hProcessId, PPROCESS_TABLE_ENTRY pEntry);

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT pDriverObject);
NTSTATUS DestroyPsMonitor();
