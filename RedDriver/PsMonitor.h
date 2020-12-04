#pragma once
NTSTATUS SetProcessProtection(HANDLE hProcessId, BOOLEAN bProtected);
NTSTATUS SetProcessExclusion(HANDLE hProcessId, BOOLEAN bExcluded);
NTSTATUS ClearProcessAttributes(HANDLE hProcessId);

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT pDriverObject);
NTSTATUS DestroyPsMonitor();
