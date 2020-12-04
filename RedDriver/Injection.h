#pragma once
#include <ntddk.h>

NTSTATUS InjectDLL(_In_ HANDLE hProcessId, _In_ PUNICODE_STRING pModulePath);