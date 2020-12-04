#pragma once

typedef struct _process_table_entry {
	HANDLE hProcessId;

	BOOLEAN bProtected;
	BOOLEAN bExcluded;

	BOOLEAN bSubsystem;
} PROCESS_TABLE_ENTRY, * PPROCESS_TABLE_ENTRY;

NTSTATUS InitializeProcessTable(VOID(*InitProcessEntryCallback)(PPROCESS_TABLE_ENTRY, PCUNICODE_STRING, HANDLE));
VOID DestroyProcessTable();

BOOLEAN AddProcessToProcessTable(PPROCESS_TABLE_ENTRY entry);
BOOLEAN RemoveProcessFromProcessTable(PPROCESS_TABLE_ENTRY entry);
BOOLEAN GetProcessInProcessTable(PPROCESS_TABLE_ENTRY entry);
BOOLEAN UpdateProcessInProcessTable(PPROCESS_TABLE_ENTRY entry);
