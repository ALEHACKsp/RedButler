#pragma once
#include <ntddk.h>

VOID ChangeDriverState(BOOLEAN bStatus);
BOOLEAN IsDriverEnabled();