#pragma once
#include "KernelIncludes.h"

NTSTATUS InitSharedMemory(void);
VOID     CleanupSharedMemory(void);
BOOLEAN  ProcessSharedCommand(void); // 被伪装系统调用触发