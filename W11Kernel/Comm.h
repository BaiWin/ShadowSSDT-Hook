#pragma once
#include "KernelIncludes.h"

NTSTATUS InitSharedMemory(void);
VOID     CleanupSharedMemory(void);
BOOLEAN  ProcessSharedCommand(void); // ��αװϵͳ���ô���