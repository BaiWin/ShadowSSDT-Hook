#include "KernelIncludes.h"

PVOID g_SharedMemoryBase = NULL;
SIZE_T g_SharedMemorySize = 0x1000;
UNICODE_STRING g_SharedMemoryName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\W11SharedMemory");

NTSTATUS InitSharedMemory(void)
{
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &g_SharedMemoryName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Comm] ZwOpenSection failed: 0x%X\n", status);
        return status;
    }

    SIZE_T viewSize = g_SharedMemorySize;
    status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &g_SharedMemoryBase, 0L, viewSize, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

    ZwClose(hSection);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Comm] ZwMapViewOfSection failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[Comm] Shared memory mapped at: %p\n", g_SharedMemoryBase);
    return STATUS_SUCCESS;
}

VOID CleanupSharedMemory(void)
{
    if (g_SharedMemoryBase)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), g_SharedMemoryBase);
        g_SharedMemoryBase = NULL;
    }
}

typedef struct _COMMAND_BLOCK
{
    ULONG CommandId;
    ULONG Data[4];
} COMMAND_BLOCK, * PCOMMAND_BLOCK;

BOOLEAN ProcessSharedCommand(void)
{
    if (!g_SharedMemoryBase)
        return FALSE;

    PCOMMAND_BLOCK cmd = (PCOMMAND_BLOCK)g_SharedMemoryBase;
    switch (cmd->CommandId)
    {
    case 1:
        DbgPrint("[Comm] Received command 1, param: %u\n", cmd->Data[0]);
        return TRUE;
    case 2:
        DbgPrint("[Comm] Received command 2, param: %u\n", cmd->Data[1]);
        return TRUE;
    default:
        return FALSE;
    }
}