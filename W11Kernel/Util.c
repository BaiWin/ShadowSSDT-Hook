#include "KernelIncludes.h"

NTSTATUS SuperCopyMemory(
    IN VOID UNALIGNED* Destination,
    IN CONST VOID UNALIGNED* Source,
    IN ULONG Length)
{
    //Change memory properties.
    PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
    if (!g_pmdl)
        return STATUS_UNSUCCESSFUL;
    MmBuildMdlForNonPagedPool(g_pmdl);
    unsigned int* Mapped = (unsigned int*)MmMapLockedPages(g_pmdl, KernelMode);
    if (!Mapped)
    {
        IoFreeMdl(g_pmdl);
        return STATUS_UNSUCCESSFUL;
    }
    KIRQL kirql = KeRaiseIrqlToDpcLevel();
    RtlCopyMemory(Mapped, Source, Length);
    KeLowerIrql(kirql);
    //Restore memory properties.
    MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
    IoFreeMdl(g_pmdl);
    return STATUS_SUCCESS;
}


KIRQL DisableWP()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
#ifdef _AMD64_        
    cr0 &= 0xfffffffffffeffff;
#else
    cr0 &= 0xfffeffff;
#endif
    __writecr0(cr0);
    _disable();    // Disable interrupts
    return irql;
}

void EnableWP(KIRQL irql)
{
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();		// Enable interrupts
    __writecr0(cr0);
    KeLowerIrql(irql);
}

NTSTATUS PsLookupProcessByNameA(_In_ const char* targetName, _Out_ PEPROCESS* outProcess)
{
    if (!targetName || !outProcess)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'prcL');

    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(buffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (TRUE)
    {
        if (spi->ImageName.Buffer)
        {
            CHAR imageNameA[260] = { 0 };
            size_t len = spi->ImageName.Length / sizeof(WCHAR);
            for (size_t i = 0; i < len && i < sizeof(imageNameA) - 1; ++i)
                imageNameA[i] = (CHAR)spi->ImageName.Buffer[i];

            if (_stricmp(imageNameA, targetName) == 0)
            {
                // 找到目标进程，使用 PID 获取 EPROCESS
                status = PsLookupProcessByProcessId(spi->UniqueProcessId, outProcess);
                ExFreePool(buffer);
                return status;
            }
        }

        if (spi->NextEntryOffset == 0)
            break;

        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    ExFreePool(buffer);
    return STATUS_NOT_FOUND;
}

NTSTATUS GetProcessIdByName(OUT PHANDLE pPid, PCWSTR targetProcessName)
{
    if (!pPid || !targetProcessName) return STATUS_INVALID_PARAMETER;

    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;

    do
    {
        buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'pidf');
        if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePool(buffer);
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status))
    {
        if (buffer) ExFreePool(buffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE)
    {
        if (pInfo->ImageName.Buffer)
        {
            if (wcsstr(pInfo->ImageName.Buffer, targetProcessName))
            {
                *pPid = pInfo->UniqueProcessId;
                ExFreePool(buffer);
                return STATUS_SUCCESS;
            }
        }

        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
    }

    ExFreePool(buffer);
    return STATUS_NOT_FOUND;
}