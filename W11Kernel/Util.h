#pragma once
#include "KernelIncludes.h"

NTSTATUS SuperCopyMemory(
    IN VOID UNALIGNED* Destination,
    IN CONST VOID UNALIGNED* Source,
    IN ULONG Length);

KIRQL DisableWP();

void EnableWP(KIRQL irql);

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    // ... Ê¡ÂÔÆäÓà×Ö¶Î
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



NTSTATUS PsLookupProcessByNameA(_In_ const char* targetName, _Out_ PEPROCESS* outProcess);

NTSTATUS GetProcessIdByName(OUT PHANDLE pPid, PCWSTR targetProcessName);

#ifdef __cplusplus
extern "C" {
#endif

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );

#ifdef __cplusplus
}
#endif

#define SystemProcessInformation 5
