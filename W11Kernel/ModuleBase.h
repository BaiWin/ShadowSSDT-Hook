#pragma once
#include "KernelIncludes.h"

#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG ModulesCount;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

PVOID GetModuleBaseByName(PCUNICODE_STRING moduleName, SIZE_T* pSize);
IMAGE_SECTION_HEADER* GetNtosknrlSectionHeader(const char* sectionName);
IMAGE_SECTION_HEADER* RvaToSection(PVOID base, ULONG rva);
PVOID FindNopBytes(PVOID start, SIZE_T size, SIZE_T nopSize);

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);