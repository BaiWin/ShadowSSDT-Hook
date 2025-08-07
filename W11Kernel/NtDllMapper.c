#include "KernelIncludes.h"

NTSTATUS ZwCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

NTSTATUS ZwCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

NTSTATUS ZwMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,  // 用这个枚举类型
    ULONG AllocationType,
    ULONG Win32Protect
);

// 结构体、宏定义可自行根据需要添加

// 从映射基址和导出名获取导出函数地址
static PVOID GetExportedFunction(PVOID baseAddress, PCSTR exportName)
{
    if (!baseAddress)
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_DATA_DIRECTORY exportDirData = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData.Size == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)baseAddress + exportDirData.VirtualAddress);
    ULONG* addrOfNames = (ULONG*)((PUCHAR)baseAddress + exportDir->AddressOfNames);
    ULONG* addrOfFuncs = (ULONG*)((PUCHAR)baseAddress + exportDir->AddressOfFunctions);
    USHORT* addrOfNameOrdinals = (USHORT*)((PUCHAR)baseAddress + exportDir->AddressOfNameOrdinals);

    for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char* currentName = (const char*)((PUCHAR)baseAddress + addrOfNames[i]);
        if (_stricmp(currentName, exportName) == 0)
        {
            USHORT ordinal = addrOfNameOrdinals[i];
            ULONG funcRVA = addrOfFuncs[ordinal];
            return (PUCHAR)baseAddress + funcRVA;
        }
    }
    return NULL;
}

// 主函数，映射用户态dll文件，并返回导出函数地址
PVOID MapUserNtdllAndFindExport(PCWSTR dllPath, PCSTR exportName)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus;
    HANDLE sectionHandle = NULL;
    PVOID mappedBase = NULL;
    LARGE_INTEGER sectionOffset = { 0 };
    SIZE_T viewSize = 0;

    InitializeObjectAttributes(&objAttr, (PUNICODE_STRING)NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, dllPath);
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // 打开文件
    status = ZwCreateFile(&fileHandle,
        GENERIC_READ,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
        return NULL;

    // 创建节
    status = ZwCreateSection(&sectionHandle,
        SECTION_MAP_READ,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        fileHandle);

    ZwClose(fileHandle);
    if (!NT_SUCCESS(status))
        return NULL;

    // 映射节到内核地址空间
    status = ZwMapViewOfSection(sectionHandle,
        NtCurrentProcess(),
        &mappedBase,
        0,
        0,
        &sectionOffset,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READONLY);

    ZwClose(sectionHandle);
    if (!NT_SUCCESS(status))
        return NULL;

    // 解析导出表
    PVOID funcAddr = GetExportedFunction(mappedBase, exportName);

    // 这里没有解除映射，你可以根据需要加解除映射逻辑

    return funcAddr;
}