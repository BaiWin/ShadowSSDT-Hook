#include "KernelIncludes.h"
#define PE_ERROR_VALUE 0xFFFFFFFF

// ----------------- 你的结构体定义 -----------------

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR ServiceTableBase;
    PULONG_PTR ServiceCounterTableBase; // optional
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE_SHADOW
{
    SERVICE_DESCRIPTOR_TABLE Table[2]; // Table[1] = win32k!W32pServiceTable   //g_KeServiceDescriptorTableShadow->Table[1].ServiceTableBase;
} SERVICE_DESCRIPTOR_TABLE_SHADOW, * PSERVICE_DESCRIPTOR_TABLE_SHADOW;   

// ----------------- 声明全局变量 -----------------

// 注意：去掉dllimport声明，改为指针，动态获取
PSERVICE_DESCRIPTOR_TABLE_SHADOW g_KeServiceDescriptorTableShadow = NULL;

PVOID OriginalNtQueryCompositionSurfaceStatistics = NULL;

extern NTSTATUS MyNtQueryCompositionSurfaceStatistics();

ULONG index = 0xFFFFFFFF; // 无效索引标记

PUCHAR ntBase = NULL;

PVOID FindKeServiceDescriptorTableShadow()
{
   /* 0: kd > u nt!KiSystemServiceStart
        nt!KiSystemServiceStart:
        fffff800`03e9575e 4889a3d8010000  mov     qword ptr[rbx + 1D8h], rsp
        fffff800`03e95765 8bf8            mov     edi, eax
        fffff800`03e95767 c1ef07          shr     edi, 7
        fffff800`03e9576a 83e720 and edi, 20h
        fffff800`03e9576d 25ff0f0000 and eax, 0FFFh
        nt!KiSystemServiceRepeat:
        fffff800`03e95772 4c8d15c7202300  lea     r10, [nt!KeServiceDescriptorTable(fffff800`040c7840)]
        fffff800`03e95779 4c8d1d00212300  lea     r11, [nt!KeServiceDescriptorTableShadow*/

    SIZE_T ntSize = 0;
    UNICODE_STRING ntoskrnlName = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    ntBase = GetModuleBaseByName(&ntoskrnlName, &ntSize);
    if (!ntBase)
    {
        DbgPrint("[W11Kernel] Failed to find win32k base\n");
        return NULL;
    }

    unsigned char pattern[] = {
        0x8B, 0xF8,                     // mov edi,eax
        0xC1, 0xEF, 0x07,               // shr edi,7
        0x83, 0xE7, 0x20,               // and edi,20h
        0x25, 0xFF, 0x0F, 0x00, 0x00    // and eax,0fffh  
    };

    SIZE_T patternLength = sizeof(pattern);
    PUCHAR match = NULL;

    for (ULONG i = 0; i <= ntSize - patternLength; i++)
    {
        if (RtlCompareMemory(ntBase + i, pattern, patternLength) == patternLength)
        {
            match = ntBase + i;
            break;
        }
    }

    if (!match)
    {
        DbgPrint("[W11Kernel] Failed to find pattern\n");
        return NULL;
    }

    PUCHAR address = match + 0xD + 0x7; // 跳过 pattern 和 lea 指令

    DbgPrint("[W11Kernel] Calculated address: %p", address);
    DbgPrint("[W11Kernel] Bytes: %02X %02X %02X", address[0], address[1], address[2]);

    if (address[0] == 0x4C && address[1] == 0x8D && address[2] == 0x1D)
    {
        LONG relOffset = *(LONG*)(address + 3);
        return (PVOID)(address + 7 + relOffset);
    }

    return NULL;
}

// ----------------- 查找函数索引 -----------------

// 实现示例（放在文件合适位置）

// Helper: RVA转文件偏移
ULONG RvaToOffset(PIMAGE_NT_HEADERS NtHeaders, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    USHORT i;

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        ULONG SectionVA = Section[i].VirtualAddress;
        ULONG SectionSize = Section[i].SizeOfRawData;

        if (Rva >= SectionVA && Rva < SectionVA + SectionSize)
        {
            ULONG delta = Rva - SectionVA;
            if (delta > Section[i].SizeOfRawData)
            {
                DbgPrint("RvaToOffset: delta > SizeOfRawData\n");
                return PE_ERROR_VALUE;
            }
            if (Section[i].PointerToRawData + delta > FileSize)
            {
                DbgPrint("RvaToOffset: Offset out of file size\n");
                return PE_ERROR_VALUE;
            }

            return Section[i].PointerToRawData + delta;
        }
    }
    DbgPrint("RvaToOffset: No matching section found\n");
    return PE_ERROR_VALUE;
}

// 磁盘读取ntdll,解析pe结构和导出表,找到函数机器码起始地址,搜索 mov eax, XX 指令获取系统调用号（SSDT索引）,返回索引
ULONG GetSyscallIndex(_In_ PCSTR ExportName)
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjAttr;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    ULONG FileSize = 0;
    UCHAR* FileData = NULL;
    ULONG syscallIndex = (ULONG)-1;

    DbgPrint("GetSyscallIndex: Start for %s\n", ExportName);

    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\System32\\ntdll.dll");
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateFile(&FileHandle, GENERIC_READ, &ObjAttr, &IoStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("ZwCreateFile failed: 0x%X\n", Status);
        return (ULONG)-1;
    }

    FILE_STANDARD_INFORMATION FileInfo;
    Status = ZwQueryInformationFile(FileHandle, &IoStatus, &FileInfo, sizeof(FileInfo), FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("ZwQueryInformationFile failed: 0x%X\n", Status);
        ZwClose(FileHandle);
        return (ULONG)-1;
    }

    FileSize = FileInfo.EndOfFile.LowPart;
    DbgPrint("File size: %u bytes\n", FileSize);

    FileData = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, FileSize, 'ldNT');
    if (!FileData)
    {
        DbgPrint("ExAllocatePoolWithTag failed\n");
        ZwClose(FileHandle);
        return (ULONG)-1;
    }

    LARGE_INTEGER Offset = { 0 };
    Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, FileData, FileSize, &Offset, NULL);
    ZwClose(FileHandle);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("ZwReadFile failed: 0x%X\n", Status);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DbgPrint("Invalid DOS signature: 0x%X\n", pDosHeader->e_magic);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(FileData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DbgPrint("Invalid NT signature: 0x%X\n", pNtHeaders->Signature);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_DATA_DIRECTORY DataDir;
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        DataDir = ((PIMAGE_NT_HEADERS64)pNtHeaders)->OptionalHeader.DataDirectory;
    else
        DataDir = ((PIMAGE_NT_HEADERS32)pNtHeaders)->OptionalHeader.DataDirectory;

    ULONG ExportDirRva = DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    ULONG ExportDirOffset = RvaToOffset(pNtHeaders, ExportDirRva, FileSize);
    if (ExportDirOffset == PE_ERROR_VALUE)
    {
        DbgPrint("Export directory offset invalid\n");
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
    ULONG NumberOfNames = pExportDir->NumberOfNames;

    ULONG AddrOfFuncsOffset = RvaToOffset(pNtHeaders, pExportDir->AddressOfFunctions, FileSize);
    ULONG AddrOfNameOrdinalsOffset = RvaToOffset(pNtHeaders, pExportDir->AddressOfNameOrdinals, FileSize);
    ULONG AddrOfNamesOffset = RvaToOffset(pNtHeaders, pExportDir->AddressOfNames, FileSize);

    if (AddrOfFuncsOffset == PE_ERROR_VALUE || AddrOfNameOrdinalsOffset == PE_ERROR_VALUE || AddrOfNamesOffset == PE_ERROR_VALUE)
    {
        DbgPrint("Export table offsets invalid\n");
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    ULONG* AddrOfFuncs = (ULONG*)(FileData + AddrOfFuncsOffset);
    USHORT* AddrOfNameOrdinals = (USHORT*)(FileData + AddrOfNameOrdinalsOffset);
    ULONG* AddrOfNames = (ULONG*)(FileData + AddrOfNamesOffset);

    ULONG FuncOffset = PE_ERROR_VALUE;
    for (ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrNameOffset = RvaToOffset(pNtHeaders, AddrOfNames[i], FileSize);
        if (CurrNameOffset == PE_ERROR_VALUE)
            continue;

        const char* CurrName = (const char*)(FileData + CurrNameOffset);

        if (strcmp(CurrName, ExportName) == 0)
        {
            ULONG FuncRva = AddrOfFuncs[AddrOfNameOrdinals[i]];
            if (FuncRva >= ExportDirRva && FuncRva < ExportDirRva + ExportDirSize)
            {
                DbgPrint("Forwarded export, ignoring: %s\n", ExportName);
                continue;
            }
            FuncOffset = RvaToOffset(pNtHeaders, FuncRva, FileSize);
            DbgPrint("Found function %s at file offset 0x%X\n", ExportName, FuncOffset);
            break;
        }
    }

    if (FuncOffset == PE_ERROR_VALUE)
    {
        DbgPrint("Function %s not found in export table\n", ExportName);
        ExFreePoolWithTag(FileData, 'ldNT');
        return (ULONG)-1;
    }

    UCHAR* pFuncCode = FileData + FuncOffset;
    for (int i = 0; i < 32 && FuncOffset + i < FileSize; i++)
    {
        if (pFuncCode[i] == 0xC2 || pFuncCode[i] == 0xC3) // ret
            break;
        if (pFuncCode[i] == 0xB8) // mov eax, imm32
        {
            syscallIndex = *(ULONG*)(pFuncCode + i + 1);
            DbgPrint("Syscall index for %s is %u\n", ExportName, syscallIndex);
            break;
        }
    }

    if (syscallIndex == (ULONG)-1)
        DbgPrint("Syscall index not found in function %s\n", ExportName);

    ExFreePoolWithTag(FileData, 'ldNT');
    return syscallIndex;
}



// 映射ntdll到内核空间，目前弃用
//ULONG GetSyscallIndex_UseMapper()
//{
//    // 确保路径正确，win10/11默认路径
//    PCWSTR ntdllPath = L"\\SystemRoot\\System32\\ntdll.dll";
//    PVOID funcAddr = MapUserNtdllAndFindExport(ntdllPath, "NtQueryCompositionSurfaceStatistics");
//    if (!funcAddr)
//        return (ULONG)-1;
//    if (!funcAddr)
//        DbgPrint("No func Addr\n");
//
//    PUCHAR bytes = (PUCHAR)funcAddr;
//    if (bytes[0] != 0xB8) // mov eax, imm32
//        return (ULONG)-1;
//
//    return *(ULONG*)(bytes + 1);
//}

// ----------------- InitShadowSSDT 改写 -----------------

NTSTATUS InitShadowSSDT()
{
    if (g_KeServiceDescriptorTableShadow == NULL)
    {
        g_KeServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE_SHADOW)FindKeServiceDescriptorTableShadow();  // win32k.sys
        if (g_KeServiceDescriptorTableShadow == NULL)
        {
            DbgPrint("[W11Kernel] Failed to find KeServiceDescriptorTableShadow\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[W11Kernel] KeServiceDescriptorTableShadow found at %p\n", g_KeServiceDescriptorTableShadow);
    }

    if (index == 0xFFFFFFFF)
    {
        index = GetSyscallIndex("NtQuerySystemInformation"); //NtQueryCompositionSurfaceStatistics ntdll
        if (index == (ULONG)-1)
        {
            DbgPrint("[W11Kernel] Failed to get syscall index.\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[+] Syscall Index: 0x%X\n", index);
    }

    // Shadow SSDT 基址
    PVOID W32pServiceTable = g_KeServiceDescriptorTableShadow->Table[1].ServiceTableBase;

    IMAGE_SECTION_HEADER* textSectionHeader = GetNtosknrlSectionHeader(".text");
    if (textSectionHeader)
    {
        DbgPrint("Section .text of win32k.sys found at offset: 0x%X\n", textSectionHeader->VirtualAddress);
    }

    PVOID dataSectionVA = (PUCHAR)ntBase + textSectionHeader->VirtualAddress;
    SIZE_T dataSectionSize = max(textSectionHeader->Misc.VirtualSize, textSectionHeader->SizeOfRawData);

    PVOID nopAddress = FindNopBytes(dataSectionVA, dataSectionSize, sizeof(HOOKOPCODES));

    if (nopAddress == NULL)
    {
        DbgPrint("[+] ntBase: 0x%p\n", ntBase);
        DbgPrint("[+] VirtualAddress: 0x%p\n", textSectionHeader->VirtualAddress);
        DbgPrint("[+] dataSectionVA: 0x%p\n", dataSectionVA);
        DbgPrint("[+] dataSectionSize: 0x%llx (%llu)\n", dataSectionSize, dataSectionSize);
        DbgPrint("[+] HOOKOPCODESSize: 0x%llx (%llu)\n", sizeof(HOOKOPCODES), sizeof(HOOKOPCODES));
        DbgPrint("[+] dataNopAddress: 0x%p\n", nopAddress);
        return STATUS_UNSUCCESSFUL;
    }

    //allocate structure
    PHOOK hook = (PHOOK)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK), 'kooH');
    //set hooking address
    hook->addr = nopAddress;        // Store the cave address
    //set hooking opcode
#ifdef _WIN64
    hook->hook.mov = 0xB848;
#else
    hook->hook.mov = 0xB8;
#endif
    hook->hook.addr = (ULONG_PTR)MyNtQueryCompositionSurfaceStatistics;    // Insert our own function
    hook->hook.push = 0x50;
    hook->hook.ret = 0xc3;
    //set original data
    RtlCopyMemory(&hook->orig, (const void*)nopAddress, sizeof(HOOKOPCODES));


    if (MmIsAddressValid((void*)nopAddress) == FALSE)
    {
        DbgPrint("Destination is not valid!\n");
        return STATUS_ACCESS_VIOLATION;
    }

    SuperCopyMemory((void*)nopAddress, &hook->hook, sizeof(HOOKOPCODES));  // set shellcode

    PLONG W32pServiceEntries = (PLONG)W32pServiceTable;
    LONG oldOffset = W32pServiceEntries[index];
    LONG newOffset = (LONG)((ULONG_PTR)nopAddress - (ULONG_PTR)W32pServiceEntries);
    newOffset = ((newOffset << 4) | (oldOffset & 0xF));

    ULONG_PTR realNtFunction = W32pServiceEntries[index] >> 4 + (ULONG_PTR)W32pServiceTable;

    hook->SSDTold = oldOffset;
    hook->SSDTnew = newOffset;
    hook->SSDTindex = index;
    hook->SSDTaddress = realNtFunction;

    SuperCopyMemory(&W32pServiceEntries[index], newOffset, sizeof(newOffset)); // hook offset -> shellcode offset

    return STATUS_SUCCESS;
}

VOID UnhookShadowSSDT()
{
    if (!OriginalNtQueryCompositionSurfaceStatistics)
        return;

    //SuperCopyMemory((void*)nopAddress, &hook->hook, sizeof(HOOKOPCODES));

    //SuperCopyMemory(&W32pServiceEntries[index], newOffset, sizeof(newOffset));

    DbgPrint("[W11Kernel] Shadow SSDT unhooked.\n");


}