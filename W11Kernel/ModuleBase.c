#include "KernelIncludes.h"


PVOID GetModuleBaseByName(PCUNICODE_STRING moduleName, SIZE_T* pSize)
{
    NTSTATUS status;
    ULONG len = 0;
    PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;
    PVOID base = NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return NULL;

    moduleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, len, 'ModI');
    if (!moduleInfo)
        return NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, len, &len);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(moduleInfo, 'ModI');
        return NULL;
    }

    for (ULONG i = 0; i < moduleInfo->ModulesCount; i++)
    {
        ANSI_STRING ansiName;
        UNICODE_STRING uniName;

        // FullPathName 是 ANSI，转成 Unicode 再比较
        RtlInitAnsiString(&ansiName, (PCSZ)moduleInfo->Modules[i].FullPathName);

        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniName, &ansiName, TRUE)))
        {
            // 只比较文件名部分（后缀），忽略路径
            PCWSTR fileName = uniName.Buffer + (moduleInfo->Modules[i].OffsetToFileName);

            UNICODE_STRING uniFileName;
            RtlInitUnicodeString(&uniFileName, fileName);

            if (RtlCompareUnicodeString(&uniFileName, moduleName, TRUE) == 0)
            {
                base = moduleInfo->Modules[i].ImageBase;
                if (pSize)
                    *pSize = moduleInfo->Modules[i].ImageSize;
                RtlFreeUnicodeString(&uniName);
                break;
            }
            RtlFreeUnicodeString(&uniName);
        }
    }

    ExFreePoolWithTag(moduleInfo, 'ModI');
    return base;
}



IMAGE_SECTION_HEADER* GetNtosknrlSectionHeader(const char* sectionName)
{
    SIZE_T ntSize = 0;
    UNICODE_STRING ntoskrnlName = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    PVOID ntBase = GetModuleBaseByName(&ntoskrnlName, &ntSize);
    if (!ntBase) return NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PUCHAR)ntBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt); // .text

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (strncmp((const char*)sec->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            return sec;
        }
    }

    return NULL;
}

// 获取ntQuery...的函数的所在节section
IMAGE_SECTION_HEADER* RvaToSection(PVOID base, ULONG rva)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PUCHAR)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
            return section;
    }
    return NULL;
}

PVOID FindNopBytes(PVOID start, SIZE_T size, SIZE_T nopSize)
{
    for (SIZE_T i = 0; i < size - nopSize; i++)
    {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < nopSize; j++)
        {
            if (*((PUCHAR)start + i + j) != 0x90)
            {
                match = FALSE;
                break;
            }
        }
        if (match) return (PUCHAR)start + i;
    }
    return NULL;
}