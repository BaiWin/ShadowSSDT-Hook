//#include <ntifs.h>
#include "KernelIncludes.h"

extern NTSTATUS InitShadowSSDT();
extern VOID UnhookShadowSSDT();

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);


    PEPROCESS winlogonProcess = NULL;
    HANDLE pid = NULL;
    if (!NT_SUCCESS(GetProcessIdByName(&pid, L"winlogon.exe")))
        return STATUS_UNSUCCESSFUL;

    NTSTATUS status = PsLookupProcessByProcessId(pid, &winlogonProcess);
    if (!NT_SUCCESS(status) || !winlogonProcess)
        return STATUS_UNSUCCESSFUL;

    KAPC_STATE apcState;
    KeStackAttachProcess(winlogonProcess, &apcState);

    UnhookShadowSSDT();

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(winlogonProcess);

    DbgPrint("[W11Kernel] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrint("Hello from driver!\n");

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[W11Kernel] Driver loaded\n");


    PEPROCESS winlogonProcess = NULL;
    HANDLE pid = NULL;
    if (!NT_SUCCESS(GetProcessIdByName(&pid, L"winlogon.exe")))
    {
        DbgPrint("[W11Kernel] Failed to find pid\n");
        return STATUS_UNSUCCESSFUL;
    }
    NTSTATUS status = PsLookupProcessByProcessId(pid, &winlogonProcess);
    if (!NT_SUCCESS(status) || !winlogonProcess)
    {
        DbgPrint("[W11Kernel] Failed to find winlogon.exe\n");
        return STATUS_UNSUCCESSFUL;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(winlogonProcess, &apcState);

    InitShadowSSDT();

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(winlogonProcess);


    return STATUS_SUCCESS;
}