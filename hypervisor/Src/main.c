//  [5/2/2015 uty]
#include <ntddk.h>
#include "vmminitstate.h"
#include "amd64/common-asm.h"
#include "vmx.h"
#include "ept.h"
#include "powercallback.h"
//-----------------------------------------------------------------------------//
NTSTATUS
RunOnProcessor (
	__in ULONG ProcessorNumber
	)
{
	KIRQL OldIrql;

	KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));
	
	OldIrql = KeRaiseIrqlToDpcLevel();

	//
	// Initialize VMX on every CPU
	//

	StartVMX();

	KeLowerIrql(OldIrql);

	KeRevertToUserAffinityThread();

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
DEV_EXT g_DevExt = {0};
//-----------------------------------------------------------------------------//
NTSTATUS
DriverEntry (
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING DeviceName = { 0 };
    PDEVICE_OBJECT  DeviceObject = NULL;

	LONG i = 0;

    RtlInitUnicodeString(&DeviceName, L"\\Device\\hypervisor");
    Status = IoCreateDevice(DriverObject, 0, &DeviceName,
        FILE_DEVICE_UNKNOWN, 0, FALSE,
        &DeviceObject);
    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("IoCreateDevice fail.\n");
        goto Exit0;
    }

	Status = RegisterPowerStateChangeCallback(&g_DevExt);
	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("RegisterPowerStateChangeCallback fail 0x%x\n", Status);
		goto Exit0;
	}

	Status = GetE820FromRegistry(&g_TotalPhysicalMemory);
	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("GetE820FromRegistry fail 0x%x\n", Status);
		goto Exit0;
	}

	Status = InitEptTable();
	if (STATUS_SUCCESS != Status)
	{
		goto Exit0;
	}

	for (i = 0; i < KeNumberProcessors; i++)
	{
		Status = InitializeVMMInitState(&g_VMMInitState[i]);
	}

	for (i = 0; i < KeNumberProcessors; i++)
	{
		Status = RunOnProcessor(i);
		if (STATUS_SUCCESS != Status)
		{
			DbgPrint("RunOnProcessor failed on processor %d\n", i);
			break;
		}
	}

	Status = STATUS_SUCCESS;
Exit0:

	if (STATUS_SUCCESS != Status)
	{
		for (i = 0; i < KeNumberProcessors; i++)
		{
			UninitializeVMMInitState(&g_VMMInitState[i]);
		}
	}
	

	return Status;
}
//-----------------------------------------------------------------------------//