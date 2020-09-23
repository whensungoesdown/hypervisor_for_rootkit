//  [6/27/2015 uty]
#include <ntddk.h>
#include <mmintrin.h>
#include "keyboardclassservicecallback.h"
//-----------------------------------------------------------------------------//
NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID *Object
	);
//-----------------------------------------------------------------------------//
extern POBJECT_TYPE *IoDriverObjectType;
//-----------------------------------------------------------------------------//
#define KBD_DRIVER_NAME L"\\Driver\\kbdclass"
#define USBKBD_DRIVER_NAME L"\\Driver\\Kbdhid"
#define PS2KBD_DRIVER_NAME L"\\Driver\\i8042prt"
//-----------------------------------------------------------------------------//
KBD_CALLBACK g_KbdCallBack = {0};
//-----------------------------------------------------------------------------//
NTSTATUS
SearchKeyboardClassServiceCallback (
	__in PDRIVER_OBJECT DriverObject
	)
{
	NTSTATUS Status = STATUS_SUCCESS;
	int i = 0;
	UNICODE_STRING uniNtNameString;
	PDEVICE_OBJECT pTargetDeviceObject = NULL;
	PDRIVER_OBJECT KbdDriverObject = NULL;
	PDRIVER_OBJECT KbdhidDriverObject = NULL;
	PDRIVER_OBJECT Kbd8042DriverObject = NULL;
	PDRIVER_OBJECT UsingDriverObject = NULL;
	PDEVICE_OBJECT UsingDeviceObject = NULL;

	PVOID KbdDriverStart = NULL;
	ULONG KbdDriverSize = 0;
	PVOID UsingDeviceExt = NULL;

	RtlInitUnicodeString(&uniNtNameString, USBKBD_DRIVER_NAME);
	Status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&KbdDriverObject);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Couldn't get the USB driver Object 0x%x\n", Status);
	}
	else
	{
		ObDereferenceObject(KbdhidDriverObject);
		DbgPrint("get the USB driver Object\n");
	}

	RtlInitUnicodeString(&uniNtNameString,PS2KBD_DRIVER_NAME);
	Status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&Kbd8042DriverObject);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Couldn't get the PS/2 driver Object 0x%x\n", Status);
	}
	else
	{
		ObDereferenceObject(Kbd8042DriverObject);
		DbgPrint("get the PS/2 driver Object\n");
	}

	if (Kbd8042DriverObject && KbdhidDriverObject)
	{
		DbgPrint("more than two kbd!\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (!Kbd8042DriverObject && !KbdhidDriverObject)
	{
		DbgPrint("no kbd!\n");
		return STATUS_SUCCESS;
	}

	UsingDriverObject = Kbd8042DriverObject? Kbd8042DriverObject : KbdhidDriverObject;
	if (NULL != UsingDriverObject->DeviceObject->NextDevice)
	{
		//
		// on win7, Kbdclass creates two device object. I guess it's the first one I am looking for
		//
		UsingDeviceObject = UsingDriverObject->DeviceObject->NextDevice; // uty debug
	}
	else
	{
		UsingDeviceObject = UsingDriverObject->DeviceObject;
	}

	UsingDeviceExt = UsingDeviceObject->DeviceExtension;

	DbgPrint("Device 0x%p\n", UsingDeviceObject);
	DbgPrint("DeviceExtension 0x%p\n", UsingDeviceObject->DeviceExtension);

	RtlInitUnicodeString(&uniNtNameString,KBD_DRIVER_NAME);
	Status = ObReferenceObjectByName(
		&uniNtNameString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&KbdDriverObject);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("MyAttach: Coundn't get the kbd driver Object\n");
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		ObDereferenceObject(KbdDriverObject);
		KbdDriverStart = KbdDriverObject->DriverStart;
		KbdDriverSize = KbdDriverObject->DriverSize;
	}

	pTargetDeviceObject = KbdDriverObject->DeviceObject;
	while(pTargetDeviceObject)
	{
		PCHAR DeviceExt;

		DeviceExt = (PCHAR)UsingDeviceExt;
		for ( ; i < 4096; i++, DeviceExt += 4)
		{
			PVOID tmp;
			if (!MmIsAddressValid(DeviceExt))
			{
				break;
			}

			if (g_KbdCallBack.classDeviceObject && g_KbdCallBack.serviceCallBack)
			{
				Status = STATUS_SUCCESS;
				break;
			}

			tmp = *(PVOID*)DeviceExt;
			if (tmp == pTargetDeviceObject)
			{
				g_KbdCallBack.classDeviceObject = (PDEVICE_OBJECT)tmp;
				DbgPrint("classDeviceObject %8x\n",tmp);
				continue;
			}

			if ((tmp > KbdDriverStart) && (tmp < (PVOID)((PCHAR)KbdDriverStart+KbdDriverSize)) && (MmIsAddressValid(tmp)))
			{
				g_KbdCallBack.serviceCallBack = (PKEYBOARDCLASSSERVICECALLBACK)tmp;
				DbgPrint("serviceCallBack: 0x%p\n", tmp);
				return STATUS_SUCCESS;
			}
		}

		pTargetDeviceObject = pTargetDeviceObject->NextDevice;
	}

	return Status;
}
//-----------------------------------------------------------------------------//
VOID
DisableWriteProtect (
	VOID
	)
{
	__writecr0(__readcr0() & (~(0x10000)));

}
//-----------------------------------------------------------------------------//
VOID
EnableWriteProtect (
	VOID
	)
{
	__writecr0(__readcr0() ^ 0x10000);
}
//-----------------------------------------------------------------------------//
PKEYBOARDCLASSSERVICECALLBACK OriginalKeyboardClassServiceCallBack = NULL;
VOID KeyboardClassServiceCallbackTrampoline(VOID);
//-----------------------------------------------------------------------------//
NTSTATUS
InlineHookKeyboardClassServiceCallback (
	__in PVOID Function,
	__in PVOID FunctionHook
	)
{
	UCHAR TmpTrampoline[15] = {0};
	LARGE_INTEGER FuncAddress = {0};

	PUCHAR pTrampoline = NULL;


	FuncAddress.QuadPart = (LONGLONG)FunctionHook;

	// PUSH <Low Absolute Address DWORD>
	// ; Only if required (when High half is non zero):
	// MOV [RSP+4], DWORD <High Absolute Address DWORD>
	// RET
	TmpTrampoline[0] = 0x68;
	*(PULONG)&TmpTrampoline[1] = FuncAddress.LowPart;
	*(PULONG)&TmpTrampoline[5] = 0x042444C7;
	*(PULONG)&TmpTrampoline[9] = FuncAddress.HighPart;
	TmpTrampoline[13] = 0xC3;
	TmpTrampoline[14] = 0x90;


	FuncAddress.QuadPart = (LONGLONG)Function + 15;
	DisableWriteProtect();
	pTrampoline = (PUCHAR)KeyboardClassServiceCallbackTrampoline + 15;
	pTrampoline[0] = 0x68;
	*(PULONG)&pTrampoline[1] = FuncAddress.LowPart;
	*(PULONG)&pTrampoline[5] = 0x042444C7;
	*(PULONG)&pTrampoline[9] = FuncAddress.HighPart;
	pTrampoline[13] = 0xC3;
	EnableWriteProtect();

	OriginalKeyboardClassServiceCallBack = (PKEYBOARDCLASSSERVICECALLBACK)KeyboardClassServiceCallbackTrampoline;


	DisableWriteProtect();
	memcpy(Function, TmpTrampoline, 15);
	EnableWriteProtect();

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
VOID
KeyboardClassServiceCallbackHook (
	__in    PDEVICE_OBJECT       DeviceObject,
	__in    PKEYBOARD_INPUT_DATA InputDataStart,
	__in    PKEYBOARD_INPUT_DATA InputDataEnd,
	__inout PULONG               InputDataConsumed
	)
{
	DbgPrint("!!!\n\n");

	OriginalKeyboardClassServiceCallBack(DeviceObject,
		                                 InputDataStart,
		                                 InputDataEnd,
		                                 InputDataConsumed);
}
//-----------------------------------------------------------------------------//