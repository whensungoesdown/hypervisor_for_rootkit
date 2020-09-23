//  [6/4/2015 uty]
#include <ntddk.h>
#include "amd64/vmx-asm.h"
#include "../../include/usertest.h"
//-----------------------------------------------------------------------------//
NTSTATUS
UtLockUserPagablePage (
	__in PVOID Address,	// address within the page
	__out PMDL* Mdl,
	__out PVOID* SystemAddress
	);
//-----------------------------------------------------------------------------//
#define HYPERVISOR_DEVICE_NAME  L"\\Device\\hypervisor"
#define HYPERVISOR_DOS_NAME  L"\\DosDevices\\hypervisor"
//-----------------------------------------------------------------------------//
NTSTATUS
Dispatch_ProtectUserPage (
	IN PVOID  InputBuffer,
	IN ULONG  InputBufferLength,
	OUT PVOID  OutputBuffer,
	IN ULONG  OutputBufferLength,
	OUT PIO_STATUS_BLOCK  IoStatusBlockP
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PUSER_SHADOW_PAGE pUserShadowPage = NULL;
	PMDL pMdl = NULL;
	PVOID pSystemAddress = NULL;
	PHYSICAL_ADDRESS OriginalPhysicalAddress = {0};
	PVOID pShadowPage = NULL;
	PHYSICAL_ADDRESS ShadowPhysicalPage = {0};

	pUserShadowPage = InputBuffer;

	DbgPrint("In Dispatch_ProtectUserPage, VirtualPageAddress 0x%p\n", pUserShadowPage->VirtualPageAddress);

	Status = UtLockUserPagablePage(pUserShadowPage->VirtualPageAddress, &pMdl, &pSystemAddress);
	if (STATUS_SUCCESS != Status)
	{
		goto Exit0;
	}

	OriginalPhysicalAddress = MmGetPhysicalAddress(pSystemAddress);
	
	pShadowPage = MmAllocateNonCachedMemory(PAGE_SIZE);
	memcpy(pShadowPage, pUserShadowPage->PageContent, PAGE_SIZE);
	ShadowPhysicalPage = MmGetPhysicalAddress(pShadowPage);

	MmUnlockPages(pMdl);

	VmxVmCall2(0x28, OriginalPhysicalAddress.QuadPart, ShadowPhysicalPage.QuadPart);


	Status = STATUS_SUCCESS;
Exit0:

	IoStatusBlockP->Status = STATUS_SUCCESS;
	IoStatusBlockP->Information = 0;

	return IoStatusBlockP->Status;
}
//-----------------------------------------------------------------------------//
typedef 
NTSTATUS 
(*PDISPATCH_FUNCTION)(
					  PVOID InBuffer,
					  ULONG uInBufferLength,
					  PVOID OutBuffer,
					  ULONG uOutBufferLength,
					  IO_STATUS_BLOCK *pIoStatusBlock
					  );

#define HYPERVISOR_DISPATCH_FUNCTION_NUMBER	1

PDISPATCH_FUNCTION HypervisorDispatch[HYPERVISOR_DISPATCH_FUNCTION_NUMBER] =
{
	Dispatch_ProtectUserPage,
};
//-----------------------------------------------------------------------------//
NTSTATUS
DriverDispatch (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PIO_STACK_LOCATION IrpSp = NULL;

	PVOID pInputOutputBuffer = NULL;
	ULONG ulInputBufferLength = 0;
	ULONG ulOutputBufferLength = 0;
	ULONG ulIoControlCode = 0;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;



	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	pInputOutputBuffer = Irp->AssociatedIrp.SystemBuffer;
	ulInputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	ulOutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;


	switch (IrpSp->MajorFunction)
	{
	case IRP_MJ_CREATE:
		break;
		
	case IRP_MJ_CLOSE:
		break;

	case IRP_MJ_DEVICE_CONTROL:

		ulIoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

		if (GET_FUNC_ID(ulIoControlCode) >= HYPERVISOR_DISPATCH_FUNCTION_NUMBER)
		{
			//
			// something must be wrong
			//
			break;
		}

		Status = HypervisorDispatch[GET_FUNC_ID(ulIoControlCode)] (
			pInputOutputBuffer,
			ulInputBufferLength,
			pInputOutputBuffer,
			ulOutputBufferLength,
			&(Irp->IoStatus));

		break;
	}


	Status = Irp->IoStatus.Status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}
//-----------------------------------------------------------------------------//
NTSTATUS
InitProtectUserPage (
	__in PDRIVER_OBJECT DriverObject
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uniDeviceName = {0};
	UNICODE_STRING uniDosName = {0};

	PDEVICE_OBJECT pDeviceObject = NULL;


	RtlInitUnicodeString(&uniDeviceName, HYPERVISOR_DEVICE_NAME);
	RtlInitUnicodeString(&uniDosName, HYPERVISOR_DOS_NAME);


	Status = IoCreateDevice(DriverObject,
		0,
		&uniDeviceName,
		FILE_DEVICE_HYPERVISOR, 0, FALSE,
		&pDeviceObject);
	if (!NT_SUCCESS(Status))
	{
		goto Exit0;
	}

	Status = IoCreateSymbolicLink(&uniDosName, &uniDeviceName);
	if (!NT_SUCCESS(Status))
	{
		goto Exit0;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] =
	DriverObject->MajorFunction[IRP_MJ_CLOSE] =
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//