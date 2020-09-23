//  [4/24/2015 frank_z_zhang]
#include <ntddk.h>
#include <mmintrin.h>
#include "amd64/vmx-asm.h"
#include "amd64/msr-asm.h"
#include "protectuserpage.h"
#include "ntquerysysteminformation.h"
//-----------------------------------------------------------------------------//
NTSTATUS NtCreateFile(
  __out     PHANDLE            FileHandle,
  __in      ACCESS_MASK        DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __out     PIO_STATUS_BLOCK   IoStatusBlock,
  __in_opt  PLARGE_INTEGER     AllocationSize,
  __in      ULONG              FileAttributes,
  __in      ULONG              ShareAccess,
  __in      ULONG              CreateDisposition,
  __in      ULONG              CreateOptions,
  __in_opt  PVOID              EaBuffer,
  __in      ULONG              EaLength
);

typedef
NTSTATUS
(NTAPI *PNTCREATEFILE)(
  __out     PHANDLE            FileHandle,
  __in      ACCESS_MASK        DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __out     PIO_STATUS_BLOCK   IoStatusBlock,
  __in_opt  PLARGE_INTEGER     AllocationSize,
  __in      ULONG              FileAttributes,
  __in      ULONG              ShareAccess,
  __in      ULONG              CreateDisposition,
  __in      ULONG              CreateOptions,
  __in_opt  PVOID              EaBuffer,
  __in      ULONG              EaLength
);
//-----------------------------------------------------------------------------//
VOID NtCreateFileTrampoline(VOID);
//-----------------------------------------------------------------------------//
PVOID NtCreateFileAddress = NULL;
PNTCREATEFILE OriginalNtCreateFile = NULL;
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
NTSTATUS NtCreateFileHook(
  __out     PHANDLE            FileHandle,
  __in      ACCESS_MASK        DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __out     PIO_STATUS_BLOCK   IoStatusBlock,
  __in_opt  PLARGE_INTEGER     AllocationSize,
  __in      ULONG              FileAttributes,
  __in      ULONG              ShareAccess,
  __in      ULONG              CreateDisposition,
  __in      ULONG              CreateOptions,
  __in_opt  PVOID              EaBuffer,
  __in      ULONG              EaLength
)
{
	static LONG Count = 0;

	if(Count < 0) 
	{
		DbgPrint("inline hooking NtCreateFile\n");
		Count = 30;
	}
	else 
	{
		Count--;
	}

	return OriginalNtCreateFile (FileHandle,
		                         DesiredAccess,
								 ObjectAttributes,
								 IoStatusBlock,
								 AllocationSize,
								 FileAttributes,
								 ShareAccess,
								 CreateDisposition,
								 CreateOptions,
								 EaBuffer,
								 EaLength);
}
//-----------------------------------------------------------------------------//
//
// nt!NtCreateFile:
// fffff800`02b89400 4c8bdc          mov     r11,rsp
// fffff800`02b89403 4881ec88000000  sub     rsp,88h
// fffff800`02b8940a 33c0            xor     eax,eax
// fffff800`02b8940c 498943f0        mov     qword ptr [r11-10h],rax
// fffff800`02b89410 c744247020000000 mov     dword ptr [rsp+70h],20h
// fffff800`02b89418 89442468        mov     dword ptr [rsp+68h],eax
// fffff800`02b8941c 498943d8        mov     qword ptr [r11-28h],rax
// fffff800`02b89420 89442458        mov     dword ptr [rsp+58h],eax
//
NTSTATUS
InlineHookNtCreateFile (
	__in PVOID Function,
	__in PVOID FunctionHook
	)
{
	UCHAR TmpTrampoline[16] = {0};
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
	TmpTrampoline[15] = 0x90;


	FuncAddress.QuadPart = (LONGLONG)Function + 16;
	DisableWriteProtect();
	pTrampoline = (PUCHAR)NtCreateFileTrampoline + 16;
	pTrampoline[0] = 0x68;
	*(PULONG)&pTrampoline[1] = FuncAddress.LowPart;
	*(PULONG)&pTrampoline[5] = 0x042444C7;
	*(PULONG)&pTrampoline[9] = FuncAddress.HighPart;
	pTrampoline[13] = 0xC3;
	EnableWriteProtect();

	OriginalNtCreateFile = (PNTCREATEFILE)NtCreateFileTrampoline;


	DisableWriteProtect();
	memcpy(Function, TmpTrampoline, 16);
	EnableWriteProtect();


	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
NTSTATUS
UtLockPagablePage (
	__in PVOID Address	// address within the page
	)
{
	PMDL pMdl = NULL;

	pMdl = IoAllocateMdl((PVOID)((ULONG_PTR)Address & ~(PAGE_SIZE - 1)), PAGE_SIZE, FALSE, FALSE, NULL);
	DbgPrint("Lock Page 0x%p\n", (ULONG_PTR)Address & ~(PAGE_SIZE - 1));
	if (NULL == pMdl)
	{
		return STATUS_UNSUCCESSFUL;
	}

	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}
	
	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
NTSTATUS
UtLockUserPagablePage (
	__in PVOID Address,	// address within the page
	__out PMDL* Mdl,
	__out PVOID* SystemAddress
	)
{
	PVOID pSystemAddress = NULL;

	*Mdl = IoAllocateMdl((PVOID)((ULONG_PTR)Address & ~(PAGE_SIZE - 1)), PAGE_SIZE, FALSE, FALSE, NULL);
	DbgPrint("Lock Page 0x%p\n", (ULONG_PTR)Address & ~(PAGE_SIZE - 1));
	if (NULL == *Mdl)
	{
		return STATUS_UNSUCCESSFUL;
	}

	__try
	{
		MmProbeAndLockPages(*Mdl, UserMode, IoReadAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

	pSystemAddress = MmGetSystemAddressForMdlSafe(*Mdl, NormalPagePriority);
	if (NULL == pSystemAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}

	*SystemAddress = pSystemAddress;
	
	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
NTSTATUS TestInvisibleNtCreateFileInlineHook (VOID)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uniNtCreateFile = {0};

	PVOID pReturn = NULL;
	PVOID pOrigianlAddress = NULL;
	PHYSICAL_ADDRESS OriginalPhysicalAddress = {0};
	PVOID pShadowPage = NULL;
	PHYSICAL_ADDRESS ShadowPhysicalPage = {0};

	RtlInitUnicodeString(&uniNtCreateFile, L"NtCreateFile");
	NtCreateFileAddress = (PVOID)MmGetSystemRoutineAddress(&uniNtCreateFile);
	if( NULL == NtCreateFileAddress )
	{
		Status = STATUS_UNSUCCESSFUL;
		goto Exit0;
	}

	pOrigianlAddress = (PVOID)NtCreateFileAddress;

	pReturn = MmLockPagableCodeSection((PVOID)pOrigianlAddress);
	if (NULL == pReturn)
	{
		DbgPrint("MmLocakPagableCodeSection fail.\n");
		Status = STATUS_UNSUCCESSFUL;
		goto Exit0;
	}

	OriginalPhysicalAddress = MmGetPhysicalAddress(pOrigianlAddress);

	pShadowPage = MmAllocateNonCachedMemory(PAGE_SIZE);
	memcpy(pShadowPage, PAGE_ALIGN(pOrigianlAddress), PAGE_SIZE);
	// Get Physical page
	ShadowPhysicalPage = MmGetPhysicalAddress(pShadowPage);
	DbgPrint("Shadow Physical page 0x%x\n", ShadowPhysicalPage.LowPart);


	InlineHookNtCreateFile((PVOID)NtCreateFileAddress, (PVOID)NtCreateFileHook);
	// init
	VmxVmCall2(0x28, OriginalPhysicalAddress.QuadPart, ShadowPhysicalPage.QuadPart);


	Status = STATUS_SUCCESS;
Exit0:                                              
	return Status;
}
//-----------------------------------------------------------------------------//
NTSTATUS
Test (VOID)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uniNtCreateFile = {0};

	PHYSICAL_ADDRESS OriginalPhysicalAddress = {0};


	RtlInitUnicodeString(&uniNtCreateFile, L"NtCreateFile");
	NtCreateFileAddress = (PVOID)MmGetSystemRoutineAddress(&uniNtCreateFile);
	if( NULL == NtCreateFileAddress )
	{
		Status = STATUS_UNSUCCESSFUL;
		goto Exit0;
	}

	OriginalPhysicalAddress = MmGetPhysicalAddress(NtCreateFileAddress);

	DbgPrint("NtCreateFile address 0x%p, Physical address 0x%p\n", NtCreateFileAddress, OriginalPhysicalAddress);

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
NTSTATUS
DriverEntry (
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
	)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING DeviceName = { 0 };
    PDEVICE_OBJECT DeviceObject = NULL;


    RtlInitUnicodeString(&DeviceName, L"\\Device\\test");
    Status = IoCreateDevice(DriverObject, 0, &DeviceName,
        FILE_DEVICE_UNKNOWN, 0, FALSE,
        &DeviceObject);
    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("IoCreateDevice fail.\n");
        return STATUS_UNSUCCESSFUL;
    }

	return TestInvisibleNtQuerySystemInformationInlineHook();
	//return TestInvisibleNtCreateFileInlineHook();
}
//-----------------------------------------------------------------------------//