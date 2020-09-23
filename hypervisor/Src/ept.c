//  [5/7/2015 uty]
#include <ntddk.h>
#include "vmx.h"
#include "msr.h"
#include "ept.h"
#include "amd64/vmx-asm.h"
#include "reghelper.h"
#include "cpu.h"
//-----------------------------------------------------------------------------//
struct vt_ept g_ept = {0};
struct vt_ept g_ept_shadow = {0};
//-----------------------------------------------------------------------------//
KSPIN_LOCK g_EptSpinLock;
KSPIN_LOCK g_ShadowEptSpinLock;
//-----------------------------------------------------------------------------//
#define  E820_BUFFER_SIZE     10240

CHAR g_PhysicalMemoryBuffer[E820_BUFFER_SIZE] = {0};

// in bytes
ULONG64 g_TotalPhysicalMemory = 0;
ULONG g_EptNumberOfPages = 0;
//-----------------------------------------------------------------------------//
//
// Shadow hook related
//
ULONG64 g_TmpShadowHookAddress = 0;
//-----------------------------------------------------------------------------//
NTSTATUS
GetE820FromRegistry (
	__out PULONG64 TotalPhysicalMemory
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG ulType = 0;
	ULONG ulReturnLength = 0;

	PCM_RESOURCE_LIST pCmResourceList = NULL;
	ULONG i  = 0;


	*TotalPhysicalMemory = 0;

	//
	// Physical Memory
	//

	Status = NIAPGetRegValue(L"\\Registry\\machine\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
		L".Translated",
		g_PhysicalMemoryBuffer, E820_BUFFER_SIZE, &ulType, &ulReturnLength
		);
	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("NIAPGetRegValue fail 0x%x\n", Status);
		goto Exit0;
	}

	pCmResourceList = (PCM_RESOURCE_LIST)g_PhysicalMemoryBuffer;

	DbgPrint("Physical Memory: Count %d\n", pCmResourceList->Count);
	for (i = 0; i < pCmResourceList->List[0].PartialResourceList.Count; i++)
	{
		PCM_PARTIAL_RESOURCE_DESCRIPTOR  pCmPartialResourceDescriptor = NULL;
		PHYSICAL_ADDRESS Start = {0};
		ULONG64 Length = 0;

		pCmPartialResourceDescriptor = &pCmResourceList->List[0].PartialResourceList.PartialDescriptors[i];
		if (CmResourceTypeMemory == pCmPartialResourceDescriptor->Type)
		{
			Start = pCmPartialResourceDescriptor->u.Memory.Start;
			Length = pCmPartialResourceDescriptor->u.Memory.Length;
		}
		else if (CmResourceTypeMemoryLarge == pCmPartialResourceDescriptor->Type)
		{
			switch (pCmPartialResourceDescriptor->Flags)
			{
			case CM_RESOURCE_MEMORY_LARGE_40:
				{
					Start = pCmPartialResourceDescriptor->u.Memory40.Start;
					Length = pCmPartialResourceDescriptor->u.Memory40.Length40;
					Length = Length << 8;
					break;
				}

			case CM_RESOURCE_MEMORY_LARGE_48:
				{
					Start = pCmPartialResourceDescriptor->u.Memory48.Start;
					Length = pCmPartialResourceDescriptor->u.Memory48.Length48;
					Length = Length << 16;
					break;
				}
			case CM_RESOURCE_MEMORY_LARGE_64:
				{
					Start = pCmPartialResourceDescriptor->u.Memory64.Start;
					Length = pCmPartialResourceDescriptor->u.Memory64.Length64;
					Length = Length << 32;
					break;
				}
			default:
				{
					ASSERT(FALSE);
					KeBugCheck(0xCD3);
				}
			}
		}
		else
		{
			ASSERT(FALSE);
			KeBugCheck(0xCD3);
		}

		*TotalPhysicalMemory = *TotalPhysicalMemory + Length;
		DbgPrint("Type 0x%x, Start 0x%p, Length 0x%x\n", pCmPartialResourceDescriptor->Type, Start, Length);
	}
	DbgPrint("Total Physical Memory 0x%p bytes.\n", *TotalPhysicalMemory);

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
PVOID
FindMdl (
	__in struct vt_ept* Ept,
	__in ULONG64 PhysicalAddress
	)
{
	int i = 0;

	for (i = 0; i < Ept->cnt; i++)
	{
		if (PhysicalAddress == Ept->pages_phys[i])
		{
			return Ept->mdls[i];
		}
	}

	// should not be here
	// panic

	KeBugCheck (0xCC);
	
	return NULL;
}
//-----------------------------------------------------------------------------//
// pml4 pdp pd pt
VOID
EptMapPage (
	__in struct vt_ept* Ept,
	__in BOOLEAN Write,
	__in ULONG64 GuestPhys,
	__in ULONG64 HostPhys, 
	__in ULONG Access,
	__in ULONG CacheType,
	__in BOOLEAN IgnoreHostPhys,  // only change access or CacheType
	__in_opt PKSPIN_LOCK SpinLock
	)
{
	PEPT_PML4E pPml4eTable = NULL;
	PEPT_PDPTE pPdpteTable = NULL;
	PEPT_PDE pPdeTable = NULL;
	PEPT_PTE pPteTable = NULL;

	EPT_PML4E pml4e = {0};
	EPT_PDPTE pdpte = {0};
	EPT_PDE pde = {0};

	EPT_PHYSICAL_ADDRESS EptPhys = {0};
	ULONG64 PhysicalAddress = 0;

	PMDL pPdpteMdl = NULL;
	PMDL pPdeMdl = NULL;
	PMDL pPteMdl = NULL;

	KIRQL OldIrql;

	if (NULL != SpinLock)
	{
		KeAcquireSpinLock(SpinLock, &OldIrql);
	}

	EptPhys.QuardPart = GuestPhys;

	pPml4eTable = (PEPT_PML4E)Ept->pml4;

	pml4e = pPml4eTable[EptPhys.Pml4eIndex];
	if (0 == pml4e.Read)
	{
		pPml4eTable[EptPhys.Pml4eIndex].PageFrameNumber = Ept->pages_phys[Ept->cnt] >> PAGE_SHIFT;
		pPml4eTable[EptPhys.Pml4eIndex].Read = 1;
		pPml4eTable[EptPhys.Pml4eIndex].Write = 1;
		pPml4eTable[EptPhys.Pml4eIndex].Execute = 1;
		Ept->cnt++;

		pml4e = pPml4eTable[EptPhys.Pml4eIndex];
	}


	PhysicalAddress = pml4e.PageFrameNumber << 12;
	pPdpteMdl = FindMdl(Ept, PhysicalAddress);
	pPdpteTable = MmGetSystemAddressForMdlSafe(pPdpteMdl, HighPagePriority);

	pdpte = pPdpteTable[EptPhys.PdpteIndex];
	if (0 == pdpte.Read)
	{
		pPdpteTable[EptPhys.PdpteIndex].PageFrameNumber = Ept->pages_phys[Ept->cnt] >> PAGE_SHIFT;
		pPdpteTable[EptPhys.PdpteIndex].Read = 1;
		pPdpteTable[EptPhys.PdpteIndex].Write = 1;
		pPdpteTable[EptPhys.PdpteIndex].Execute = 1;
		Ept->cnt++;

		pdpte = pPdpteTable[EptPhys.PdpteIndex];
	}



	PhysicalAddress = pdpte.PageFrameNumber << 12;
	pPdeMdl = FindMdl(Ept, PhysicalAddress);
	pPdeTable = MmGetSystemAddressForMdlSafe(pPdeMdl, HighPagePriority);

	pde = pPdeTable[EptPhys.PdeIndex];
	if (0 == pde.Read)
	{
		pPdeTable[EptPhys.PdeIndex].PageFrameNumber = Ept->pages_phys[Ept->cnt] >> PAGE_SHIFT;
		pPdeTable[EptPhys.PdeIndex].Read = 1;
		pPdeTable[EptPhys.PdeIndex].Write = 1;
		pPdeTable[EptPhys.PdeIndex].Execute = 1;
		Ept->cnt++;

		pde = pPdeTable[EptPhys.PdeIndex];
	}


	PhysicalAddress = pde.PageFrameNumber << 12;
	pPteMdl = FindMdl(Ept, PhysicalAddress);
	pPteTable = MmGetSystemAddressForMdlSafe(pPteMdl, HighPagePriority);


	if (Access & EPTE_READ)
	{
		pPteTable[EptPhys.PteIndex].Read = 1;
	}
	else
	{
		pPteTable[EptPhys.PteIndex].Read = 0;
	}

	if (Access & EPTE_WRITE)
	{
		pPteTable[EptPhys.PteIndex].Write = 1;
	}
	else
	{
		pPteTable[EptPhys.PteIndex].Write = 0;
	}

	if (Access & EPTE_EXECUTE)
	{
		pPteTable[EptPhys.PteIndex].Execute = 1;
	}
	else
	{
		pPteTable[EptPhys.PteIndex].Execute = 0;
	}
	
	if (!IgnoreHostPhys)
	{
		pPteTable[EptPhys.PteIndex].PageFrameNumber = HostPhys >> PAGE_SHIFT;
	}
	
	pPteTable[EptPhys.PteIndex].MemoryType = CacheType;
	pPteTable[EptPhys.PteIndex].IgnorePAT = 1;



	MmUnmapLockedPages(pPdpteTable, pPdpteMdl);
	MmUnmapLockedPages(pPdeTable, pPdeMdl);
	MmUnmapLockedPages(pPteTable, pPteMdl);

	if (NULL != SpinLock)
	{
		KeReleaseSpinLock(SpinLock, OldIrql);
	}	
}
//-----------------------------------------------------------------------------//
VOID
EptSetPageAccess (
	__in struct vt_ept* Ept,
	__in BOOLEAN Write,
	__in ULONG64 GuestPhys,
	__in ULONG Access,
	__in_opt PKSPIN_LOCK SpinLock
	)
{
	EptMapPage(Ept, Write, GuestPhys, 0, Access, CACHE_TYPE_WB,  TRUE, SpinLock);
}
//-----------------------------------------------------------------------------//
VOID
EptMapRage (
	__in PHYSICAL_ADDRESS Start,
	__in LONG64 Length,
	__in ULONG CacheType
	)
{
	LONG64 i = 0;

	DbgPrint("EptMapRage Start: 0x%p, Length: 0x%p\n", Start.QuadPart, Length);

	for (i = Start.QuadPart; i <= Start.QuadPart + Length; i += 0x1000)
	{
		EptMapPage(&g_ept, FALSE, i, i, EPTE_READ | EPTE_WRITE | EPTE_EXECUTE, CacheType, FALSE, NULL);
		EptMapPage(&g_ept_shadow, FALSE, i, i, EPTE_READ | EPTE_WRITE | EPTE_EXECUTE, CacheType, FALSE, NULL);
	}
}
//-----------------------------------------------------------------------------//
NTSTATUS Ept11mapping (VOID)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PCM_RESOURCE_LIST pCmResourceList = NULL;
	ULONG i = 0;


	//
	// Physical Memory
	//

	pCmResourceList = (PCM_RESOURCE_LIST)g_PhysicalMemoryBuffer;

	for (i = 0; i < pCmResourceList->List[0].PartialResourceList.Count; i++)
	{
		PCM_PARTIAL_RESOURCE_DESCRIPTOR  pCmPartialResourceDescriptor = NULL;
		PHYSICAL_ADDRESS Start = {0};
		ULONG64 Length = 0;

		pCmPartialResourceDescriptor = &pCmResourceList->List[0].PartialResourceList.PartialDescriptors[i];
		if (CmResourceTypeMemory == pCmPartialResourceDescriptor->Type)
		{
			Start = pCmPartialResourceDescriptor->u.Memory.Start;
			Length = pCmPartialResourceDescriptor->u.Memory.Length;
		}
		else if (CmResourceTypeMemoryLarge == pCmPartialResourceDescriptor->Type)
		{
			switch (pCmPartialResourceDescriptor->Flags)
			{
			case CM_RESOURCE_MEMORY_LARGE_40:
				{
					Start = pCmPartialResourceDescriptor->u.Memory40.Start;
					Length = pCmPartialResourceDescriptor->u.Memory40.Length40;
					Length = Length << 8;
					break;
				}
				
			case CM_RESOURCE_MEMORY_LARGE_48:
				{
					Start = pCmPartialResourceDescriptor->u.Memory48.Start;
					Length = pCmPartialResourceDescriptor->u.Memory48.Length48;
					Length = Length << 16;
					break;
				}
			case CM_RESOURCE_MEMORY_LARGE_64:
				{
					Start = pCmPartialResourceDescriptor->u.Memory64.Start;
					Length = pCmPartialResourceDescriptor->u.Memory64.Length64;
					Length = Length << 32;
					break;
				}
			default:
				{
					ASSERT(FALSE);
					KeBugCheck(0xCD3);
				}
			}
		}
		else
		{
			ASSERT(FALSE);
			KeBugCheck(0xCD3);
		}

		EptMapRage(Start, Length, CACHE_TYPE_WB);
	}


	Status = STATUS_SUCCESS;
//Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
ULONG
CountForPages (
	__in ULONG64 TotalPhysicalMemory
	)
{
	ULONG64 Size1MB = 0;

	Size1MB = 1024 * 1024;

	//
	// Approximately 12GB physical memory, 8192 pages would be enough,
	// So every GB need 682 pages
	//

	if (TotalPhysicalMemory < (ULONG64)(1024 * Size1MB))
	{
		return 0x300;
	}

	return (ULONG)(0x300 * (TotalPhysicalMemory / (1024 * Size1MB)));
}
//-----------------------------------------------------------------------------//
NTSTATUS
InitEptTable (
	VOID
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG64 i = 0;

	PHYSICAL_ADDRESS PhysicalAddress = {0};
	PHYSICAL_ADDRESS LowAddress = {0};
	PHYSICAL_ADDRESS HighAddress = {0};
	PHYSICAL_ADDRESS SkipBytes = {0};
	PPFN_NUMBER pPfnNumber = NULL;

	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = 0xFFFFFFFFFFFFFFFF;
	SkipBytes.QuadPart = 0;

	g_EptNumberOfPages = CountForPages(g_TotalPhysicalMemory);
	DbgPrint("g_EptNumberOfPages %d\n", g_EptNumberOfPages);

	KeInitializeSpinLock(&g_EptSpinLock);
	KeInitializeSpinLock(&g_ShadowEptSpinLock);

	g_ept.pml4 = MmAllocateNonCachedMemory(4096);
	if (NULL == g_ept.pml4)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit0;
	}
	PhysicalAddress = MmGetPhysicalAddress(g_ept.pml4);
	g_ept.pml4_phys = PhysicalAddress.QuadPart;
	memset(g_ept.pml4, 0, 4096);

	g_ept_shadow.pml4 = MmAllocateNonCachedMemory(4096);
	PhysicalAddress = MmGetPhysicalAddress(g_ept_shadow.pml4);
	if (NULL == g_ept_shadow.pml4)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit0;
	}
	g_ept_shadow.pml4_phys = PhysicalAddress.QuadPart;
	memset(g_ept_shadow.pml4, 0, 4096);

	for (i = 0; i < g_EptNumberOfPages; i++)
	{
		g_ept.mdls[i] = MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, PAGE_SIZE, MmNonCached, 0);
		if (NULL == g_ept.mdls[i])
		{
			DbgPrint("MmAllocatePagesForMdlEx fail\n");
			goto Exit0;
		}
		pPfnNumber = MmGetMdlPfnArray(g_ept.mdls[i]);
		g_ept.pages_phys[i] = pPfnNumber[0] << PAGE_SHIFT;


		g_ept_shadow.mdls[i] = MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, PAGE_SIZE, MmNonCached, 0);
		if (NULL == g_ept_shadow.mdls[i])
		{
			DbgPrint("MmAllocatePagesForMdlEx fail\n");
			goto Exit0;
		}
		pPfnNumber = MmGetMdlPfnArray(g_ept_shadow.mdls[i]);
		g_ept_shadow.pages_phys[i] = pPfnNumber[0] << PAGE_SHIFT;

	}

	g_ept.cnt = 0;
	g_ept_shadow.cnt = 0;

	DbgPrint("Initialize ept table\n");

	Ept11mapping();

	DbgPrint("g_ept.cnt %d\n", g_ept.cnt);

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
NTSTATUS
EptInit (
	VOID
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS PhysicalAddress;
	ULONG ulContent = 0;


	ulContent = (ULONG)VmxRead(CPU_BASED_VM_EXEC_CONTROL);
	ulContent |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	VmxWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(ulContent, MSR_IA32_VMX_PROCBASED_CTLS));

	
	ulContent = (ULONG)VmxRead(SECONDARY_VM_EXEC_CONTROL);
	ulContent |= CPU_BASED_CTL2_ENABLE_EPT;
	VmxWrite(SECONDARY_VM_EXEC_CONTROL, VmxAdjustControls(ulContent, MSR_IA32_VMX_PROCBASED_CTLS2));


	PhysicalAddress.QuadPart = g_ept.pml4_phys;
	VmxWrite(EPT_POINTER, PhysicalAddress.LowPart | EPT_PAGEWALK_LENGTH_4 | EPT_POINTER_EPT_WB);
	VmxWrite(EPT_POINTER_HIGH, PhysicalAddress.HighPart);

	Status = STATUS_SUCCESS;
//Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
VOID
EptViolation (
	__in BOOLEAN Write,
	__in ULONG64 GuestPhys
	)
{
	EptMapPage(&g_ept, Write, GuestPhys, GuestPhys, EPTE_READ | EPTE_WRITE | EPTE_EXECUTE, CACHE_TYPE_UC, FALSE, &g_EptSpinLock);
	EptMapPage(&g_ept_shadow, Write, GuestPhys, GuestPhys, EPTE_READ | EPTE_WRITE | EPTE_EXECUTE, CACHE_TYPE_UC, FALSE, &g_EptSpinLock);
}
//-----------------------------------------------------------------------------//
void
Convert32to64 (ULONG src_l, ULONG src_h, ULONG64 *dest)
{
	*dest = src_l | (ULONG64)src_h << 32;
}
//-----------------------------------------------------------------------------//
NTSTATUS
SwitchToEPTOriginal (
	__inout PVMM_INIT_STATE VMMInitState
	)
{
	PHYSICAL_ADDRESS tmp;

	tmp.QuadPart = g_ept.pml4_phys;

	VmxWrite(EPT_POINTER, tmp.LowPart | EPT_PAGEWALK_LENGTH_4 | EPT_POINTER_EPT_WB);
	DbgPrint("Ept pointer 0x%x\n", tmp.LowPart);
	VmxWrite(EPT_POINTER_HIGH, tmp.HighPart);

	__wbinvd();

	VMMInitState->ShadowEpt = FALSE;

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
NTSTATUS
SwitchToEPTShadow (
	__inout PVMM_INIT_STATE VMMInitState
	)
{
	PHYSICAL_ADDRESS tmp;

	tmp.QuadPart = g_ept_shadow.pml4_phys;

	VmxWrite(EPT_POINTER, tmp.LowPart | EPT_PAGEWALK_LENGTH_4 | EPT_POINTER_EPT_WB);
	DbgPrint("Ept shadow pointer 0x%x\n", tmp.LowPart);
	VmxWrite(EPT_POINTER_HIGH, tmp.HighPart);

	__wbinvd();

	VMMInitState->ShadowEpt = TRUE;

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
VOID
HandleEptViolation (
	VOID
	)
{
	ULONG eqe;
	ULONG ulGuestPhysicalAddressLow = 0;
	ULONG ulGuestPhysicalAddressHigh = 0;
	ULONG64 ul64GuestPhysicalAddress = 0;

	PVMM_INIT_STATE pCurrentVMMInitState = NULL;
	pCurrentVMMInitState = &g_VMMInitState[KeGetCurrentProcessorNumber()];

	eqe = (ULONG)VmxRead(EXIT_QUALIFICATION);
	ulGuestPhysicalAddressLow = (ULONG)VmxRead(GUEST_PHYSICAL_ADDRESS);
	ulGuestPhysicalAddressHigh = (ULONG)VmxRead(GUEST_PHYSICAL_ADDRESS_HIGH);

	Convert32to64(ulGuestPhysicalAddressLow, ulGuestPhysicalAddressHigh, &ul64GuestPhysicalAddress);
	
	if (PAGE_ALIGN(ul64GuestPhysicalAddress) == PAGE_ALIGN(g_TmpShadowHookAddress))
	{
		DbgPrint("ul64GuestPhysicalAddress 0x%p, g_TmpShadowHookAddress 0x%p\n", ul64GuestPhysicalAddress, g_TmpShadowHookAddress);

		if (pCurrentVMMInitState->ShadowEpt)
		{
			SwitchToEPTOriginal(pCurrentVMMInitState);
		}
		else
		{
			SwitchToEPTShadow(pCurrentVMMInitState);
		}
		
		// 
		return;
	}
	

#define EPT_VIOLATION_EXIT_QUAL_WRITE_BIT 0x2

	EptViolation((BOOLEAN)(eqe & EPT_VIOLATION_EXIT_QUAL_WRITE_BIT), ul64GuestPhysicalAddress);
}
//-----------------------------------------------------------------------------//