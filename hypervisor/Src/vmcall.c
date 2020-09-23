//  [5/15/2015 uty]
#include <ntddk.h>
#include "ept.h"
#include "vmxexithandler.h"
#include "common.h"
//-----------------------------------------------------------------------------//
VOID
HandleVMCALL (
	__inout PGUEST_REGS GuestRegs
	)
{
	PVMM_INIT_STATE pCurrentVMMInitState = NULL;
	pCurrentVMMInitState = &g_VMMInitState[KeGetCurrentProcessorNumber()];

	if (0x25 == GuestRegs->rax)
	{
		DbgPrint("in HandleVMCALL 0x25\n");
		SwitchToEPTOriginal(pCurrentVMMInitState);
	}
	else if (0x26 == GuestRegs->rax)
	{
		DbgPrint("in HandleVMCALL 0x26\n");
		SwitchToEPTShadow(pCurrentVMMInitState);
	}
	else if (0x27 == GuestRegs->rax)
	{
		PVOID pNewPage = NULL;
		PHYSICAL_ADDRESS PhysicalNewPage = {0};

		DbgPrint("in HandleVMCALL 0x27, arg0 0x%x\n", GuestRegs->rbx);
		pNewPage = MmAllocateNonCachedMemory(4096);
		if (NULL == pNewPage)
		{
			return;
		}
		PhysicalNewPage = MmGetPhysicalAddress(pNewPage);
		DbgPrint("New Physical Page 0x%x\n", PhysicalNewPage);
		DbgPrint("Map Guest Physical Page 0x%x to Host Physical Page 0x%x\n", GuestRegs->rbx, PhysicalNewPage.QuadPart);

		EptMapPage(&g_ept_shadow, FALSE, GuestRegs->rbx, PhysicalNewPage.QuadPart, EPTE_READ | EPTE_WRITE | EPTE_EXECUTE, CACHE_TYPE_WB, FALSE, &g_ShadowEptSpinLock);
	}
	else if (0x28 == GuestRegs->rax)
	{
		DbgPrint("VMCALL 0x28, RBX 0x%x, RCX 0x%x\n", GuestRegs->rbx, GuestRegs->rcx);
		//
		// EBX is Guest Physical Page, ECX is the Host Physical Page should mapping with EBX
		//
		g_TmpShadowHookAddress = GuestRegs->rbx;
		DbgPrint("g_TmpShadowHookAddress 0x%x\n", g_TmpShadowHookAddress);

		EptSetPageAccess(&g_ept, FALSE, (ULONG64)PAGE_ALIGN(GuestRegs->rbx), EPTE_EXECUTE, &g_EptSpinLock);
		EptMapPage(&g_ept_shadow, FALSE, GuestRegs->rbx, GuestRegs->rcx, EPTE_WRITE | EPTE_READ, CACHE_TYPE_WB, FALSE, &g_ShadowEptSpinLock);
	}
}
//-----------------------------------------------------------------------------//