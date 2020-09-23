// [5/15/2015 uty]
#include <ntddk.h>
//-----------------------------------------------------------------------------//
/* Set a single bit of a DWORD argument */
VOID CmSetBit(ULONG * dword, ULONG bit)
{
	ULONG mask = ( 1 << bit );
	*dword = *dword | mask;
}
//-----------------------------------------------------------------------------//
/* Clear a single bit of a DWORD argument */
VOID CmClearBit32(ULONG* dword, ULONG bit)
{
	ULONG mask = 0xFFFFFFFF;
	ULONG sub = ( 1 << bit );
	mask = mask - sub;
	*dword = *dword & mask;
}
//-----------------------------------------------------------------------------//
/* Clear a single bit of a WORD argument */
VOID CmClearBit16(USHORT* word, ULONG bit)
{
	USHORT mask = 0xFFFF;
	USHORT sub = (USHORT) ( 1 << bit );
	mask = mask - sub;
	*word = *word & mask;
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