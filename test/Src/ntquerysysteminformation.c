//  [7/19/2015 uty]
#include <ntddk.h>
#include "amd64/vmx-asm.h"
//-----------------------------------------------------------------------------//
VOID
DisableWriteProtect (
	VOID
	);

VOID
EnableWriteProtect (
	VOID
	);
//-----------------------------------------------------------------------------//
//
// System Information Classes.
//

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef unsigned char       BYTE;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
//-----------------------------------------------------------------------------//

NTSTATUS
NtQuerySystemInformation (
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef
NTSTATUS
(NTAPI *PNTQUERYSYSTEMINFOMATION) (
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );
//-----------------------------------------------------------------------------//
VOID NtQuerySystemInformationTrampoline(VOID);
//-----------------------------------------------------------------------------//
PNTQUERYSYSTEMINFOMATION OriginalNtQuerySystemInformation = NULL;
//-----------------------------------------------------------------------------//
NTSTATUS
NtQuerySystemInformationHook (
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    )
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PSYSTEM_PROCESS_INFORMATION pPrevProcessInfo = NULL;
	PSYSTEM_PROCESS_INFORMATION pCurrProcessInfo = NULL;

	Status = OriginalNtQuerySystemInformation (SystemInformationClass,
		                                       SystemInformation,
											   SystemInformationLength,
											   ReturnLength);

	if (!NT_SUCCESS(Status))
	{
		goto Exit0;
	}

	if (SystemProcessInformation != SystemInformationClass)
	{
		goto Exit0;
	}


	pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

	do 
	{
		if ((HANDLE)4 == pCurrProcessInfo->UniqueProcessId)
		{

			if (NULL != pPrevProcessInfo)
			{
				if (pCurrProcessInfo->NextEntryOffset)
				{
					pPrevProcessInfo->NextEntryOffset += pCurrProcessInfo->NextEntryOffset;
				}
				else
				{
					pPrevProcessInfo->NextEntryOffset = 0;
				}
			}
			else
			{
				if (pCurrProcessInfo->NextEntryOffset)
				{
					(PCHAR)SystemInformation += pCurrProcessInfo->NextEntryOffset;
				}
				else
				{
					SystemInformation = NULL;
				}
			}
		}

		
		pPrevProcessInfo = pCurrProcessInfo;

		pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)pCurrProcessInfo + pCurrProcessInfo->NextEntryOffset);

	} while (0 !=pCurrProcessInfo->NextEntryOffset);

Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
//
// nt!NtQuerySystemInformation:
// fffff800`02beb8fc fff3            push    rbx
// fffff800`02beb8fe 4883ec30        sub     rsp,30h
// fffff800`02beb902 83f953          cmp     ecx,53h
// fffff800`02beb905 458bd8          mov     r11d,r8d
// fffff800`02beb908 488bda          mov     rbx,rdx
// fffff800`02beb90b 448bd1          mov     r10d,ecx
// fffff800`02beb90e 7f61            jg      nt!NtQuerySystemInformation+0x75 (fffff800`02beb971)
// fffff800`02beb910 743d            je      nt!NtQuerySystemInformation+0x53 (fffff800`02beb94f)
//
NTSTATUS
InlineHookNtQuerySystemInformation (
	__in PVOID Function,
	__in PVOID FunctionHook
	)
{
	UCHAR TmpTrampoline[16] = {0};
	LARGE_INTEGER FuncAddress = {0};

	PUCHAR pTrampoline = NULL;

	//__debugbreak();

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


	FuncAddress.QuadPart = (LONGLONG)Function + 15;  // <--
	DisableWriteProtect();
	pTrampoline = (PUCHAR)NtQuerySystemInformationTrampoline + 15; // <--
	pTrampoline[0] = 0x68;
	*(PULONG)&pTrampoline[1] = FuncAddress.LowPart;
	*(PULONG)&pTrampoline[5] = 0x042444C7;
	*(PULONG)&pTrampoline[9] = FuncAddress.HighPart;
	pTrampoline[13] = 0xC3;
	EnableWriteProtect();

	OriginalNtQuerySystemInformation = (PNTQUERYSYSTEMINFOMATION)NtQuerySystemInformationTrampoline;


	DisableWriteProtect();
	memcpy(Function, TmpTrampoline, 15); // <--
	EnableWriteProtect();


	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
NTSTATUS
TestInvisibleNtQuerySystemInformationInlineHook (
	VOID
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uniNtQuerySystemInformation = {0};

 	PHYSICAL_ADDRESS OriginalPhysicalAddress = {0};
 	PVOID pShadowPage = NULL;
 	PHYSICAL_ADDRESS ShadowPhysicalPage = {0};

	PVOID NtQuerySystemInformationAddress = NULL;
    PVOID pReturn = NULL;

	RtlInitUnicodeString(&uniNtQuerySystemInformation, L"NtQuerySystemInformation");
	NtQuerySystemInformationAddress = (PVOID)MmGetSystemRoutineAddress(&uniNtQuerySystemInformation);
	if( NULL == NtQuerySystemInformationAddress )
	{
		Status = STATUS_UNSUCCESSFUL;
		goto Exit0;
	}

    pReturn = MmLockPagableCodeSection((PVOID)NtQuerySystemInformationAddress);
    if (NULL == pReturn)
    {
        DbgPrint("MmLocakPagableCodeSection fail.\n");
        Status = STATUS_UNSUCCESSFUL;
        goto Exit0;
    }

	OriginalPhysicalAddress = MmGetPhysicalAddress(NtQuerySystemInformationAddress);
	pShadowPage = MmAllocateNonCachedMemory(PAGE_SIZE);
	memcpy(pShadowPage, PAGE_ALIGN(NtQuerySystemInformationAddress), PAGE_SIZE);
	ShadowPhysicalPage = MmGetPhysicalAddress(pShadowPage);

	InlineHookNtQuerySystemInformation(NtQuerySystemInformationAddress, NtQuerySystemInformationHook);

	// init
	VmxVmCall2(0x28, OriginalPhysicalAddress.QuadPart, ShadowPhysicalPage.QuadPart);

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//