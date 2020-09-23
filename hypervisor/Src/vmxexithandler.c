//  [5/5/2015 uty]
#include <ntddk.h>
#include "vmx.h"
#include "amd64/vmx-asm.h"
#include "amd64/common-asm.h"
#include "vmxexithandler.h"
#include "ept.h"
#include "exceptionnmi.h"
#include "vmcall.h"
//-----------------------------------------------------------------------------//
VOID
ResumeToNextInstruction (
	VOID
	)
{
	PVOID pResumeRIP = NULL;
	PVOID pCurrentRIP = NULL;
	ULONG ulExitInstructionLength = 0;

	pCurrentRIP = (PVOID)VmxRead(GUEST_RIP);
	ulExitInstructionLength = (ULONG)VmxRead(VM_EXIT_INSTRUCTION_LEN);

	pResumeRIP = (PCHAR)pCurrentRIP + ulExitInstructionLength;

	VmxWrite(GUEST_RIP, (ULONG64)pResumeRIP);
}
//-----------------------------------------------------------------------------//
VOID
HandleCPUID (
	__inout PGUEST_REGS GuestRegs
	)
{
	int cpuInfo[4] = {0};

	__cpuid(&cpuInfo, (int)GuestRegs->rax);

	GuestRegs->rax = (ULONG64)cpuInfo[0];
	GuestRegs->rbx = (ULONG64)cpuInfo[1];
	GuestRegs->rcx = (ULONG64)cpuInfo[2];
	GuestRegs->rdx = (ULONG64)cpuInfo[3];
}
//-----------------------------------------------------------------------------//
VOID
HandleCR (
	__inout PGUEST_REGS GuestRegs
	)
{
	ULONG movcrControlRegister = 0;
	ULONG movcrAccessType = 0;
	ULONG movcrOperandType = 0;
	ULONG movcrGeneralPurposeRegister = 0;

	ULONG64 ExitQualification = 0;
	ULONG64 GuestCR0 = 0;
	ULONG64 GuestCR3 = 0;
	ULONG64 GuestCR4 = 0;

	ULONG64 x = 0;

	ExitQualification = VmxRead(EXIT_QUALIFICATION);
	GuestCR0 = VmxRead(GUEST_CR0);
	GuestCR3 = VmxRead(GUEST_CR3);
	GuestCR4 = VmxRead(GUEST_CR4);

	movcrControlRegister = (ULONG)(ExitQualification & 0x0000000F);
	movcrAccessType = (ULONG)((ExitQualification & 0x00000030) >> 4);
	movcrOperandType = (ULONG)((ExitQualification & 0x00000040) >> 6);
	movcrGeneralPurposeRegister = (ULONG)((ExitQualification & 0x00000F00) >> 8);


	/* Process the event (only for MOV CRx, REG instructions) */
	if (movcrOperandType == 0 && (movcrControlRegister == 0 || movcrControlRegister == 3 || movcrControlRegister == 4)) 
	{
		if (movcrAccessType == 0) 
		{
			/* CRx <-- reg32 */

			if (movcrControlRegister == 0) 
				x = GUEST_CR0;
			else if (movcrControlRegister == 3)
				x = GUEST_CR3;
			else
				x = GUEST_CR4;	  

			switch(movcrGeneralPurposeRegister) 
			{
			case 0:  VmxWrite(x, GuestRegs->rax); break;
			case 1:  VmxWrite(x, GuestRegs->rcx); break;
			case 2:  VmxWrite(x, GuestRegs->rdx); break;
			case 3:  VmxWrite(x, GuestRegs->rbx); break;
			case 4:  VmxWrite(x, GuestRegs->rsp); break;
			case 5:  VmxWrite(x, GuestRegs->rbp); break;
			case 6:  VmxWrite(x, GuestRegs->rsi); break;
			case 7:  VmxWrite(x, GuestRegs->rdi); break;
			default: break;
			}
		} 
		else if (movcrAccessType == 1) 
		{
			/* reg32 <-- CRx */

			if (movcrControlRegister == 0)
				x = GuestCR0;
			else if (movcrControlRegister == 3)
				x = GuestCR3;
			else
				x = GuestCR4;

			switch(movcrGeneralPurposeRegister) 
			{
			case 0:  GuestRegs->rax = x; break;
			case 1:  GuestRegs->rcx = x; break;
			case 2:  GuestRegs->rdx = x; break;
			case 3:  GuestRegs->rbx = x; break;
			case 4:  GuestRegs->rsp = x; break;
			case 5:  GuestRegs->rbp = x; break;
			case 6:  GuestRegs->rsi = x; break;
			case 7:  GuestRegs->rdi = x; break;
			default: break;
			}
		}
	}
}
//-----------------------------------------------------------------------------//
VOID doVmxExitHandler (PGUEST_REGS GuestRegs)
{
	ULONG ulExitReason = 0;


	ulExitReason = (ULONG)VmxRead(VM_EXIT_REASON);

	switch (ulExitReason)
	{
		//
		// 25.1.2  Instructions That Cause VM Exits Unconditionally
		// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
		// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, 
		// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		//

	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD: 
	case EXIT_REASON_VMPTRST: 
	case EXIT_REASON_VMREAD:  
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_VMLAUNCH:
		{
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_EXCEPTION_NMI:
		{
			HandleExceptionNmi();
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_CPUID:
		{
			HandleCPUID(GuestRegs);
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_INVD:
		{
			_INVD();
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_VMCALL:
		{
			HandleVMCALL(GuestRegs);
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_CR_ACCESS:
		{
			//
			// The first processors to support the virtual-machine extensions 
			// supported only the 1-setting of this control.
			//

			HandleCR(GuestRegs);
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_EPT_VIOLATION:
		{
			HandleEptViolation();
			break;
		}

	default:
		{
			DbgPrint("VM_EXIT_REASION %d\n", ulExitReason);
		}
		break;
	}
}
//-----------------------------------------------------------------------------//