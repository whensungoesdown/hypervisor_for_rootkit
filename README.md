# hypervisor_for_rootkit
                              ==Phrack Inc.==

                Volume 0x0f, Issue 0x45, Phile #0x0f of 0x10

|=-----------------------------------------------------------------------=|
|=----------------------=[ How to hide a hook  ]=------------------------=|
|=-------------------=[ A hypervisor for rootkits ]=---------------------=|
|=-----------------------------------------------------------------------=|
|=------------------=[ uty <whensungoes@gmail.com> ]=--------------------=|
|=----------------=[ saman <saman.zonouz@rutgers.edu> ]=-----------------=|
|=-----------------------------------------------------------------------=|

--[ Table of contents

1. Introduction
2. Background
    2.1 Intel VMX
    2.2 EPT
3. How to make a hook invisible
    3.1 Hypervisor setup
    3.2 Memory 1:1 mapping
    3.3 Two mappings for one page
    3.4 User mode pages
    3.5 Execute and read at the same page
    3.6 Wakeup from sleep
4. Demo
    4.1 A keylogger
    4.2 Bypass PatchGuard
5. Other Applications
6. Greetings
7. References
8. Appendix: Code


--[ 1. Introduction

Writing rootkits is becoming more and more difficult. Because there are
many tools waiting out there to detect misbehaviors. Adversaries put so
much effort trying to make rootkits as stealthy as possible but there needs
to be only one hook that defense solutions could monitor and detect the
misbehavior.

Our goal is to make that hook invisible so that the detection tools cannot
see it even using dynamic debuggers to check that range of code, while to
rootkit does exist and functions correctly. There are other approaches,
like Shadow workers which are based on TLB splitting. Researchers would
initially wonder when the corresponding Intel cpu architecture was going to
change, and it recently did [6][7][8]. Also TLB splitting need to hook page
fault handler, that is a pain in practice. We present a way to do it only
by virtualization technology, typically use Intel VT with EPT (Extended
Page Tables) [5]. The same principle could also apply to other CPUs like
ARM, as long as they support hardware virtualization, physical memory
translation and can distinguish different types of access to a page. For
instance, in x86 paging mode, a read operation is not denied as long as the
page is marked as executable.

We provide a 64bits run-time loaded hypervisor, it is loaded as a Windows
driver. And with EPT, underneath the guest operating system our solution
maps all the physical memory, using a 1:1 mapping. We leverage it to map a
guest physical page to two different host physical pages. One is set with
READ and WRITE and the other one with EXECUTE only. Normally it will be set
as EXECUTE, which CPU can run on that page, but when someone want to check
the integrity of it, for example to see if there is any hooks. The READ
operation by the checker will trigger an EPT violation, the hypervisor will
get noticed and change the underlying mapping of that page to another host
physical page that contains whatever stuff you want the checker to see,
e.g., the original code without any of your inline hooks. On the other end,
when the CPU tries to execute code on this page again, it also will cause a
EPT violation, we just change it back and let the CPU continue on it.

It is noteworthy that there are many kinds of hooks. In this paper, we
focus on the inline hook for the modifications on the code section. Other
types like SSDT hook or kernel object manipulation are outside the scope of
this article.

The platform we are woking on are Windows 7 x64 and Windows 8.1 x64. Sure,
with the invisible inline hooks, you can ignore Windows PatchGuard!


--[ 2. Background

--[ 2.1 Intel VMX

VMX is short for Intel virtual-machine extensions, it supports
virtualization of CPUs in hardware. VMX supports two more lower operation
mode called root and non-root mode. Usually processor has running
mode known as ring-0 to ring-3, where ring-0 is kernel mode, ring-3 is user
mode, ring 1 and ring 2 are rarely used. When CPU enables virtualization,
it could be seen as running in the non-root mode. The root mode can be
considered as a lower and more privileged level, it controls the whole CPU.
And the guest operating system will run in non-root mode. Root mode runs
VMM (Virtual Machine Monitor) is often called ring -1.

VMXON and VMXOFF are instructions to enter and exit VMX mode. There is an
important data structure called VMCS (Virtual-Machine Control Structure),
which is 4 KB large in size. It controls the state switch between VMX root
mode and VMX non-root mode. From root mode to non-root mode called VM Exit.
From non-root mode to root mode called VM Enter.

Every logical CPU (each core in a real physical CPU is called a logical
CPU) has a processor state called VMCS pointer. It contains the physical
address of the VMCS. There could be many VMCSs, the one stored in VMCS
pointer is considered as the current one. Every VMCS can represent a
virtual processor for the virtual machine, inside virtual machine, that is
a logical CPU seen by operating system. Although hypervisor knows the
physical address of a VMCS, but hypervisor cannot modify it directly,
hypervisor can only reads and writes VMCS using VMREAD, VMWRITE
instructions. Hypervisor use VMPTRLD to set a VMCS both as active and
current. And use VMCLEAR to mark the VMCS as inactive.

A VMCS contains many fields related every aspect of a virtual machine.
There are six fields: Guest-state area, Host-state area, VM-execution
control fields, VM-exit control fields, VM-entry control fields and VM-exit
information fields. And each field also contains many more control fields
with a lot of settings. Once the CPU enters into a virtual machine by
execute VMLAUNCH which associates with a VMCS, this virtual machine is
fully control by the settings in the VMCS. Hypervisor can set during what
circumstances the virtual machine should exit. And then the hypervisor can
handle this situation, for example emulate a hardware device or change the
virtual machine's behavior.

In our case, we do not actually emulate any hardware device, we put the
current system into a virtual machine environment and our code run as the
hypervisor.


--[ 2.2 EPT

The extended page-table mechanism (EPT) is used to support physical memory
virtualization. When inside a virtual machine, a virtual memory access will
be translated into a physical memory access by virtual CPU. Since the
virtual machine is emulated, the physical memory inside the virtual machine
is also emulated. It is called guest physical memory, which cannot be
accessed directly by CPU. In earlier days, hypervisors had to maintain a
guest virtual memory to host physical memory mapping called "shadow page
table". It is hidden from guest operating system. Hypervisor needed to make
sure the guest operating system believes that there is no such thing. So
every operation by the guest operating system had to be intercepted and
handled by hypervisor to provide a `fake` result to look normal to the
guest operating system. This was tedious dynamically.

With EPT enabled virtual machine, hypervisor's responsibilities drop. The
guest CPU translates and accesses physical memory as it wishes. But the
guest physical memory is interpreted again by the hypervisor to translate
it to the real host physical memory.

From the name, EPT is a page table. It is quite similar to the page tables
in x86 architecture. Every guest physical address to host physical address
translation is performed by EPT. In comparison to x86 paging mechanism,
every VMCS has a EPT pointer, that is like CR3 in x86. It stores the root
of the table. And it uses 4 level page-walk, there are PML4E, PDPTE, PDE
and PTE. Page fault in EPT's term is called EPT violation, that could be
CPU accessing the guest physical memory which is not currently mapped or
there is an access permission violation.


--[ 3. How to make a hook invisible

--[ 3.1 Hypervisor setup

First we need to setup a hypervisor once Windows operating system
boots up. It could be cumbersome just to fill VMXON region and VMCS that
are the most important data structures in VMX. There have been open-source
projects that have accomplished similar goals, e.g., Xen[2], HyperDbg[3],
BluePill[4] and Intel. I learn from the giants. Code is available at
EnalbeVMX() and VmxSetupVMCS() which both are called by doStartVMX().
doStartVMX() need to be called from every CPU core of the system. This is
because we need to put every physical cpu core into VMX mode (interested
reader is referred to Intel manual "31.5 VMM SETUP & TEAR DOWN”[5]).

Once VMCS is set up properly and executes vmxlauch successfully, the
hypervisor starts running. We then get many vm exits that we need to
handle. The handling function is doVmxExitHandler() that is located in
vmxexithandler.c. Some vm-exits happen even without any particular
settings in VMCS; for example, the control register operations.


--[ 3.2 Memory 1:1 mapping

Our hypervisor is loaded at run-time. The operating system and device
drivers already has been initialized. So the physical pages and especially
interface registers in devices which mapped to physical memory space
through MMIO (Memory mapped IO) are decided. At this point we can choose
mapping of the guest physical address space to host physical address space
directly using EPT. It's a 1:1 mapping. In other words, for example there
is physical address access at guest physical address 0x1C000, the
underneath hypervisor will direct translate it to host physical address
0x1c000.

  +-----------------------------+
  | #   # #        #  #         |         Guest Virtual Pages
  +--\-/---\--------\-|---------+
      X     \        \|
  +--/-\-----\--------|\--------+
  | #   #     #       # #       |         Guest Physical Pages
  +-|---|-----|-------|-|-------+
    |   |     |       | |                                   (Guest machine)
----|---|-----|-------|-|--------------------------------------------------
  +-|---|-----|-------|-|-------+                            (Hypervisor)
  | #   #     #       # #       |         Host Physical Memory
  +-----------------------------+

EPT tables entries also need to specify memory type. Because in physical
memory space, there are RAM, ROM, graphics memory and device registers,
they all exist in physical memory space. Memory types could be any of the
following:

  Uncacheable
  Write Through
  Write Combine
  Write Protected
  Write Back

The details of cache police (11.3 METHODS OF CACHING AVAILABLE [5]) is not
covered here.

Different kinds of memory should have different memory type. For example,
memory ranges of PCI devices should use "Uncacheable". RAM normally should
be "Write Back" and graphics memory could be "Write Combine" for better
performance. As I test it, you could just make all the physical memory
space as "Uncacheable", but it will be extremely slow because by doing that
you give up cache. On the other hand, you should not mark all the memory
types as "Write Back", because PCI devices ranges usually contains
registers on the devices, it is important for the register to get data
strictly in order.

To decide on the memory type, we could first check Memory Type Range
Registers (MTRR) and also check Page Attribute Table (PAT) which is
specified in page table entries. MTRR and PAT are both Intel CPU's
mechanisms to assign memory types to physical memory. MTRR are a set of MSR
registers to specify memory type for several ranges of memory, usually
eight ranges. PAT is supplementary to MTRR that it can provide page
granularity control.

For this prototype project, we just set "IgnorePAT" bit in EPT entries and
set whole RAM as "Write back" and all other memory as "Uncacheable".
Because from Intel manual it seems EPT entries only support this two memory
types. "A value of 0 indicates the Uncacheable type (UC), while a value of
6 indicates the write-back type (WB). Other values are reserved" [5].

So how do we know which range of memory is RAM? There is a data structure
called E820 table. It got its name because there is a BIOS function, int
0x15. With argument 0xE820 in eax register, raising interruption 0x15 will
get the memory map for your PC. But since this is a BIOS function and the
system already boot up, we cannot call it anymore. Fortunately on Windows
operating system, all the memory information is stored in registry. It is
"HKEY_LOCAL_MACHINE\HARDWARE\RESOURCEMAP\System Resources". We will not go
into details about the stored data structure [9], but that is how we get
the memory layout information in our implementations. This information is
available at GetE820FromRegistry().


--[ 3.3 Two mappings for one page

Suppose we want to hook function NtCreateFile for example, before doing
anything we should first find the physical page where the function is
within. Next we prepare another physical page which is totally copied from
the original one. This copy is to provide to the checker to evade any
integrity violation detection. In the following we will call these two
pages as the original page and the shadow page. The original page is the
one we will later install hooks on.

Now we are ready to install inline hook on the original page. After that,
we let the original page have the EXECUTE permission flag and the shadow
page has READ & WRITE bits, and we tell hypervisor all about it.

So the NtCreateFile with our inline hook will run normally as it has
EXECUTE bit. Let's assume there is someone trying to take a look at the
function. The read operation will violate the permission the page has. So
there will be an EPT violation raised to the hypervisor. Since we have the
control over the hypervisor, we change the page's mapping to the shadow one
with READ & WRITE bits. With the correct permission flags, the virtual
machine is happy to run again. Remember the content of the shadow page is
untouched by us hence no inline hook in it. Later the kernel will call
NtCreateFile and there will be another EPT violation, we change its mapping
back and everything is back to the original state. This ensures that the
integrity check is satisfied and our modification evades the detection.

In our implementation, we do not change EPT table entries all the time,
actually we have two identical but slightly different EPT tables. And the
original page and the shadow page are recorded separately in these two
tables. When EPT violation happens, we just simply switch between them.

The EPT related functions are implemented in ept.c. In HandleEptViolation()
handles the EPT violations:

if (PAGE_ALIGN(ul64GuestPhysicalAddress)
	== PAGE_ALIGN(g_TmpShadowHookAddress))
{
	if (pCurrentVMMInitState->ShadowEpt)
	{
		SwitchToEPTOriginal(pCurrentVMMInitState);
	}
	else
	{
		SwitchToEPTShadow(pCurrentVMMInitState);
	}

	return;
}

EptViolation((BOOLEAN)(eqe & EPT_VIOLATION_EXIT_QUAL_WRITE_BIT),
		ul64GuestPhysicalAddress);

So when ept violation happens, our solution first checks if faulting guest
physical page equals the page where it installed the hook on. If so, the
engine knows it is due to the access violation, and we just switch its
mapping by using the other EPT table. If not, it is an IO page that needs a
1:1 mapping.

As it can be inferred, we can only install hook on one page. However, one
can slightly extend it to handle multiple pages using Exit Qualification to
determine the cause of the EPT violation (see Intel manual "28.2.2  EPT
Translation Mechanism" [5]). The code that accomplishes that goal would be:

#define EPT_VIOLATION_EXIT_QUAL_READACCESS		0x1
#define EPT_VIOLATION_EXIT_QUAL_WRITEACCESS		0x2
#define EPT_VIOLATION_EXIT_QUAL_EXECUTEACCESS	0x4

#define EPT_VIOLATION_EXIT_QUAL_READABLE		0x8
#define EPT_VIOLATION_EXIT_QUAL_WRITABLE		0x10
#define EPT_VIOLATION_EXIT_QUAL_EXECUTABLE		0x20

if (eqe & (EPT_VIOLATION_EXIT_QUAL_READABLE |
           EPT_VIOLATION_EXIT_QUAL_WRITABLE |
	    EPT_VIOLATION_EXIT_QUAL_EXECUTABLE))
{
	if ((eqe & EPT_VIOLATION_EXIT_QUAL_READACCESS) ||
		(eqe & EPT_VIOLATION_EXIT_QUAL_WRITEACCESS))
	{
		// Due to read or write access violation
	}
	else if (eqe & EPT_VIOLATION_EXIT_QUAL_EXECUTEACCESS)
	{
		// Due to execute access violation
	}
}
else
{
	// No any access violation, do a 1:1 mapping
}



--[ 3.4 User mode pages

For user mode pages, because EPT is in charge of the physical page address
translation underneath. Once you make sure which physical page is backing
up the user mode page, the rest is almost the same as in kernel mode. But
user mode pages often be swapped out to disk. When it swaps back to memory,
it may ends up in a different physical page frame.

So we have to lock the page from being swapped out. It is important for
both kernel pages and user pages. How do we lock it? First thing to try
is MmProbeAndLockPages(), but you have to release the lock before a process
context switch. If you don't, what will happen is Windows mm will know and
give you a Bug Check 0x76: PROCESS_HAS_LOCKED_PAGES.

Since we already get into hypervisor, it is a little embarrassing to go
back and find out what is going on with mm. Luckily, there is a win 32 API
called VirtualLock(). From its name, we can tell it must be the one.
Although this may leave a clue that something is going on with this page
but it is just a common Win32 API, I guess many existing software modules
make use of it.


--[ 3.5 Execute and read at the same page

There could be one situation that one instruction may be executed and read
data at the same page. For example, the IAT jump table. That need READ and
EXECUTE permission at the same time.

One way to solve this problem is to give it all permissions for short
period of time, let this special instruction do whatever it wants and then
set it back. We set the READ and EXECUTE permissions and also set single
step flag for the guest virtual machine. So it will execute and stop at the
next instruction. We then handle this event and change the permissions
back and clear the single step flag. Sounds like a plan, but in reality
there will be some problems, virtual machine behaves strange with multiple
CPUs. I am still trying to figure it out. This truly could be a problem,
for which the solution would be emulating that instruction by hypervisor.


--[ 3.6 Wakeup from sleep

When CPU wakeup from S4 state(sleep), the CPU state is restored. But not
the VMX states. It means when wakeup from sleep, the CPU is not in VMX mode
anymore. We should reinitialize VMX when the system wakes up [1]. The code
is located in powercallback.c.


--[ 4 Demo

--[ 4.1 A keylogger

This is a simple keylogger that will leave no hook to be found. There are
many places you can hook for a keylogger. The one we choose is
KeyboardClassServiceCallBack. It is a low level function but not too low,
both PS/2 and USE keyboard will call it to transfer keystrokes. And this
part is not mine, I cannot find the right author to say thank you :)

Inline hooking in 64bits environment usually takes 14 bytes rather than
5 bytes in 32bits. It first pushes quad word address into stack, following
by a RET instruction:

PUSH <Low Absolute Address DWORD>
MOV [RSP+4], DWORD <High Absolute Address DWORD>
RET


So the original KeyboardClassServiceCallBack() looks like:

fffff880`03994990 4c8bdc          mov     r11,rsp
fffff880`03994993 49895b08        mov     qword ptr [r11+8],rbx
fffff880`03994997 49896b10        mov     qword ptr [r11+10h],rbp
fffff880`039949s9b 49897318       mov     qword ptr [r11+18h],rsi
fffff880`0399499f 57              push    rdi
fffff880`039949a0 4154            push    r12
fffff880`039949a2 4155            push    r13
fffff880`039949a4 4156            push    r14

After inline hooking, it then looks like:

fffff880`03994990 68b058d502      push    2D558B0h
fffff880`03994995 c744240480f8ffff mov     dword ptr [rsp+4],0FFFFF880h
fffff880`0399499d c3              ret
fffff880`0399499e 90              nop
fffff880`0399499f 57              push    rdi
fffff880`039949a0 4154            push    r12
fffff880`039949a2 4155            push    r13
fffff880`039949a4 4156            push    r14


The address pushed into stack is the address of the trampoline function
which first execute those missing instructions and then jump right back to
the original KeyboardClassServiceCallback.

With our attack, the malicious driver first make a copy of the page which
KeyboardClassServiceCallback within. As mentioned before, it's for the
checker. Then it will tell hypervisor both of the pages by a vmcall. The
hypervisor will then take care of the rest.

One thing I should mention, the demos has some hard coded values, it works
on my test machines, but you should modify it a little bit to run on other
version of Windows. You know how it is :)


--[ 4.2  Bypass PatchGuard

PatchGuard won't check driver images other than kernel, both the
KeyboardClassServiceCallback hook keylogger and the interruption hook
keylogger can not trigger it. So we have to simply hook a system service
call which PatchGuard do care about. Let's say NtQuerySystemInformation. If
we don't have hypervisor underneath, hooking a system service function will
lead to BSOD with bug check code 0x109 (CRITICAL_STRUCTURE_CORRUPTION). It
usually take several minutes for PatchGuard to find out, sometimes it may
need half an hour.

So in this demo project, we just simply inline hook
NtQuerySystemInformation() and hide a process. In our explorations, we
found out that there is some data within the same page with
NtQuerySystemInformation(). And Windows operating system keeps referencing
them. Hence this page will be switched back and forth between two EPT
tables all the time. On the other hand, NtCreateFile() causes a very
different silent situation. So in project "test" you can test either one of
them by enabling function TestInvisibleNtCreateFileInlineHook() or
TestInvisibleNtQuerySystemInformationInlineHook().

--[ 5  Other applications

This could be used by rootkit, also it could be used by anti-virus products
to hide track from being detected by malware.

To defend and discover 0-day attacks, sandbox system is used more and more
widely. It quite efficient because it does not heavily rely on virus
signatures. When a sample need to be analyzed, it will be put into a
virtual machine. It makes believe that this is a real victim machine and
run the sample. And the monitor program will record all the behaviors that
the sample shows. If any harmful behavior is found, this sample will be
marked as malware or virus.

So the whole sandbox system is based on monitoring. That is to say there
will be a lot of hooks. Perhaps on Win32 API or system calls.

You can imagine the malware and virus do not want to be treated like that,
they try many ways to defeat sandbox system. One way that is used most
commonly is to detect if there exists any hooks in the system. If there is,
they will consider this as a trap and could behave accordingly.


--[ 6. Greetings

I'd like to say thank you to ufphpc and MysteryMop for the advices and
helping me debugging. Thank Phrack Staff for the endless patience and
encouraging.

Special thanks to uay and our two kids :)


--[ 7. References

[1] http://blogs.msdn.com/b/doronh/archive/2006/06/13/630493.aspx
[2] http://www.xenproject.org
[3] https://code.google.com/p/hyperdbg/
[4] http://theinvisiblethings.blogspot.com/2006/06/
	introducing-blue-pill.html
[5] http://www.intel.com/content/www/us/en/processors/
	architectures-software-developer-manuals.html
[6] http://phrack.org/issues/63/8.html
[7] https://pax.grsecurity.net/docs/pageexec.txt
[8] https://www.blackhat.com/docs/us-14/materials/us-14-Torrey-
	MoRE-Shadow-Walker-The-Progression-Of-TLB-Splitting-On-x86.pdf
[9] https://msdn.microsoft.com/en-us/library/aa390339%28v=vs.85%29.aspx
[10] https://msdn.microsoft.com/en-us/library/windows/hardware/
	 ff564575%28v=vs.85%29.aspx


--[ 8. Appendix: Code
