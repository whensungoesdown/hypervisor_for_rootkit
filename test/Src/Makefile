# Add additional source files in this macro.
SOURCES=ntquerysysteminformation.c protectuserpage.c main.c \
    amd64\common-asm.asm amd64\msr-asm.asm amd64\regs-asm.asm amd64\vmx-asm.asm amd64\trampoline-asm.asm

# Output driver file name.
OUT=test.sys


# Build list of object files.
OBJS=$(SOURCES:.c=.obj)
OBJS=$(OBJS:.asm=.obj)

# Valid combinations of compilers & WDKs:
#     VS2012 + WDK 8.0 (Microsoft Windows 7)
#     VS2013 + WDK 8.1 (Microsoft Windows 8.1)
#     VS2015 + WDK 8.1 (Microsoft Windows 10)
#
WDK=C:\Program Files (x86)\Windows Kits\10

# Environmental variables honored by "cl.exe" and "link.exe". See the following
# URLs for more information:
#
#     https://msdn.microsoft.com/en-us/library/73f9s62w.aspx
#     https://msdn.microsoft.com/en-us/library/1xhzskbe.aspx
#
INCLUDE=$(INCLUDE);$(WDK)\Include\km;$(WDK)\Include\km\crt;$(WDK)\Include\shared;$(WDK)\Include\10.0.10586.0\km;
LIB=$(LIB);$(WDK)\Lib\win7\km\x64

# See the following URL for more information on "NTDDI_VERSION":
#
#     https://msdn.microsoft.com/en-us/library/windows/desktop/aa383745%28v=vs.85%29.aspx
#
CFLAGS=/nologo /D_AMD64_ /DNTDDI_VERSION=NTDDI_WIN7 /D_WIN32_WINNT /W3 /D_CSTL_BUILD_WIN_DRIVER \
       /GS- /TC /Gz /Gy /GF /EHsc /MT

AFLAGS=/nologo /W3

LFLAGS=/nologo /DRIVER:WDM ntoskrnl.lib hal.lib \
       /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /BASE:"0x10000" /RELEASE /MACHINE:X64 /NODEFAULTLIB  \
       /PDB:test.pdb /DEBUG

# Default inference rule looks buggy in practice. It always complains it can't
# open file "Files" (probably some shitty environment variable expansion takes
# place). See the following URL for more information on inference rules:
#
#     https://msdn.microsoft.com/en-us/library/cx06ysxh.aspx
#
.asm.obj:
    $(AS) $(AFLAGS) /c $<


$(OUT): $(OBJS)
    link.exe *.obj $(LFLAGS) /OUT:$(OUT)


clean:
    del /F *.obj $(OUT)