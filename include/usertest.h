//  [6/4/2015 uty]
#ifndef _USER_TEST_H_
#define _USER_TEST_H_
//-----------------------------------------------------------------------------//
#define PAGE_SIZE 0x1000

typedef struct _USER_SHADOW_PAGE
{
	PVOID VirtualPageAddress;
	CHAR PageContent[PAGE_SIZE];
} USER_SHADOW_PAGE, *PUSER_SHADOW_PAGE;
//-----------------------------------------------------------------------------//
//#define HYPERVISOR_DEVICE_NAME  L"hypervisor"
#define HYPERVISOR_DEVICE_LINK_NAME  L"\\\\.\\hypervisor"

#define FILE_DEVICE_HYPERVISOR	0x8500
#define HYPERVISOR_IOCTL_INDEX  0x838

#define GET_FUNC_ID(n) ((((n) & 0x3FFC) >> 2) - HYPERVISOR_IOCTL_INDEX)

//-----------------------------------------------------------------------------//
#define IOCTL_HYPERVISOR_PROTECT_PAGE			CTL_CODE(FILE_DEVICE_UNKNOWN,  \
	HYPERVISOR_IOCTL_INDEX + 0,  \
	METHOD_BUFFERED,       \
	FILE_ANY_ACCESS)
//-----------------------------------------------------------------------------//
#endif