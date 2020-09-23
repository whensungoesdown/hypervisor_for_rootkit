//  [5/20/2015 uty]
#ifndef _POWERCALLBACK_H_
#define _POWERCALLBACK_H_
//-----------------------------------------------------------------------------//
typedef struct _DEV_EXT {
	PVOID CbRegistration;
	PCALLBACK_OBJECT CbObject;
} DEV_EXT, *PDEV_EXT;
//-----------------------------------------------------------------------------//
NTSTATUS
RegisterPowerStateChangeCallback(
    PDEV_EXT DevExt
    );

VOID
DeregisterPowerStateChangeCallback(
    PDEV_EXT DevExt
    );
//-----------------------------------------------------------------------------//
#endif