//  [5/20/2015 uty]
#include <ntddk.h>
#include "powercallback.h"
//-----------------------------------------------------------------------------//
NTSTATUS
RunOnProcessor (
	__in ULONG ProcessorNumber
	);
//-----------------------------------------------------------------------------//
VOID
PowerStateCallback(
    __in PVOID Context,
    __in PVOID Argument1,
    __in PVOID Argument2
    )
{
    PDEV_EXT pDevExt;

    pDevExt = (PDEV_EXT) Context;

    if (Argument1 != (PVOID) PO_CB_SYSTEM_STATE_LOCK) {
        return;
    }

    if (Argument2 == (PVOID) 0) 
	{
        //
        // Exiting S0...
        //
    }
    else if (Argument2 == (PVOID) 1)
	{
        //
        // We have reentered S0 (note that we may have never left S0)
        //
		NTSTATUS Status = STATUS_UNSUCCESSFUL;
		LONG i = 0;

		for (i = 0; i < KeNumberProcessors; i++)
		{
			Status = RunOnProcessor(i);
			if (STATUS_SUCCESS != Status)
			{
				DbgPrint("RunOnProcessor failed on processor %d\n", i);
				break;
			}
		}
    }
}
//-----------------------------------------------------------------------------//
NTSTATUS
RegisterPowerStateChangeCallback(
    PDEV_EXT DevExt
    )
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING string;
    NTSTATUS status;

    RtlInitUnicodeString(&string, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&oa,
                               &string,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    //
    // Create a callback object, but we do not want to be the first ones
    // to create it (it should be created way before we load in NTOS
    // anyways) so we pass FALSE for the 3rd parameter.
    //
    status = ExCreateCallback(&DevExt->CbObject, &oa, FALSE, TRUE);

    if (NT_SUCCESS(status)) {
        DevExt->CbRegistration = ExRegisterCallback(DevExt->CbObject,
                                                    PowerStateCallback,
                                                    DevExt);
        if (DevExt->CbRegistration == NULL) {
            ObDereferenceObject(DevExt->CbObject);
            DevExt->CbObject = NULL;

            status = STATUS_UNSUCCESSFUL;
        }
    }

    return status;
}
//-----------------------------------------------------------------------------//
VOID
DeregisterPowerStateChangeCallback(
    PDEV_EXT DevExt
    )
{
    if (DevExt->CbRegistration != NULL) {
        ExUnregisterCallback(DevExt->CbRegistration);
        DevExt->CbRegistration = NULL;
    }

    if (DevExt->CbObject != NULL) {
        ObDereferenceObject(DevExt->CbObject);
        DevExt->CbObject = NULL;
    }
}
//-----------------------------------------------------------------------------//