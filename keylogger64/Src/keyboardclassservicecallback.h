//  [6/27/2015 uty]
#ifndef _KEYBOARDCLASSSERVICECALLBACK_H_
#define _KEYBOARDCLASSSERVICECALLBACK_H_
//-----------------------------------------------------------------------------//
typedef struct _KEYBOARD_INPUT_DATA {
	USHORT UnitId;
	USHORT MakeCode;
	USHORT Flags;
	USHORT Reserved;
	ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;
//-----------------------------------------------------------------------------//
typedef VOID
(_stdcall *PKEYBOARDCLASSSERVICECALLBACK)( 
	IN PDEVICE_OBJECT DeviceObject,
	IN PKEYBOARD_INPUT_DATA InputDataStart,
	IN PKEYBOARD_INPUT_DATA InputDataEnd,
	IN OUT PULONG InputDataConsumed
	);

typedef struct _KBD_CALLBACK
{
	PDEVICE_OBJECT classDeviceObject;
	PKEYBOARDCLASSSERVICECALLBACK serviceCallBack;
} KBD_CALLBACK, *PKBD_CALLBACK;
//-----------------------------------------------------------------------------//
extern KBD_CALLBACK g_KbdCallBack;
//-----------------------------------------------------------------------------//
NTSTATUS
SearchKeyboardClassServiceCallback (
	__in PDRIVER_OBJECT DriverObject
	);


NTSTATUS
InlineHookKeyboardClassServiceCallback (
	__in PVOID Function,
	__in PVOID FunctionHook
	);

VOID
KeyboardClassServiceCallbackHook (
	__in    PDEVICE_OBJECT       DeviceObject,
	__in    PKEYBOARD_INPUT_DATA InputDataStart,
	__in    PKEYBOARD_INPUT_DATA InputDataEnd,
	__inout PULONG               InputDataConsumed
	);
//-----------------------------------------------------------------------------//
#endif