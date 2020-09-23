//  [5/5/2015 uty]
#include <ntddk.h>
#include "cpu.h"
//-----------------------------------------------------------------------------//
NTSTATUS
InitializeSegmentSelector (
	PSEGMENT_SELECTOR SegmentSelector, 
	USHORT Selector,
	ULONG64 GdtBase
	)
{
	PSEGMENT_DESCRIPTOR2 SegDesc;

	if (!SegmentSelector)
		return STATUS_INVALID_PARAMETER;

	if (Selector & 0x4) {
		DbgPrint("InitializeSegmentSelector(): Given selector points to LDT\n", Selector);
		return STATUS_INVALID_PARAMETER;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR2) ((PUCHAR) GdtBase + (Selector & ~0x7));

	SegmentSelector->sel = Selector;
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
	//SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 8;

	if (!(SegDesc->attr0 & LA_STANDARD)) {
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64) ((PUCHAR) SegDesc + 8));
		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->attributes.fields.g) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
ULONG64
GetSegmentDescriptorBase (
	ULONG64 gdt_base,
	USHORT seg_selector
	)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };

	InitializeSegmentSelector(&SegmentSelector, seg_selector, gdt_base);

	return SegmentSelector.base;

}
//-----------------------------------------------------------------------------//
ULONG
GetSegmentDescriptorLimit (
	ULONG64 gdt_base,
	USHORT selector
	)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };

	InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);

	return SegmentSelector.limit;
}
//-----------------------------------------------------------------------------//
ULONG
GetSegmentDescriptorAR (
	ULONG64 gdt_base,
	USHORT selector
	)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);

	uAccessRights = (ULONG)SegmentSelector.attributes.UCHARs;

	if (!selector)
		uAccessRights |= 0x10000;

	return uAccessRights;
}
//-----------------------------------------------------------------------------//