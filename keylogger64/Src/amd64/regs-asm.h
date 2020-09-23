//  [5/4/2015 uty]
#ifndef _REGS_ASM_H_
#define _REGS_ASM_H_
//-----------------------------------------------------------------------------//
ULONG64 RegGetCr0 (VOID);
ULONG64 RegGetCr3 (VOID);
ULONG64 RegGetCr4 (VOID);
VOID RegSetBitCr4 (ULONG mask);
VOID RegClearBitCr4 (ULONG mask);

ULONG64 RegGetRflags(VOID);

USHORT RegGetCs(VOID);
USHORT RegGetDs(VOID);
USHORT RegGetEs(VOID);
USHORT RegGetSs(VOID);
USHORT RegGetFs(VOID);
USHORT RegGetGs(VOID);

ULONG64 RegGetIdtBase(VOID);
USHORT RegGetIdtLimit(VOID);
ULONG64 RegGetGdtBase(VOID);
USHORT RegGetGdtLimit(VOID);
USHORT RegGetLdtr(VOID);
USHORT RegGetTr(VOID);


//-----------------------------------------------------------------------------//
#endif