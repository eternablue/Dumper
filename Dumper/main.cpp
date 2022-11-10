#include "util.hpp"
#include <stdio.h>
#include <string>

#define PAGE_SIZE 0x1000

void main(int argc, char** argv)
{
	if (argc != 2)
		{printf("\tUsage : Dumper.exe [EXE_NAME]\n"); return;}

	uint64_t PID = get_pid_by_name(argv[1]);
	if (PID)
		printf("[+] Found process %s with pid %d\n", argv[1], PID);
	else
		{printf("[-] Failed to find process %s \n", argv[1]); return;};

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess)
		printf("[+] Opened handle 0x%X to process\n", hProcess);
	else
		{printf("[-] Failed to open handle to process\n"); return;};

	uint64_t process_base = get_module_base(PID);
	printf("[+] Process module base 0x%p\n");


	IMAGE_DOS_HEADER dos_header;
	ReadProcessMemory(hProcess, (void*)process_base, &dos_header, sizeof(IMAGE_DOS_HEADER), 0);
	printf("[+] DOS header [%p]\n", dos_header);

	IMAGE_NT_HEADERS nt_header;
	ReadProcessMemory(hProcess, (void*)(process_base + dos_header.e_lfanew), &nt_header, sizeof(IMAGE_NT_HEADERS), 0);
	printf("[+] NT header [%p]\n", nt_header);

	
	void* process_buffer = VirtualAlloc(0, nt_header.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("[+] Allocated %d bytes for process at 0x%p\n", nt_header.OptionalHeader.SizeOfImage, nt_header);


	for (uint64_t page = 0; page < nt_header.OptionalHeader.SizeOfImage; page += PAGE_SIZE)
		ReadProcessMemory(hProcess, (void*)(process_base + page), (void*)((uint64_t)process_buffer + page), PAGE_SIZE, 0);


	PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)process_buffer;

	if (image_dos_header->e_magic == IMAGE_DOS_SIGNATURE)
		printf("[+] Process DOS header 0x%p\n", image_dos_header);
	else
		{printf("[-] Invalid process dos signature\n");return;}

	PIMAGE_NT_HEADERS image_nt_header = (PIMAGE_NT_HEADERS)((uint64_t)process_buffer + image_dos_header->e_lfanew);
	printf("[+] Process NT header 0x%p\n", image_nt_header);


	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(image_nt_header);

	for (uint64_t i = 0; i < image_nt_header->FileHeader.NumberOfSections; ++i, ++section)
	{
		std::string section_name = (char*)(section->Name);
		printf("\t> Fixing section %s at 0x%p\n", section_name, (uint64_t)process_base + section->VirtualAddress);

		section->PointerToRawData = section->VirtualAddress;
		section->SizeOfRawData = section->Misc.VirtualSize;
	}

	std::string dump_file_name = "DUMP_" + std::string(argv[1]);

	DeleteFileA(dump_file_name.c_str());
	HANDLE hFile = CreateFileA(dump_file_name.c_str(), GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);

	if (!hFile)
		{printf("[-] Failed to create dump file\n");return;}

	BOOL success = WriteFile(hFile, process_buffer, image_nt_header->OptionalHeader.SizeOfImage, 0, 0);

	if (success)
		printf("[+] Dumped %s of size %d\n", argv[1], image_nt_header->OptionalHeader.SizeOfImage);
	else
		{printf("[-] Failed to write dump to file\n");return;}


}