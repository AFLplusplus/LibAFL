#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#define STBI_ASSERT(x)
#define STBI_NO_SIMD
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

int target_func(const uint8_t *buf, size_t size) {

  /*printf("BUF (%ld): ", size);
  for (int i = 0; i < size; i++) {
      printf("%02X", buf[i]);
  }
  printf("\n");*/
  
  if (size == 0) return 0;
  
  switch (buf[0]) {

    case 1:
      if (buf[1] == 0x44) {
        //__builtin_trap();
        return 8;
      }

      break;
    case 0xff:
      if (buf[2] == 0xff) {
        if (buf[1] == 0x44) {
          //*(char *)(0xdeadbeef) = 1;
          return 9;
        }
      }

      break;
    default:
      break;

  }

  return 1;

}

int parse_pe(const uint8_t *data, int size)
{
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	// allocate heap
	fileSize = size;
	fileData = (void *)data;
	
	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
  
	printf("******* DOS HEADER *******\n");
	printf("\t0x%x\t\tMagic number\n", dosHeader->e_magic);
	/*
  printf("\t0x%x\t\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t0x%x\t\tPages in file\n", dosHeader->e_cp);
	printf("\t0x%x\t\tRelocations\n", dosHeader->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tChecksum\n", dosHeader->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", dosHeader->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", dosHeader->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", dosHeader->e_lfanew);
*/
	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);
  /*
	printf("\n******* NT HEADERS *******\n");
	printf("\t%x\t\tSignature\n", imageNTHeaders->Signature);
	
	// FILE_HEADER
	printf("\n******* FILE HEADER *******\n");
	printf("\t0x%x\t\tMachine\n", imageNTHeaders->FileHeader.Machine);
	printf("\t0x%x\t\tNumber of Sections\n", imageNTHeaders->FileHeader.NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", imageNTHeaders->FileHeader.TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", imageNTHeaders->FileHeader.PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", imageNTHeaders->FileHeader.NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", imageNTHeaders->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	printf("\n******* OPTIONAL HEADER *******\n");
	printf("\t0x%x\t\tMagic\n", imageNTHeaders->OptionalHeader.Magic);
	printf("\t0x%x\t\tMajor Linker Version\n", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
	printf("\t0x%x\t\tMinor Linker Version\n", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
	printf("\t0x%x\t\tSize Of Code\n", imageNTHeaders->OptionalHeader.SizeOfCode);
	printf("\t0x%x\t\tSize Of Initialized Data\n", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
	printf("\t0x%x\t\tSize Of UnInitialized Data\n", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t0x%x\t\tBase Of Code\n", imageNTHeaders->OptionalHeader.BaseOfCode);
	//printf("\t0x%x\t\tBase Of Data\n", imageNTHeaders->OptionalHeader.BaseOfData);
	printf("\t0x%x\t\tImage Base\n", imageNTHeaders->OptionalHeader.ImageBase);
	printf("\t0x%x\t\tSection Alignment\n", imageNTHeaders->OptionalHeader.SectionAlignment);
	printf("\t0x%x\t\tFile Alignment\n", imageNTHeaders->OptionalHeader.FileAlignment);
	printf("\t0x%x\t\tMajor Operating System Version\n", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinor Operating System Version\n", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajor Image Version\n", imageNTHeaders->OptionalHeader.MajorImageVersion);
	printf("\t0x%x\t\tMinor Image Version\n", imageNTHeaders->OptionalHeader.MinorImageVersion);
	printf("\t0x%x\t\tMajor Subsystem Version\n", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
	printf("\t0x%x\t\tMinor Subsystem Version\n", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32 Version Value\n", imageNTHeaders->OptionalHeader.Win32VersionValue);
	printf("\t0x%x\t\tSize Of Image\n", imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("\t0x%x\t\tSize Of Headers\n", imageNTHeaders->OptionalHeader.SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", imageNTHeaders->OptionalHeader.CheckSum);
	printf("\t0x%x\t\tSubsystem\n", imageNTHeaders->OptionalHeader.Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", imageNTHeaders->OptionalHeader.DllCharacteristics);
	printf("\t0x%x\t\tSize Of Stack Reserve\n", imageNTHeaders->OptionalHeader.SizeOfStackReserve);
	printf("\t0x%x\t\tSize Of Stack Commit\n", imageNTHeaders->OptionalHeader.SizeOfStackCommit);
	printf("\t0x%x\t\tSize Of Heap Reserve\n", imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
	printf("\t0x%x\t\tSize Of Heap Commit\n", imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
	printf("\t0x%x\t\tLoader Flags\n", imageNTHeaders->OptionalHeader.LoaderFlags);
	printf("\t0x%x\t\tNumber Of Rva And Sizes\n", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	printf("\n******* DATA DIRECTORIES *******\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[1].Size);
  */
return 0;
	// SECTION_HEADERS
	printf("\n******* SECTION HEADERS *******\n");
	// get offset to first section headeer
	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);
	
	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	// print section data
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
    /*
		printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);
    */
		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	// get file offset to import table
	rawOffset = (DWORD)fileData + importSection->PointerToRawData;
	
	// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
	importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));
	
	printf("\n******* DLL IMPORTS *******\n");	
	for (; importDescriptor->Name != 0; importDescriptor++)	{
		// imported dll modules
		printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
		thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));
		
		// dll exported functions
		for (; thunkData->u1.AddressOfData != 0; thunkData++) {
			//a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
			if (thunkData->u1.AddressOfData > 0x80000000) {
				//show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
				printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
			} else {
				printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
			}
		}
	}

    return 0;
}



int load_stbi(const uint8_t *data, int size)
{
  int w;
  int h;
  int channels;

  const unsigned char * img = stbi_load_from_memory(data, size, &w, &h, &channels, 0);
  if (img) { stbi_image_free((void *)img); }
  // STBI_FREE((void *)img); }

  return 0;
}

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  //return target_func(Data, Size);

  if(Size > 0x4000) return 0;

  int size = Size;
  const unsigned char * data = Data;
  //return load_stbi(data, size);  
  return parse_pe(data, size);
}

