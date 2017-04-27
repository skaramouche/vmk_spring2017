#pragma once
#include <Windows.h>
#include <stdio.h>

#pragma region __ Constants __
#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251
#define MEGABYTE 1048576
#define MAX_FILE_SIZE_ALLOWED_TO_READ 20 * MEGABYTE
#define SIZE_OF_CALL_INSTRUCTION 5
#define OFFSET_PATTERN 0x77777777

#define TOO_LARGE_FILE "File is larger than allowed, can not parse"
#define NULL_FILE_SIZE "File has size of 0"
#define NOT_PE_FILE "This file is not PE"

#pragma endregion


#pragma region __ Structures __
struct ENTRY_POINT_CODE
{
  DWORD sizeOfCode;
  char* code;
};

typedef struct {
	IMAGE_DOS_HEADER *dos_hdr;
	IMAGE_NT_HEADERS32 *nt_hdr;
	IMAGE_FILE_HEADER *file_hdr;
	IMAGE_OPTIONAL_HEADER32 *opt_hdr;
	IMAGE_SECTION_HEADER *sect_hdr_start;
} PEFile;
#pragma endregion


#pragma region __ Functions __
HANDLE GetFileFromArguments( int argc, char** argv );
DWORD ReadFileToBuffer( HANDLE fileHandle, char* buffer, DWORD bufferSize );
DWORD WriteFileFromBuffer( char* filename, char* buffer, DWORD bufferSize );
int ChangeEntryPoint( HANDLE fileHandle, DWORD fileSize, char* originalFilename);
DWORD CheckFileSizeForCorrectness( DWORD fileSize );
DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern );
DWORD GetCodeSize();
ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint );
int ParsePE(char *fileBuf, DWORD bufSize, PEFile *res);

void PrintError( char* functionFrom );
void PrintHelp( char* programName );
#pragma endregion

