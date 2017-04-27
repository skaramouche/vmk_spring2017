#include "pe_parser.h"
#include <locale.h>
#include <stdio.h>


int main(int argc, char** argv)
{
	UINT codePage = GetConsoleOutputCP();
	SetConsoleOutputCP(CYRILLIC_CODE_PAGE); // set code page to display russian symbols
	setlocale(LC_ALL, "Russian");
	HANDLE fileHandle = GetFileFromArguments(argc, argv);

	if (NULL != fileHandle)
	{
		DWORD fileSize = CheckFileSizeForCorrectness(GetFileSize(fileHandle, NULL));
		if (INVALID_FILE_SIZE != fileSize)
		{
			if (!ChangeEntryPoint(fileHandle, fileSize, argv[1])) {
				printf("File successfully patched\n");
			}
			else {
				printf("File patching failed\n");
			}
		}
		CloseHandle(fileHandle);
	}
	SetConsoleOutputCP(codePage);  // restore code page
	return 0;
}
