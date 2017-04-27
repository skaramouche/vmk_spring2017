#include "pe_parser.h"
#include <string.h>
#include <time.h>

int align_up(int a,int b){
   while (a>b){
      b*=2;
   }
   return b;
}

int ParsePE(char *fileBuf, DWORD bufSize, PEFile *res)
{
	if (bufSize < sizeof(IMAGE_DOS_HEADER)) {
		return 1;
	}

	//проверка e_magic на MZ
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)fileBuf;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("This is not a PE file\n");
		return 1;
	}

	//e_lfanew - смещение заголовка относительно начала PE файла
	if (dos_header->e_lfanew < 0 || dos_header->e_lfanew > bufSize) {
		return 1;
	}

	IMAGE_NT_HEADERS32 *nt_headers = (IMAGE_NT_HEADERS32 *)(fileBuf + dos_header->e_lfanew);

	//подпись заголовка
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		printf("No NT headers: signature = %x\n", nt_headers->Signature);
		return 1;
	}

	//проверка на 64 битовые файлы
	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Incorrect optional header magic, maybe 64bit file?! (%x)\n", nt_headers->OptionalHeader.Magic);
		return 1;
	}

	if (dos_header->e_lfanew + sizeof(*nt_headers) + nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) >= bufSize) {
		return 1;
	}

	//условия на FileAlignment
	if (nt_headers->OptionalHeader.FileAlignment < 512 || nt_headers->OptionalHeader.FileAlignment > 65536 ||
		nt_headers->OptionalHeader.SectionAlignment < nt_headers->OptionalHeader.FileAlignment) {
		printf("Incorrect file or section alignment\n");
		return 1;
	}

	IMAGE_SECTION_HEADER *sect_hdr = (IMAGE_SECTION_HEADER *)(fileBuf + dos_header->e_lfanew + sizeof(*nt_headers));

	res->dos_hdr = dos_header;
	res->nt_hdr = nt_headers;
	res->file_hdr = &nt_headers->FileHeader;
	res->opt_hdr = &nt_headers->OptionalHeader;
	res->sect_hdr_start = sect_hdr;

	return 0;
}


int putEntryPointToCavern(PEFile *pe, char *buffer, DWORD origSize)
{
	printf("Trying to put entry point to cavern\n");
	for (int i = 0; i < pe->file_hdr->NumberOfSections; i++) {  //идём по секциям
		IMAGE_SECTION_HEADER *sect = pe->sect_hdr_start + i;
		//проверка, что в секцию можно писать код
		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            continue;
        }

        DWORD code_min_start = sect->VirtualAddress + sect->Misc.VirtualSize;  //Misc.VirtualSize - размер секции
        DWORD code_max_start = sect->VirtualAddress + sect->SizeOfRawData - GetCodeSize();

        if (code_max_start < code_min_start) {
            printf("Cavern is too small\n");
            return -1;
        }

        DWORD code_offset = 0;
        if (code_max_start > code_min_start) {
            code_offset = rand() % (code_max_start - code_min_start);
        }
        printf("Code offset = %#x\n", code_offset);
        DWORD code_start = code_min_start + code_offset;
        ENTRY_POINT_CODE code = GetEntryPointCodeSmall(code_start, pe->opt_hdr->AddressOfEntryPoint);
        memcpy(buffer + sect->PointerToRawData + sect->Misc.VirtualSize + code_offset, code.code, code.sizeOfCode);
        pe->opt_hdr->AddressOfEntryPoint = code_start;
        return 0;
	}
	return -1;

}

int putEntryPointToExtendedSect(PEFile *pe, char *buffer, DWORD origSize)
{
	printf("Trying to extend section\n");
	for (int i = 0; i < pe->file_hdr->NumberOfSections; i++) {
		IMAGE_SECTION_HEADER *sect = pe->sect_hdr_start + i;
		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {  //проверяем, что в секцию можно писать код
			DWORD code_max_start = align_up(sect->VirtualAddress + sect->SizeOfRawData, pe->opt_hdr->SectionAlignment);

			DWORD code_min_start = sect->VirtualAddress + sect->SizeOfRawData;
			if (code_max_start < code_min_start) {
				printf("Can't extend the section\n");
			} else {
				DWORD code_offset = 0;
				if (code_max_start > code_min_start) {
					code_offset = rand() % (code_max_start - code_min_start);
				}
				printf("Code offset = %#x\n", code_offset);
				DWORD code_start = code_min_start + code_offset;
				DWORD data_shift = pe->opt_hdr->FileAlignment;
				printf("%d",data_shift);
				ENTRY_POINT_CODE code = GetEntryPointCodeSmall(code_start,
					pe->opt_hdr->AddressOfEntryPoint);

				memmove(buffer + sect->PointerToRawData + sect->SizeOfRawData + data_shift,
					buffer + sect->PointerToRawData + sect->SizeOfRawData,
					origSize - sect->PointerToRawData - sect->SizeOfRawData);

				memcpy(buffer + sect->PointerToRawData + sect->SizeOfRawData + code_offset,
					code.code,
					code.sizeOfCode);
				pe->opt_hdr->AddressOfEntryPoint = code_start;
				sect->Misc.VirtualSize = sect->SizeOfRawData + code_offset + code.sizeOfCode;
				sect->SizeOfRawData += data_shift;
				pe->opt_hdr->SizeOfCode += data_shift;

				for (int j = 0; j < pe->file_hdr->NumberOfSections; j++) {
					if (pe->sect_hdr_start[j].PointerToRawData > sect->PointerToRawData) {
						pe->sect_hdr_start[j].PointerToRawData += data_shift;
					}
				}
				return data_shift;
			}
		}
	}
	return -1;
}

int putEntryPointToNewSect(PEFile *pe, char *buffer, DWORD origSize)
{
	printf("Trying to put to new section\n");

	DWORD min_addr = MAXDWORD;
	DWORD max_addr = 0;
	DWORD last_size = 0;
	for (int i = 0; i < pe->file_hdr->NumberOfSections; i++) {
		IMAGE_SECTION_HEADER *sect = pe->sect_hdr_start + i;
		if (sect->VirtualAddress < min_addr) {
			min_addr = sect->VirtualAddress;
		}
		if (sect->VirtualAddress > max_addr) {
			max_addr = sect->VirtualAddress;
			last_size = sect->SizeOfRawData;
		}
	}

	if (min_addr - ((char *)(pe->sect_hdr_start + pe->file_hdr->NumberOfSections) - buffer)< sizeof(IMAGE_SECTION_HEADER)) {
		printf("Not enough space to place section header\n");

		return -1;
    }

    DWORD code_offset = rand() % (pe->opt_hdr->SectionAlignment - GetCodeSize());
    printf("Code offset = %#x\n", code_offset);

    IMAGE_SECTION_HEADER new_section;
    new_section.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;;
    new_section.VirtualAddress = align_up(max_addr + last_size, pe->opt_hdr->SectionAlignment);
    memcpy(new_section.Name, ".nsect\0", 7);
    new_section.SizeOfRawData = (code_offset / pe->opt_hdr->FileAlignment + 1) * pe->opt_hdr->FileAlignment;
    new_section.Misc.VirtualSize = code_offset + GetCodeSize();
    new_section.PointerToRawData = origSize;
    memcpy(pe->sect_hdr_start + pe->file_hdr->NumberOfSections, &new_section, sizeof(new_section));

    pe->file_hdr->NumberOfSections++;
    pe->opt_hdr->SizeOfImage += pe->opt_hdr->SectionAlignment;
    pe->opt_hdr->SizeOfHeaders += sizeof(new_section);
    pe->opt_hdr->SizeOfCode += new_section.Misc.VirtualSize;

    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(new_section.VirtualAddress + code_offset, pe->opt_hdr->AddressOfEntryPoint);
    memcpy(buffer + origSize + code_offset, code.code, code.sizeOfCode);
    pe->opt_hdr->AddressOfEntryPoint = new_section.VirtualAddress + code_offset;
    return new_section.SizeOfRawData;
}

int ChangeEntryPoint(HANDLE fileHandle, DWORD fileSize, char* originalFilename)
{
	srand(time(NULL));
    //считываем файл в buffer
	char *buffer = (char *)malloc(fileSize);
	if (!buffer) {
		printf("impossible to allocate memory\n");
		return 1;
	}
	int readSize = ReadFileToBuffer(fileHandle, buffer, fileSize);
	if (readSize != fileSize)
	{
		printf("Can't read the file");
		return 1;
	}

	PEFile pe;
	if (ParsePE(buffer, fileSize, &pe)) {
		printf("File error - incorrect PE\n");
		return 1;
	}

	DWORD bufferSize = fileSize;

    int mode = rand()%3;
    mode=2;

    buffer = (char *)realloc(buffer, bufferSize);
    if (!buffer) {
        printf("Impossible to reallocate memory\n");
        return 1;
    }

    bool entry_point_changed = false;
    DWORD sizeAdd = -1;
    switch (mode) {
    case 0:
        sizeAdd = putEntryPointToCavern(&pe, buffer, fileSize);
        break;
    case 1:
        //extend section
        bufferSize = fileSize + pe.opt_hdr->FileAlignment;

        buffer = (char *)realloc(buffer, bufferSize);
        if (!buffer) {
            printf("Impossible to reallocate memory\n");
            return 1;
        }

        sizeAdd = putEntryPointToExtendedSect(&pe, buffer, fileSize);
        break;
    case 2:
        //new section
        bufferSize = fileSize + pe.opt_hdr->SectionAlignment;

        buffer = (char *)realloc(buffer, bufferSize);
        if (!buffer) {
            printf("Impossible to reallocate memory\n");
            return 1;
        }

        sizeAdd = putEntryPointToNewSect(&pe, buffer, fileSize);
        break;
    default:
        break;
    }

    if (sizeAdd == -1) {
        entry_point_changed = false;
    } else {
        entry_point_changed = true;
        bufferSize = fileSize + sizeAdd;
    }


	if (entry_point_changed) {
		WriteFileFromBuffer("C:\\Users\\Al\\Documents\\spec\\out.exe", buffer, bufferSize);
	}

	free(buffer);
	return !entry_point_changed;
}

static char byteCode[] = {
	0xE8, 0x00, 0x00, 0x00,
	0x00, 0x50, 0x8B, 0x44,
	0x24, 0x04, 0x05, 0x77,
	0x77, 0x77, 0x77, 0x89,
	0x44, 0x24, 0x04, 0x58,
	0xC3 };

DWORD GetCodeSize()
{
	return sizeof(byteCode);
}

ENTRY_POINT_CODE GetEntryPointCodeSmall(DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint)
{
	ENTRY_POINT_CODE code;
	DWORD offsetToOriginalEntryPoint = rvaToOriginalEntryPoint - rvaToNewEntryPoint - SIZE_OF_CALL_INSTRUCTION;
	DWORD* positionOfOffsetToOriginalEntryPoint = GetPositionOfPattern(byteCode, sizeof(byteCode), OFFSET_PATTERN);
	if (NULL != positionOfOffsetToOriginalEntryPoint)
	{
		*positionOfOffsetToOriginalEntryPoint = offsetToOriginalEntryPoint;
		code.sizeOfCode = sizeof(byteCode);
		code.code = (char*)malloc(code.sizeOfCode);
		memcpy(code.code, byteCode, code.sizeOfCode);
	} else
	{
		code.code = NULL;
		code.sizeOfCode = 0x00;
	}
	return code;
}

DWORD* GetPositionOfPattern(char* buffer, DWORD bufferSize, DWORD pattern)
{
	DWORD* foundPosition = NULL;
	char* position;
	char* lastPosition = buffer + bufferSize - sizeof(DWORD);

	for (position = buffer; position <= lastPosition; ++position)
	{
		if (*((DWORD*)position) == pattern)
		{
			foundPosition = (DWORD*)position;
			break;
		}
	}
	return foundPosition;
}
