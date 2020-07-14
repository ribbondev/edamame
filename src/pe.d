module pe;

import core.stdc.stdint;

alias off_t = long;

extern (C) {

  struct IMAGE_COFF_HEADER {
    align(1):
    uint16_t Machine;
	  uint16_t NumberOfSections;
	  uint32_t TimeDateStamp;
	  uint32_t PointerToSymbolTable;
	  uint32_t NumberOfSymbols;
	  uint16_t SizeOfOptionalHeader;
	  uint16_t Characteristics;
  }

  alias IMAGE_FILE_HEADER = IMAGE_COFF_HEADER;

  struct IMAGE_DOS_HEADER {
    align (1):
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
  }

  struct IMAGE_OPTIONAL_HEADER_32 {
    align (1):
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Reserved1;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
  }

  struct IMAGE_OPTIONAL_HEADER_64 {
    align (1):
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Reserved1;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
  }

  struct IMAGE_OPTIONAL_HEADER {
    align (1):
	  uint16_t type; // opt_type_e
	  size_t length;
	  IMAGE_OPTIONAL_HEADER_32 *_32;
	  IMAGE_OPTIONAL_HEADER_64 *_64;
  }

  struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
  }

  struct IMAGE_SECTION_HEADER {
    align (1):
    uint8_t Name[8];
    union {
      uint32_t PhysicalAddress;
      uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
  }

  struct pe_file_t {
    IMAGE_DOS_HEADER *dos_hdr;
    uint32_t signature;
    IMAGE_COFF_HEADER *coff_hdr;
    void *optional_hdr_ptr;
    IMAGE_OPTIONAL_HEADER optional_hdr;
    uint32_t num_directories;
    void *directories_ptr;
    IMAGE_DATA_DIRECTORY **directories;
    uint16_t num_sections;
    void *sections_ptr;
    IMAGE_SECTION_HEADER **sections;
    uint64_t entrypoint;
    uint64_t imagebase;
  }

  struct pe_imports_t {
    pe_err_e err;
    uint32_t dll_count;
    pe_imported_dll_t *dlls;
  }

  struct pe_cached_data_t {
    pe_imports_t *imports;
    pe_exports_t *exports;
    pe_hash_headers_t *hash_headers;
    pe_hash_sections_t *hash_sections;
    pe_hash_t *hash_file;
    pe_resources_t *resources;
  }

  struct pe_ctx_t {
    FILE *stream;
    char *path;
    void *map_addr;
    off_t map_size;
    uintptr_t map_end;
    pe_file_t pe;
    pe_cached_data_t cached_data;
  }

}
