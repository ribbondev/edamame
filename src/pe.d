module pe;

import core.stdc.stdint;
import core.stdc.stdio;
import std.bitmanip;

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
    uint16_t[4] e_res;
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t[10] e_res2;
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
    uint8_t[8] Name;
    union Misc {
      uint32_t PhysicalAddress;
      uint32_t VirtualSize;
    };
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

  enum pe_err_e {
    LIBPE_E_OK = 0,
    LIBPE_E_ALLOCATION_FAILURE = -23,
    LIBPE_E_OPEN_FAILED,
    LIBPE_E_FDOPEN_FAILED,
    LIBPE_E_FSTAT_FAILED,
    LIBPE_E_NOT_A_FILE,
    LIBPE_E_NOT_A_PE_FILE,
    LIBPE_E_INVALID_LFANEW,
    LIBPE_E_MISSING_COFF_HEADER,
    LIBPE_E_MISSING_OPTIONAL_HEADER,
    LIBPE_E_INVALID_SIGNATURE,
    LIBPE_E_UNSUPPORTED_IMAGE,
    LIBPE_E_MMAP_FAILED,
    LIBPE_E_MUNMAP_FAILED,
    LIBPE_E_CLOSE_FAILED,
    LIBPE_E_TOO_MANY_DIRECTORIES,
    LIBPE_E_TOO_MANY_SECTIONS,
    LIBPE_E_INVALID_THUNK,
    LIBPE_E_EXPORTS_CANT_READ_RVA,
    LIBPE_E_EXPORTS_CANT_READ_DIR,
    LIBPE_E_EXPORTS_FUNC_NEQ_NAMES,
    LIBPE_E_HASHING_FAILED,
    LIBPE_E_NO_CALLBACKS_FOUND,
    LIBPE_E_NO_FUNCTIONS_FOUND
  }

  struct pe_imported_function_t {
    char *name;
    uint16_t hint;
    uint16_t ordinal;
  }

  struct pe_imported_dll_t {
    pe_err_e err;
    char *name;
    uint32_t functions_count;
    pe_imported_function_t *functions;
  }

  struct pe_imports_t {
    pe_err_e err;
    uint32_t dll_count;
    pe_imported_dll_t *dlls;
  }

  struct pe_exported_function_t {
    uint32_t ordinal;
    char *name;
    char *fwd_name;
    uint32_t address;
  }

  struct pe_exports_t {
    pe_err_e err;
    char *name;
    uint32_t functions_count;
    pe_exported_function_t *functions;
  }

  struct pe_hash_t {
    char *name;
    char *md5;
    char *ssdeep;
    char *sha1;
    char *sha256;
  }

  struct pe_hash_headers_t {
    pe_err_e err;
    pe_hash_t *dos;
    pe_hash_t *coff;
    pe_hash_t *optional;
  }

  struct pe_hash_sections_t {
    pe_err_e err;
    uint32_t count;
    pe_hash_t **sections;
  }

  struct IMAGE_RESOURCE_DIRECTORY {
    align (1):
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
  }

  struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    align (1):
    union u0 {
      struct data {
        mixin(bitfields!(
          uint32_t, "NameOffset", 31,
          uint32_t, "NameIsString", 1));
      };
      uint32_t Name;
      uint16_t Id;
    };
    union u1 {
      uint32_t OffsetToData;
      struct data {
        mixin(bitfields!(
          uint32_t, "OffsetToDirectory", 31,
          uint32_t, "DataIsDirectory", 1));
      };
    };
  }

  alias wchar_t = dchar;

  struct IMAGE_RESOURCE_DATA_STRING_U {
    align (1):
    uint16_t Length;
    wchar_t[1] String;
  }

  struct IMAGE_RESOURCE_DATA_ENTRY {
    align (1):
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
  }

  enum pe_resource_node_type_e {
    LIBPE_RDT_RESOURCE_DIRECTORY = 1,
    LIBPE_RDT_DIRECTORY_ENTRY = 2,
    LIBPE_RDT_DATA_STRING = 3,
    LIBPE_RDT_DATA_ENTRY = 4
  }

  struct pe_resource_node_t {
    uint16_t depth;
    uint32_t dirLevel;
    pe_resource_node_type_e type;
    char *name;
    union raw {
      void *raw_ptr;
      IMAGE_RESOURCE_DIRECTORY *resourceDirectory;
      IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry;
      IMAGE_RESOURCE_DATA_STRING_U *dataString;
      IMAGE_RESOURCE_DATA_ENTRY *dataEntry;
    };
    pe_resource_node_t *parentNode;
    pe_resource_node_t *childNode;
    pe_resource_node_t *nextNode;
  }

  struct pe_resources_t {
    pe_err_e err;
    void *resource_base_ptr;
    pe_resource_node_t *root_node;
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

  pe_err_e pe_load_file(pe_ctx_t *ctx, const char *path);
  pe_err_e pe_parse(pe_ctx_t *ctx);
  bool pe_is_pe(const pe_ctx_t *ctx);
}
