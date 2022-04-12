typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef DWORD (* PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef long LONG;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

typedef void * PVOID;

typedef ulong ULONG_PTR;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

typedef uchar BYTE;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

typedef union _SLIST_HEADER * PSLIST_HEADER;

typedef double ULONGLONG;

typedef struct _struct_299 _struct_299, *P_struct_299;

typedef struct _SINGLE_LIST_ENTRY _SINGLE_LIST_ENTRY, *P_SINGLE_LIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY SINGLE_LIST_ENTRY;

typedef ushort WORD;

struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY * Next;
};

struct _struct_299 {
    SINGLE_LIST_ENTRY Next;
    WORD Depth;
    WORD Sequence;
};

union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct _struct_299 s;
};

typedef wchar_t WCHAR;

typedef char CHAR;

typedef CHAR * LPCSTR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef WCHAR * LPCWSTR;

typedef void * HANDLE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef uint UINT_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbname[18];
};

typedef struct in_addr in_addr, *Pin_addr;

typedef union _union_1226 _union_1226, *P_union_1226;

typedef struct _struct_1227 _struct_1227, *P_struct_1227;

typedef struct _struct_1228 _struct_1228, *P_struct_1228;

typedef ulong ULONG;

typedef uchar UCHAR;

typedef ushort USHORT;

struct _struct_1228 {
    USHORT s_w1;
    USHORT s_w2;
};

struct _struct_1227 {
    UCHAR s_b1;
    UCHAR s_b2;
    UCHAR s_b3;
    UCHAR s_b4;
};

union _union_1226 {
    struct _struct_1227 S_un_b;
    struct _struct_1228 S_un_w;
    ULONG S_addr;
};

struct in_addr {
    union _union_1226 S_un;
};

typedef USHORT ADDRESS_FAMILY;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef void * LPCVOID;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef DWORD * LPDWORD;

typedef uint UINT;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
    pointer32 GuardCFCCheckFunctionPointer;
    pointer32 GuardCFDispatchFunctionPointer;
    pointer32 GuardCFFunctionTable;
    dword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer32 GuardAddressTakenIatEntryTable;
    dword GuardAddressTakenIatEntryCount;
    pointer32 GuardLongJumpTargetTable;
    dword GuardLongJumpTargetCount;
    pointer32 DynamicValueRelocTable;
    pointer32 CHPEMetadataPointer;
    pointer32 GuardRFFailureRoutine;
    pointer32 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer32 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    dword Reserved3;
};

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    ADDRESS_FAMILY sa_family;
    CHAR sa_data[14];
};

typedef struct WSAData WSAData, *PWSAData;

typedef struct WSAData WSADATA;

struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    ushort iMaxSockets;
    ushort iMaxUdpDg;
    char * lpVendorInfo;
};

typedef UINT_PTR SOCKET;

typedef ushort u_short;

typedef WSADATA * LPWSADATA;

typedef struct hostent hostent, *Phostent;

struct hostent {
    char * h_name;
    char * * h_aliases;
    short h_addrtype;
    short h_length;
    char * * h_addr_list;
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

struct _IMAGE_SECTION_HEADER { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef int errno_t;

typedef uint size_t;




undefined * FUN_00401000(void)

{
  return &DAT_00405390;
}



void __cdecl FUN_00401010(undefined4 param_1,undefined param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined1 *puVar4;
  
  uVar1 = __acrt_iob_func(1);
  puVar4 = &param_2;
  uVar3 = 0;
  puVar2 = (undefined4 *)FUN_00401000();
  __stdio_common_vfprintf(*puVar2,puVar2[1],uVar1,param_1,uVar3,puVar4);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// lpStartAddress parameter of CreateThread
// 

undefined4 lpStartAddress_00401050(SOCKET *param_1)

{
  SOCKET s;
  bool bVar1;
  char *pcVar2;
  void *_Dst;
  undefined4 *buf;
  undefined4 unaff_EDI;
  undefined uVar3;
  undefined8 local_18;
  undefined8 local_10;
  
  s = *param_1;
  local_18 = 0;
  send(s,"Welcome",8,0);
  recv(s,(char *)&local_18,8,0);
  FUN_00401010("[x] Data Recieved: 0x%x.\n",(char)local_18);
  FUN_00401010("[x] Data Recieved: 0x%x.\n",(char)((ulonglong)local_18 >> 0x20));
  uVar3 = (undefined)unaff_EDI;
  if ((int)local_18 == -0x80000000) {
    FUN_00401010("[x] Bye! Have Fun!\n",uVar3);
                    // WARNING: Subroutine does not return
    exit(1);
  }
  if ((int)local_18 == -0x7fffffff) {
    FUN_00401010("[x] Hello, Figure Me!\n",uVar3);
    if (local_18._4_4_ < 2000) {
      buf = (undefined4 *)malloc(local_18._4_4_ + 1);
      memset(buf,0,local_18._4_4_ + 1);
      recv(s,(char *)buf,local_18._4_4_,0);
      *buf = 0x646e6946;
      buf[1] = 0x656d20;
      free(buf);
      bVar1 = true;
      while( true ) {
        while( true ) {
          if (300 < local_18._4_4_) break;
          if (local_18._4_4_ == 300) {
            pcVar2 = "Come again!\n";
            goto LAB_00401235;
          }
          if (local_18._4_4_ == 0) {
            FUN_00401010("High ends, requires short begins\n",(char)unaff_EDI);
            local_18._4_4_ = 300;
          }
          else if (local_18._4_4_ == 100) {
            local_18._4_4_ = 0;
          }
          else {
            if (local_18._4_4_ != 200) goto LAB_0040125c;
            local_18._4_4_ = 0x309;
            bVar1 = false;
          }
        }
        if (local_18._4_4_ != 400) break;
        local_18._4_4_ = 0x309;
        bVar1 = false;
      }
      if (local_18._4_4_ == 0x309) {
        if (bVar1) {
          free(buf);
          free(buf);
          return 0;
        }
      }
      else {
LAB_0040125c:
        pcVar2 = "Not now please :}\n";
LAB_00401235:
        FUN_00401010(pcVar2,(char)unaff_EDI);
      }
      free(buf);
    }
  }
  else if ((int)local_18 == -0x7ffffffe) {
    FUN_00401010("[x] Hello, Figure Me Too!\n",uVar3);
    send(s,"Heap!\n",6,0);
    if (local_18._4_4_ < 0x100) {
      pcVar2 = (char *)malloc(local_18._4_4_ + 1);
      if (pcVar2 != (char *)0x0) {
        local_10 = 0;
        recv(s,pcVar2,local_18._4_4_,0);
        _Dst = malloc(local_18._4_4_ * 100);
        memset(_Dst,1,local_18._4_4_ * 100);
        memcpy((void *)((int)_Dst + 0x14),&param_1,0x1374);
        free(pcVar2);
        return 0;
      }
      FUN_00401010("[x] Could not allocate buffer",uVar3);
      return 0;
    }
  }
  return 0;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl MAIN(int argc,char **argv)

{
  char cVar1;
  HANDLE hFileMappingObject;
  void *pvVar2;
  int iVar3;
  SOCKET s;
  hostent *phVar4;
  ulong uVar5;
  undefined8 *puVar6;
  char *pcVar7;
  uint uVar8;
  size_t _Size;
  undefined1 unaff_DI;
  void *_Src;
  undefined uVar9;
  char *pcVar10;
  undefined local_24c [4];
  undefined4 uStack584;
  undefined local_244;
  size_t local_240;
  void *local_23c;
  undefined local_238 [4];
  ulong local_234;
  sockaddr local_228;
  char local_218 [128];
  WSADATA local_198;
  
  uVar9 = 0xf0;
  FUN_00401010("db   db  .d8b.  d8888b.  .d88b.   .d88b.  d8888b.\n88   88 d8\' `8b 88  `8D .8P  Y8. .8P  Y8. 88  `8D \n88ooo88 88ooo88 88oooY\' 88    88 88    88 88oooY\' \n88~~~88 88~~~88 88~~~b. 88    88 88    88 88~~~b. \n88   88 88   88 88   8D `8b  d8\' `8b  d8\' 88   8D \nYP   YP YP   YP Y8888P\'  `Y88P\'   `Y88P\'  Y8888P\'\n"
               ,unaff_DI);
  FUN_00401010("\nSecure Channel Created..\nStart Using our Bug Free App... Have Fun *_^!\n",uVar9);
  if (argc < 2) {
    FUN_00401010("[x] Choose from 1 to 4\n0 to End Your Misery\n",unaff_DI);
    return 0;
  }
  cVar1 = *argv[1];
  if (('0' < cVar1) && (cVar1 < ':')) {
    switch(cVar1) {
    case '0':
      FUN_00401010("Hope We See You Soon ^_^\n",unaff_DI);
      return 0;
    case '1':
      FUN_00401010("[x] Starting Secret Data Exchange..\n",unaff_DI);
      puVar6 = (undefined8 *)local_24c;
      _local_24c = 0x57425f4648514d;
      uVar8 = 0;
      do {
        cVar1 = *(char *)puVar6;
        puVar6 = (undefined8 *)((int)puVar6 + 1);
      } while (cVar1 != '\0');
      if (puVar6 != (undefined8 *)((int)local_24c + 1)) {
        do {
          *(byte *)((int)local_24c + uVar8) = *(byte *)((int)local_24c + uVar8) ^ 7;
          puVar6 = (undefined8 *)local_24c;
          uVar8 = uVar8 + 1;
          do {
            cVar1 = *(char *)puVar6;
            puVar6 = (undefined8 *)((int)puVar6 + 1);
          } while (cVar1 != '\0');
        } while (uVar8 < (uint)((int)puVar6 - ((int)local_24c + 1)));
      }
      hFileMappingObject = OpenFileMappingA(0xf001f,0,local_24c);
      if ((hFileMappingObject != (HANDLE)0xffffffff) && (hFileMappingObject != (HANDLE)0x0)) {
        pcVar7 = (char *)MapViewOfFile(hFileMappingObject,0xf001f,0,0,0);
        memset(local_218,0,0x80);
        pcVar10 = pcVar7;
        do {
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
          pcVar10[(int)&local_228 + (0xf - (int)pcVar7)] = cVar1;
        } while (cVar1 != '\0');
        FUN_00401010("Secret Exchanged Data: %s\n",0xe8);
        UnmapViewOfFile(pcVar7);
        CloseHandle(hFileMappingObject);
        return 0;
      }
      puVar6 = (undefined8 *)local_24c;
      uVar8 = 0;
      do {
        cVar1 = *(char *)puVar6;
        puVar6 = (undefined8 *)((int)puVar6 + 1);
      } while (cVar1 != '\0');
      if (puVar6 != (undefined8 *)((int)local_24c + 1)) {
        do {
          *(byte *)((int)local_24c + uVar8) = *(byte *)((int)local_24c + uVar8) ^ 7;
          puVar6 = (undefined8 *)local_24c;
          uVar8 = uVar8 + 1;
          do {
            cVar1 = *(char *)puVar6;
            puVar6 = (undefined8 *)((int)puVar6 + 1);
          } while (cVar1 != '\0');
        } while (uVar8 < (uint)((int)puVar6 - ((int)local_24c + 1)));
      }
      uVar9 = 0x90;
      FUN_00401010("Hushhh... our shared memory secret is %s\n",0xb4);
      FUN_00401010("is it enough >.>?\n",uVar9);
      return 0;
    case '2':
      FUN_00401010("[x] Sending Secret..\n",unaff_DI);
      if (argc == 4) {
        uVar5 = strtoul(argv[3],(char **)0x0,0);
        puVar6 = (undefined8 *)local_24c;
        pcVar10 = argv[2];
        local_244 = 0;
        uVar8 = 0;
        _local_24c = 0x5d626f6f6261485b;
        do {
          cVar1 = *(char *)puVar6;
          puVar6 = (undefined8 *)((int)puVar6 + 1);
        } while (cVar1 != '\0');
        if (puVar6 != (undefined8 *)((int)local_24c + 1)) {
          do {
            if (((char *)((int)local_24c + uVar8))[(int)pcVar10 - (int)local_24c] !=
                *(char *)((int)local_24c + uVar8)) {
              return 0;
            }
            uVar8 = uVar8 + 1;
          } while (uVar8 < (uint)((int)puVar6 - (int)(undefined8 *)((int)local_24c + 1)));
        }
        _local_24c = CONCAT44(0x5d626f6f,uVar5 * 0x3520);
        pvVar2 = malloc(uVar5 * 0x3520);
        if (pvVar2 == (void *)0x0) {
          return 0;
        }
        local_240 = uVar5 * 0x88;
        local_23c = pvVar2;
        memset(pvVar2,0,local_240);
        pcVar7 = pcVar10;
        do {
          cVar1 = *pcVar7;
          pcVar7 = pcVar7 + 1;
        } while (cVar1 != '\0');
        if ((uint)((int)pcVar7 - (int)(pcVar10 + 1)) < 0x81) {
          pcVar7 = pcVar10;
          do {
            cVar1 = *pcVar7;
            pcVar7 = pcVar7 + 1;
          } while (cVar1 != '\0');
          _Size = (int)pcVar7 - (int)(pcVar10 + 1);
        }
        else {
          _Size = 0x80;
        }
        iVar3 = uVar5 * 100;
        _Src = pvVar2;
        if (0 < iVar3) {
          do {
            memcpy(pvVar2,pcVar10,_Size);
            pvVar2 = (void *)((int)pvVar2 + 0x88);
            iVar3 = iVar3 + -1;
            _Src = local_23c;
          } while (iVar3 != 0);
        }
        pvVar2 = malloc(local_240);
        if (pvVar2 != (void *)0x0) {
          memcpy(pvVar2,_Src,local_24c);
          free(pvVar2);
        }
        free(_Src);
        return 0;
      }
      break;
    case '3':
      FUN_00401010("[x] Bottom Initilization..\n",unaff_DI);
      memset(&local_198,0,400);
      iVar3 = WSAStartup(0x202,&local_198);
      if (iVar3 != 0) {
        FUN_00401010("[x] Error, WSAStartup.\n",unaff_DI);
        return 0;
      }
      s = WSASocketW(2,1,6,0,0,0);
      if (s != 0xffffffff) {
        FUN_00401010("[x] Socket created!\n",unaff_DI);
        local_238._0_2_ = 2;
        local_238._2_2_ = ntohs(0x7a69);
        phVar4 = gethostbyname("");
        inet_ntoa((in_addr)((in_addr *)*phVar4->h_addr_list)->S_un);
        local_234 = inet_addr("0.0.0.0");
        iVar3 = bind(s,(sockaddr *)local_238,0x10);
        if (iVar3 == -1) {
          pcVar10 = "[x] Error, bind.\n";
        }
        else {
          FUN_00401010("[x] Bind successful!\n",unaff_DI);
          iVar3 = listen(s,1);
          if (iVar3 != -1) {
            FUN_00401010("[x] Listening..!\n",unaff_DI);
            _local_24c = CONCAT44(uStack584,0x10);
            do {
              local_240 = accept(s,&local_228,(int *)local_24c);
              CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,lpStartAddress_00401050,&local_240,0,
                           (LPDWORD)&local_23c);
            } while( true );
          }
          pcVar10 = "[x] Error, listen.\n";
        }
        FUN_00401010(pcVar10,unaff_DI);
        closesocket(s);
        WSACleanup();
        return 0;
      }
      FUN_00401010("[x] Error, WSASocket.\n",unaff_DI);
      return 0;
    case '4':
      FUN_00401010("[x] Ending Parameters..\n",unaff_DI);
      if (argc == 3) {
        uVar5 = strtoul(argv[2],(char **)0x0,0);
        puVar6 = (undefined8 *)malloc(uVar5 * 8);
        if (puVar6 != (undefined8 *)0x0) {
          memset(puVar6,1,uVar5);
        }
        free(puVar6);
        *puVar6 = 0x4024000000000000;
        return 0;
      }
      break;
    default:
      FUN_00401010("[-] Invalid Choice.\n",unaff_DI);
      goto LAB_0040179a;
    }
    FUN_00401010("[-] Invalid Number of argumetns.\n",unaff_DI);
    return 0;
  }
LAB_0040179a:
                    // WARNING: Subroutine does not return
  exit(1);
}



int entry(void)

{
  code *pcVar1;
  char **argv;
  bool bVar2;
  undefined4 uVar3;
  int iVar4;
  code **ppcVar5;
  int *piVar6;
  undefined4 *puVar7;
  uint uVar8;
  int unaff_EBP;
  int unaff_ESI;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar9;
  undefined4 uVar10;
  
  ___security_init_cookie();
  FUN_00401fb0(&DAT_004039d8,0x14);
  uVar3 = ___scrt_initialize_crt(1);
  if ((char)uVar3 != '\0') {
    bVar2 = false;
    *(undefined *)(unaff_EBP + -0x19) = 0;
    *(undefined4 *)(unaff_EBP + -4) = 0;
    uVar3 = ___scrt_acquire_startup_lock();
    *(char *)(unaff_EBP + -0x24) = (char)uVar3;
    if (DAT_00405028 != 1) {
      if (DAT_00405028 == 0) {
        DAT_00405028 = 1;
        iVar4 = _initterm_e(&DAT_00403134,&DAT_00403140);
        if (iVar4 != 0) {
          *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
          unaff_ESI = 0xff;
          goto LAB_004019ed;
        }
        _initterm(&DAT_00403128,&DAT_00403130);
        DAT_00405028 = 2;
      }
      else {
        bVar2 = true;
        *(undefined *)(unaff_EBP + -0x19) = 1;
      }
      ___scrt_release_startup_lock((char)*(undefined4 *)(unaff_EBP + -0x24));
      ppcVar5 = (code **)FUN_00401d75();
      if (*ppcVar5 != (code *)0x0) {
        uVar3 = ___scrt_is_nonwritable_in_current_image();
        if ((char)uVar3 != '\0') {
          pcVar1 = *ppcVar5;
          uVar10 = 0;
          uVar9 = 2;
          uVar3 = 0;
          _guard_check_icall();
          (*pcVar1)(uVar3,uVar9,uVar10);
        }
      }
      piVar6 = (int *)FUN_00401d7b();
      if (*piVar6 != 0) {
        uVar3 = ___scrt_is_nonwritable_in_current_image();
        if ((char)uVar3 != '\0') {
          _register_thread_local_exe_atexit_callback(*piVar6);
        }
      }
      _get_initial_narrow_environment();
      puVar7 = (undefined4 *)__p___argv();
      argv = (char **)*puVar7;
      piVar6 = (int *)__p___argc();
      unaff_ESI = MAIN(*piVar6,argv);
      uVar8 = FUN_00401ea0();
      if ((char)uVar8 != '\0') {
        if (!bVar2) {
          _cexit();
        }
        ___scrt_uninitialize_crt(1,'\0');
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
LAB_004019ed:
        *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0x10);
        return unaff_ESI;
      }
      goto LAB_00401a04;
    }
  }
  ___scrt_fastfail(7);
LAB_00401a04:
                    // WARNING: Subroutine does not return
  exit(unaff_ESI);
}



// Library Function - Single Match
//  struct _IMAGE_SECTION_HEADER * __cdecl find_pe_section(unsigned char * const,unsigned int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_IMAGE_SECTION_HEADER * __cdecl find_pe_section(uchar *param_1,uint param_2)

{
  int iVar1;
  _IMAGE_SECTION_HEADER *p_Var2;
  _IMAGE_SECTION_HEADER *p_Var3;
  
  iVar1 = *(int *)(param_1 + 0x3c);
  p_Var2 = (_IMAGE_SECTION_HEADER *)
           (param_1 + (uint)*(ushort *)(param_1 + iVar1 + 0x14) + iVar1 + 0x18);
  p_Var3 = p_Var2 + (uint)*(ushort *)(param_1 + iVar1 + 6) * 0x28;
  while( true ) {
    if (p_Var2 == p_Var3) {
      return (_IMAGE_SECTION_HEADER *)0x0;
    }
    if ((*(uint *)(p_Var2 + 0xc) <= param_2) &&
       (param_2 < (uint)(*(int *)(p_Var2 + 8) + *(int *)(p_Var2 + 0xc)))) break;
    p_Var2 = p_Var2 + 0x28;
  }
  return p_Var2;
}



// Library Function - Single Match
//  ___scrt_acquire_startup_lock
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint ___scrt_acquire_startup_lock(void)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  undefined3 extraout_var;
  uint uVar4;
  int in_FS_OFFSET;
  
  bVar3 = ___scrt_is_ucrt_dll_in_use();
  uVar4 = CONCAT31(extraout_var,bVar3);
  if (uVar4 != 0) {
    uVar1 = *(uint *)(*(int *)(in_FS_OFFSET + 0x18) + 4);
    while( true ) {
      uVar4 = 0;
      LOCK();
      uVar2 = uVar1;
      if (DAT_0040502c != 0) {
        uVar4 = DAT_0040502c;
        uVar2 = DAT_0040502c;
      }
      DAT_0040502c = uVar2;
      if (uVar4 == 0) break;
      if (uVar1 == uVar4) {
        return CONCAT31((int3)(uVar4 >> 8),1);
      }
    }
  }
  return uVar4 & 0xffffff00;
}



// Library Function - Single Match
//  ___scrt_initialize_crt
// 
// Library: Visual Studio 2019 Release

uint __cdecl ___scrt_initialize_crt(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  
  if (param_1 == 0) {
    DAT_00405030 = 1;
  }
  ___isa_available_init();
  uVar1 = FUN_00401d1f();
  if ((char)uVar1 != '\0') {
    uVar2 = FUN_00401d1f();
    if ((char)uVar2 != '\0') {
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
    uVar1 = FUN_00401d1f();
  }
  return uVar1 & 0xffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___scrt_initialize_onexit_tables(int param_1)

{
  code *pcVar1;
  bool bVar2;
  undefined4 in_EAX;
  undefined3 extraout_var;
  uint uVar3;
  undefined4 uVar4;
  
  if (DAT_00405031 != '\0') {
    return CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  if ((param_1 != 0) && (param_1 != 1)) {
    ___scrt_fastfail(5);
    pcVar1 = (code *)swi(3);
    uVar4 = (*pcVar1)();
    return uVar4;
  }
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  uVar3 = CONCAT31(extraout_var,bVar2);
  if ((uVar3 == 0) || (param_1 != 0)) {
    _DAT_00405034 = 0xffffffff;
    _DAT_00405038 = 0xffffffff;
    _DAT_0040503c = 0xffffffff;
    _DAT_00405040 = 0xffffffff;
    _DAT_00405044 = 0xffffffff;
    _DAT_00405048 = 0xffffffff;
LAB_00401b3f:
    DAT_00405031 = '\x01';
    uVar3 = CONCAT31((int3)(uVar3 >> 8),1);
  }
  else {
    uVar3 = _initialize_onexit_table(&DAT_00405034);
    if (uVar3 == 0) {
      uVar3 = _initialize_onexit_table(&DAT_00405040);
      if (uVar3 == 0) goto LAB_00401b3f;
    }
    uVar3 = uVar3 & 0xffffff00;
  }
  return uVar3;
}



// Library Function - Single Match
//  ___scrt_is_nonwritable_in_current_image
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint ___scrt_is_nonwritable_in_current_image(void)

{
  _IMAGE_SECTION_HEADER *p_Var1;
  uint uVar2;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  FUN_00401fb0(&DAT_004039f8,8);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  p_Var1 = find_pe_section((uchar *)&IMAGE_DOS_HEADER_00400000,*(int *)(unaff_EBP + 8) - 0x400000);
  if ((p_Var1 == (_IMAGE_SECTION_HEADER *)0x0) || (*(int *)(p_Var1 + 0x24) < 0)) {
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    uVar2 = (uint)p_Var1 & 0xffffff00;
  }
  else {
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    uVar2 = CONCAT31((int3)((uint)p_Var1 >> 8),1);
  }
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0x10);
  return uVar2;
}



// Library Function - Single Match
//  ___scrt_release_startup_lock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl ___scrt_release_startup_lock(char param_1)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  iVar1 = DAT_0040502c;
  iVar3 = CONCAT31(extraout_var,bVar2);
  if ((iVar3 != 0) && (param_1 == '\0')) {
    DAT_0040502c = 0;
    iVar3 = iVar1;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___scrt_uninitialize_crt
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined __cdecl ___scrt_uninitialize_crt(undefined4 param_1,char param_2)

{
  if ((DAT_00405030 == '\0') || (param_2 == '\0')) {
    FUN_00401d1f();
    FUN_00401d1f();
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2019 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  int iVar1;
  
  if (_DAT_00405034 == -1) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_00405034,_Func);
  }
  return (_onexit_t)(~-(uint)(iVar1 != 0) & (uint)_Func);
}



// Library Function - Single Match
//  _atexit
// 
// Library: Visual Studio 2019 Release

int __cdecl _atexit(void *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  ___get_entropy
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint ___get_entropy(void)

{
  DWORD DVar1;
  uint local_18;
  uint local_14;
  _FILETIME local_10;
  uint local_8;
  
  local_10.dwLowDateTime = 0;
  local_10.dwHighDateTime = 0;
  GetSystemTimeAsFileTime(&local_10);
  local_8 = local_10.dwHighDateTime ^ local_10.dwLowDateTime;
  DVar1 = GetCurrentThreadId();
  local_8 = local_8 ^ DVar1;
  DVar1 = GetCurrentProcessId();
  local_8 = local_8 ^ DVar1;
  QueryPerformanceCounter((LARGE_INTEGER *)&local_18);
  return local_14 ^ local_18 ^ local_8 ^ (uint)&local_8;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___security_init_cookie(void)

{
  if ((DAT_00405018 == 0xbb40e64e) || ((DAT_00405018 & 0xffff0000) == 0)) {
    DAT_00405018 = ___get_entropy();
    if (DAT_00405018 == 0xbb40e64e) {
      DAT_00405018 = 0xbb40e64f;
    }
    else if ((DAT_00405018 & 0xffff0000) == 0) {
      DAT_00405018 = DAT_00405018 | (DAT_00405018 | 0x4711) << 0x10;
    }
  }
  DAT_00405014 = ~DAT_00405018;
  return;
}



undefined4 FUN_00401d06(void)

{
  return 0;
}



undefined4 FUN_00401d09(void)

{
  return 1;
}



undefined4 FUN_00401d0d(void)

{
  return 0x4000;
}



void FUN_00401d13(void)

{
  InitializeSListHead((PSLIST_HEADER)&ListHead_00405050);
  return;
}



undefined FUN_00401d1f(void)

{
  return 1;
}



void FUN_00401d22(void)

{
  code *pcVar1;
  errno_t eVar2;
  
  eVar2 = _controlfp_s((uint *)0x0,0x10000,0x30000);
  if (eVar2 == 0) {
    return;
  }
  ___scrt_fastfail(7);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void _guard_check_icall(void)

{
  return;
}



undefined * FUN_00401d46(void)

{
  return &DAT_00405058;
}



void FUN_00401d4c(void)

{
  uint *puVar1;
  
  puVar1 = (uint *)FUN_00401000();
  *puVar1 = *puVar1 | 0x24;
  puVar1[1] = puVar1[1];
  puVar1 = (uint *)FUN_00401d46();
  *puVar1 = *puVar1 | 2;
  puVar1[1] = puVar1[1];
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_00401d69(void)

{
  return _DAT_00405004 == 0;
}



undefined * FUN_00401d75(void)

{
  return &DAT_0040539c;
}



undefined * FUN_00401d7b(void)

{
  return &DAT_00405398;
}



// Library Function - Single Match
//  ___scrt_fastfail
// 
// Library: Visual Studio 2019 Release

void ___scrt_fastfail(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  undefined4 local_328 [39];
  EXCEPTION_RECORD local_5c;
  _EXCEPTION_POINTERS local_c;
  
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  FUN_00401f45();
  memset(local_328,0,0x2cc);
  local_328[0] = 0x10001;
  memset(&local_5c,0,0x50);
  local_5c.ExceptionCode = 0x40000015;
  local_5c.ExceptionFlags = 1;
  BVar2 = IsDebuggerPresent();
  local_c.ExceptionRecord = &local_5c;
  local_c.ContextRecord = (PCONTEXT)local_328;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_c);
  if ((LVar3 == 0) && (BVar2 != 1)) {
    FUN_00401f45();
  }
  return;
}



undefined4 thunk_FUN_00401d06(void)

{
  return 0;
}



uint FUN_00401ea0(void)

{
  HMODULE pHVar1;
  int *piVar2;
  
  pHVar1 = GetModuleHandleW((LPCWSTR)0x0);
  if ((((pHVar1 != (HMODULE)0x0) && (*(short *)&pHVar1->unused == 0x5a4d)) &&
      (piVar2 = (int *)((int)&pHVar1->unused + pHVar1[0xf].unused), *piVar2 == 0x4550)) &&
     (((pHVar1 = (HMODULE)0x10b, *(short *)(piVar2 + 6) == 0x10b && (0xe < (uint)piVar2[0x1d])) &&
      (piVar2[0x3a] != 0)))) {
    return 0x101;
  }
  return (uint)pHVar1 & 0xffffff00;
}



undefined4 FUN_00401eef(int **param_1)

{
  int *piVar1;
  int iVar2;
  int **ppiVar3;
  
  piVar1 = *param_1;
  if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
     ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
      (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
    ppiVar3 = (int **)__current_exception();
    *ppiVar3 = piVar1;
    piVar1 = param_1[1];
    ppiVar3 = (int **)__current_exception_context();
    *ppiVar3 = piVar1;
                    // WARNING: Subroutine does not return
    terminate();
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401f45(void)

{
  _DAT_00405060 = 0;
  return;
}



// WARNING: Removing unreachable block (ram,0x00401f5d)
// WARNING: Removing unreachable block (ram,0x00401f5e)
// WARNING: Removing unreachable block (ram,0x00401f64)
// WARNING: Removing unreachable block (ram,0x00401f6e)
// WARNING: Removing unreachable block (ram,0x00401f75)

void FUN_00401f4d(void)

{
  return;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_00401fb0(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 unaff_EBX;
  uint uVar6;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_SS;
  undefined2 in_FS;
  undefined auStack4 [4];
  
  puVar1 = (undefined4 *)segment(in_FS,0);
  uVar6 = (uint)auStack4 & 0xffff0000 | (uint)(ushort)((short)register0x00000010 - 8U);
  puVar4 = (undefined4 *)segment(in_SS,(short)register0x00000010 - 8U);
  *puVar4 = *puVar1;
  iVar2 = *(int *)(uVar6 + 0x10);
  *(undefined4 *)(uVar6 + 0x10) = unaff_EBP;
  iVar2 = -iVar2;
  *(undefined4 *)(uVar6 + iVar2 + -4) = unaff_EBX;
  *(undefined4 *)(uVar6 + iVar2 + -8) = unaff_ESI;
  *(undefined4 *)(uVar6 + iVar2 + -0xc) = unaff_EDI;
  uVar5 = DAT_00405018;
  *(uint *)(uVar6 + 0xc) = *(uint *)(uVar6 + 0xc) ^ DAT_00405018;
  *(uint *)(uVar6 + iVar2 + -0x10) = uVar5 ^ uVar6 + 0x10;
  *(uint *)(uVar6 - 8) = uVar6 + iVar2 + -0x10;
  *(undefined4 *)(uVar6 + iVar2 + -0x14) = *(undefined4 *)(uVar6 + 8);
  uVar3 = *(undefined4 *)(uVar6 + 0xc);
  *(undefined4 *)(uVar6 + 0xc) = 0xfffffffe;
  *(undefined4 *)(uVar6 + 8) = uVar3;
  uVar3 = segment(in_FS,0);
  *(uint *)uVar3 = uVar6;
  return;
}



// Library Function - Single Match
//  __except_handler4
// 
// Library: Visual Studio 2019 Release

void __cdecl
__except_handler4(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  
  iVar1 = __filter_x86_sse2_floating_point_exception_default(*param_1);
  *param_1 = iVar1;
  _except_handler4_common(&DAT_00405018,&LAB_00402213,param_1,param_2,param_3,param_4);
  return;
}



// WARNING: Removing unreachable block (ram,0x004020a4)
// WARNING: Removing unreachable block (ram,0x00402069)
// WARNING: Removing unreachable block (ram,0x0040211b)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___isa_available_init
// 
// Library: Visual Studio 2019 Release

undefined4 ___isa_available_init(void)

{
  int *piVar1;
  uint *puVar2;
  int iVar3;
  BOOL BVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint in_XCR0;
  
  _DAT_00405064 = 0;
  DAT_00405010 = DAT_00405010 | 1;
  BVar4 = IsProcessorFeaturePresent(10);
  uVar5 = DAT_00405010;
  if (BVar4 != 0) {
    piVar1 = (int *)cpuid_basic_info(0);
    puVar2 = (uint *)cpuid_Version_info(1);
    uVar6 = puVar2[3];
    if (((piVar1[1] ^ 0x756e6547U | piVar1[3] ^ 0x6c65746eU | piVar1[2] ^ 0x49656e69U) == 0) &&
       (((((uVar5 = *puVar2 & 0xfff3ff0, uVar5 == 0x106c0 || (uVar5 == 0x20660)) ||
          (uVar5 == 0x20670)) || ((uVar5 == 0x30650 || (uVar5 == 0x30660)))) || (uVar5 == 0x30670)))
       ) {
      DAT_00405068 = DAT_00405068 | 1;
    }
    if (*piVar1 < 7) {
      uVar7 = 0;
    }
    else {
      iVar3 = cpuid_Extended_Feature_Enumeration_info(7);
      uVar7 = *(uint *)(iVar3 + 4);
      if ((uVar7 & 0x200) != 0) {
        DAT_00405068 = DAT_00405068 | 2;
      }
    }
    _DAT_00405064 = 1;
    uVar5 = DAT_00405010 | 2;
    if ((uVar6 & 0x100000) != 0) {
      uVar5 = DAT_00405010 | 6;
      _DAT_00405064 = 2;
      if ((((uVar6 & 0x8000000) != 0) && ((uVar6 & 0x10000000) != 0)) && ((in_XCR0 & 6) == 6)) {
        _DAT_00405064 = 3;
        uVar5 = DAT_00405010 | 0xe;
        if ((uVar7 & 0x20) != 0) {
          _DAT_00405064 = 5;
          uVar5 = DAT_00405010 | 0x2e;
          if (((uVar7 & 0xd0030000) == 0xd0030000) && ((in_XCR0 & 0xe0) == 0xe0)) {
            DAT_00405010 = DAT_00405010 | 0x6e;
            _DAT_00405064 = 6;
            uVar5 = DAT_00405010;
          }
        }
      }
    }
  }
  DAT_00405010 = uVar5;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2019 Release

bool ___scrt_is_ucrt_dll_in_use(void)

{
  return _DAT_0040501c != 0;
}



// Library Function - Single Match
//  ___raise_securityfailure
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  UINT uExitCode;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___report_gsfailure(void)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar5;
  undefined4 extraout_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte bVar6;
  byte bVar7;
  byte in_AF;
  byte bVar8;
  byte bVar9;
  byte in_TF;
  byte in_IF;
  byte bVar10;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined8 uVar11;
  undefined4 unaff_retaddr;
  
  uVar4 = IsProcessorFeaturePresent(0x17);
  uVar11 = CONCAT44(extraout_EDX,uVar4);
  bVar6 = 0;
  bVar10 = 0;
  bVar9 = (int)uVar4 < 0;
  bVar8 = uVar4 == 0;
  bVar7 = (POPCOUNT(uVar4 & 0xff) & 1U) == 0;
  uVar5 = extraout_ECX;
  uVar2 = unaff_retaddr;
  uVar3 = unaff_EBP;
  if (!(bool)bVar8) {
    pcVar1 = (code *)swi(0x29);
    uVar11 = (*pcVar1)();
    uVar5 = extraout_ECX_00;
    uVar2 = unaff_retaddr;
    uVar3 = unaff_EBP;
  }
  _DAT_00405174 = uVar3;
  _DAT_0040507c = uVar2;
  _DAT_00405180 =
       (uint)(in_NT & 1) * 0x4000 | (uint)(bVar10 & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)(bVar9 & 1) * 0x80 | (uint)(bVar8 & 1) * 0x40 |
       (uint)(in_AF & 1) * 0x10 | (uint)(bVar7 & 1) * 4 | (uint)(bVar6 & 1) |
       (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
       (uint)(in_AC & 1) * 0x40000;
  _DAT_00405184 = &stack0x00000004;
  _DAT_004050c0 = 0x10001;
  _DAT_00405070 = 0xc0000409;
  _DAT_00405074 = 1;
  _DAT_00405080 = 1;
  _DAT_00405084 = 2;
  _DAT_0040514c = in_GS;
  _DAT_00405150 = in_FS;
  _DAT_00405154 = in_ES;
  _DAT_00405158 = in_DS;
  _DAT_0040515c = unaff_EDI;
  _DAT_00405160 = unaff_ESI;
  _DAT_00405164 = unaff_EBX;
  _DAT_0040516c = uVar5;
  DAT_00405178 = _DAT_0040507c;
  _DAT_0040517c = in_CS;
  _DAT_00405188 = in_SS;
  ___raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_00403158);
  _DAT_00405168 = (undefined4)((ulonglong)uVar11 >> 0x20);
  _DAT_00405170 = (undefined4)uVar11;
  return;
}



void __current_exception(void)

{
                    // WARNING: Could not recover jumptable at 0x00402345. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception();
  return;
}



void __current_exception_context(void)

{
                    // WARNING: Could not recover jumptable at 0x0040234b. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception_context();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402351. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)memset();
  return pvVar1;
}



void _except_handler4_common(void)

{
                    // WARNING: Could not recover jumptable at 0x00402357. Too many branches
                    // WARNING: Treating indirect jump as call
  _except_handler4_common();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void __cdecl exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x0040235d. Too many branches
                    // WARNING: Treating indirect jump as call
  exit();
  return;
}



void _seh_filter_exe(void)

{
                    // WARNING: Could not recover jumptable at 0x00402363. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_exe();
  return;
}



void _set_app_type(void)

{
                    // WARNING: Could not recover jumptable at 0x00402369. Too many branches
                    // WARNING: Treating indirect jump as call
  _set_app_type();
  return;
}



void __setusermatherr(void)

{
                    // WARNING: Could not recover jumptable at 0x0040236f. Too many branches
                    // WARNING: Treating indirect jump as call
  __setusermatherr();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00402375. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x0040237b. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _get_initial_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x00402381. Too many branches
                    // WARNING: Treating indirect jump as call
  _get_initial_narrow_environment();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00402387. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x0040238d. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void __cdecl _exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x00402393. Too many branches
                    // WARNING: Treating indirect jump as call
  _exit();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

errno_t __cdecl _set_fmode(int _Mode)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402399. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = _set_fmode();
  return eVar1;
}



void __p___argc(void)

{
                    // WARNING: Could not recover jumptable at 0x0040239f. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argc();
  return;
}



void __p___argv(void)

{
                    // WARNING: Could not recover jumptable at 0x004023a5. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argv();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x004023ab. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void __cdecl _c_exit(void)

{
                    // WARNING: Could not recover jumptable at 0x004023b1. Too many branches
                    // WARNING: Treating indirect jump as call
  _c_exit();
  return;
}



void _register_thread_local_exe_atexit_callback(void)

{
                    // WARNING: Could not recover jumptable at 0x004023b7. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_thread_local_exe_atexit_callback();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

int __cdecl _configthreadlocale(int _Flag)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004023bd. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _configthreadlocale();
  return iVar1;
}



void __p__commode(void)

{
                    // WARNING: Could not recover jumptable at 0x004023c9. Too many branches
                    // WARNING: Treating indirect jump as call
  __p__commode();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x004023cf. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x004023d5. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x004023db. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

errno_t __cdecl _controlfp_s(uint *_CurrentState,uint _NewValue,uint _Mask)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x004023e1. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = _controlfp_s();
  return eVar1;
}



// WARNING: Exceeded maximum restarts with more pending

void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x004023e7. Too many branches
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004023ed. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __filter_x86_sse2_floating_point_exception_default
// 
// Library: Visual Studio 2019 Release

int __cdecl __filter_x86_sse2_floating_point_exception_default(int param_1)

{
  uint uVar1;
  uint in_MXCSR;
  
  if ((_DAT_00405064 < 1) || ((param_1 != -0x3ffffd4c && (param_1 != -0x3ffffd4b)))) {
    return param_1;
  }
  uVar1 = in_MXCSR ^ 0x3f;
  if ((uVar1 & 0x81) != 0) {
    if ((uVar1 & 0x204) == 0) {
      return -0x3fffff72;
    }
    if ((uVar1 & 0x102) != 0) {
      if ((uVar1 & 0x408) == 0) {
        return -0x3fffff6f;
      }
      if ((uVar1 & 0x810) != 0) {
        if ((uVar1 & 0x1020) != 0) {
          return param_1;
        }
        return -0x3fffff71;
      }
      return -0x3fffff6d;
    }
  }
  return -0x3fffff70;
}



// WARNING: Exceeded maximum restarts with more pending

void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040246b. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)memcpy();
  return pvVar1;
}


