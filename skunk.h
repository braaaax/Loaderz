#pragma once
#include <windows.h>
#include <stdint.h>

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__)   || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)+(uint32_t)(((const uint8_t *)(d))[0]) )
#endif


#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_ACCESS_DENIED 0xC0000022
#define NtCurrentProcess() ((HANDLE) -1)
#define NtCurrentThread() ((HANDLE) -2)

#define TH32CS_SNAPPROC 0x00000002
#define MAX_SYSCALLS 500

#define CBC 1
#define AES128 1
#include "aes.h"

#define RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

#define InitObjAttr( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

//
// Interface - void func pointer type
//
typedef void(*fnAddr)();

//
// Definitions
//
static BOOL CheckRelocRange(unsigned char* pRelocBuf, DWORD dwRelocBufSize, DWORD dwStartRVA, DWORD dwEndRVA);
static void* GetPAFromRVA(unsigned char* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, unsigned long long qwRVA);
static BOOL PhantomDLLHollower(unsigned char** , unsigned char** OPTIONAL, unsigned long long* , const unsigned char* , DWORD , unsigned char** , BOOL , HANDLE OPTIONAL);
DWORD FindProcByName(const char*);
uint32_t SuperFastHash (const char *, int);
LPVOID get_func_by_hash(LPVOID , DWORD );
LPVOID get_module_by_name(WCHAR* module_name);

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _PROC_INFORMATION_CLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    MaxProcessInfoClass
} PROC_INFORMATION_CLASS, *PPROC_INFORMATION_CLASS;


typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;


typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// from hashazade "peb_lookup.h"
#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                               
    BOOLEAN Initialized;                        
    HANDLE SsHandle;                            
    LIST_ENTRY InLoadOrderModuleList;           
    LIST_ENTRY InMemoryOrderModuleList;         
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

/*
typedef struct _MS_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} MS_PEB_LDR_DATA, *PMS_PEB_LDR_DATA;
*/

//here we don't want to use any functions imported form extenal modules

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress; 
    void* EntryPoint; 
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

/*
typedef struct _MS_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];//8 * 2
	LIST_ENTRY InMemoryOrderLinks; // 2
	PVOID Reserved2[2]; // 8 * 2
	PVOID DllBase;
} MS_LDR_DATA_TABLE_ENTRY, *PMS_LDR_DATA_TABLE_ENTRY;

*/

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;      
    BOOLEAN ReadImageFileExecOptions;  
    BOOLEAN BeingDebugged;             
    BOOLEAN SpareBool;                 
    HANDLE Mutant;                     

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    // [...] this is a fragment, more elements follow here

} PEB, * PPEB;

#endif //__NTDLL_H__



typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


typedef struct _CLIENT_ID
{
    void* UniqueProcess;
    void* UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;



typedef struct tagPROCENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];
} PROCENTRY32;

/*
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    HANDLE SectionHande, 
    ULONG DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PLARGE_INTEGER MaximumSize, 
    ULONG PageAttributes, 
    ULONG SectionAttributes, 
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    HANDLE ProcessHandle, 
    PVOID StartRoutine,  
    PVOID Argument, 
    ULONG CreateFlags, 
    SIZE_T ZeroBits, 
    SIZE_T StackSize, 
    SIZE_T MaximumStackSize, 
    PPS_ATTRIBUTE_LIST  AttributeList
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle, 
    HANDLE ProcessHandle, 
    PVOID *BaseAddress OPTIONAL, 
    ULONG ZeroBits OPTIONAL, 
    ULONG CommitSize, 
    PLARGE_INTEGER SectionOffset OPTIONAL, 
    SIZE_T ViewSize, 
    SECTION_INHERIT InheritDisposition, 
    ULONG AllocationType OPTIONAL, 
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE ProcessHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle, 
    PROC_INFORMATION_CLASS ProcessInformationClass, 
    PVOID ProcessInformation, 
    ULONG ProcessInformationLength, 
    PULONG ReturnLenth
    );

typedef NTSTATUS(NTAPI* pNtCreateTransaction)(
    _Out_ PHANDLE TransactionHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, 
    _In_opt_ LPGUID Uow, 
    _In_opt_ HANDLE TmHandle, 
    _In_opt_ ULONG CreateOptions, 
    _In_opt_ ULONG IsolationLevel, 
    _In_opt_ ULONG IsolationFlags, 
    _In_opt_ PLARGE_INTEGER Timeout, 
    _In_opt_ PUNICODE_STRING Description
    );

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    ULONG_PTR ZeroBits, 
    PULONG RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
    );
*/

typedef HANDLE (WINAPI* pGetCurrentProcess)(void);

typedef DWORD (WINAPI* pWaitForSingleObject)(HANDLE hHandle, DWORD swMilliseconds);

typedef HANDLE (WINAPI* pCreateToolHelpSnapshot)(DWORD dwFlags, DWORD th32ProcessID);

typedef BOOL (WINAPI* pProcess32First)(HANDLE hSnap, PROCENTRY32* lppe);

typedef BOOL (WINAPI* pProcess32Next)(HANDLE hSnap, PROCENTRY32* lppe);

typedef BOOL (WINAPI* pCloseHandle)(HANDLE hSnap);

typedef HANDLE (WINAPI* pCreateFileTransactedW)(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile,
  HANDLE                hTransaction,
  PUSHORT               pusMiniVersion,
  PVOID                 lpExtendedParameter
);


// from syswhispers2
// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#define SW2_SEED 5
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)


typedef struct _SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

typedef struct _SYSCALL_LIST
{
    DWORD Count;
    SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SYSCALL_LIST, *PSYSCALL_LIST;

// Incomplete MS typedefs are prefixed rather an redefined
typedef struct _MS_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} MS_PEB_LDR_DATA, *PMS_PEB_LDR_DATA;

typedef struct _MS_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks; 
	PVOID Reserved2[2]; 
	PVOID DllBase;
} MS_LDR_DATA_TABLE_ENTRY, *PMS_LDR_DATA_TABLE_ENTRY;

/*
typedef NTSTATUS(__stdcall* InvokeSsn_t)(
    DWORD,  // Sysid
    HANDLE, // handle to current process
    PVOID,  // func_ptr
    PVOID,  // arg #1
    PVOID,  // arg #2
    PVOID,  // arg #3
    PVOID   // arg #4
    );

NTSTATUS InvokeSsn_amd64(
    DWORD,  // Sysid
    HANDLE, // handle to current process <-target func params
    PVOID,  // func_ptr
    PVOID,  // arg #1
    PVOID,  // arg #2
    PVOID,  // arg #3
    PVOID   // arg #4
    );
*/

EXTERN_C void GetSyscallList(PSYSCALL_LIST List);
EXTERN_C BOOL GetSSN(PSYSCALL_LIST, DWORD, PDWORD);
EXTERN_C BOOL AllocVMem(PVOID*, ULONG_PTR, PULONG, ULONG, ULONG);

