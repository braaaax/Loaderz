#include "skunk.h"
#define GENERIC_CALL_LEN 27

// small tweaks to www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams for below functions
void GetSyscallList(PSYSCALL_LIST List) {
  PMS_PEB_LDR_DATA           Ldr;
  PMS_LDR_DATA_TABLE_ENTRY   LdrEntry;
  PIMAGE_DOS_HEADER       DosHeader;
  PIMAGE_NT_HEADERS       NtHeaders;
  DWORD                   i, j, NumberOfNames, VirtualAddress, Entries=0;
  PIMAGE_DATA_DIRECTORY   DataDirectory;
  PIMAGE_EXPORT_DIRECTORY ExportDirectory;
  PDWORD                  Functions;
  PDWORD                  Names;
  PWORD                   Ordinals;
  PCHAR                   DllName, FunctionName;
  PVOID                   DllBase;
  PSYSCALL_ENTRY          Table;
  SYSCALL_ENTRY           Entry;
  
  //
  // Get the DllBase address of NTDLL.dll
  // NTDLL is not guaranteed to be the second in the list.
  // so it's safer to loop through the full list and find it.   
  PPEB peb = NULL;
#if defined(_WIN64)
  peb = (PPEB)__readgsqword(0x60);
#else
  peb = (PPEB)__readfsdword(0x30);
#endif
  PMS_PEB_LDR_DATA ldr = peb->Ldr;
  // LDR_DATA_TABLE_ENTRY LdrEntry;
  
  // For each DLL loaded
  for ( 
    LdrEntry = (PMS_LDR_DATA_TABLE_ENTRY)ldr->Reserved2[1]; 
    LdrEntry->DllBase != NULL;  
    LdrEntry = (PMS_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
  {
    DllBase = LdrEntry->DllBase;
    DosHeader = (PIMAGE_DOS_HEADER)DllBase;
    NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
    DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
    VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(VirtualAddress == 0) continue;
    
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
    
    //
    // If this is NTDLL.dll, exit loop
    //
    DllName = RVA2VA(PCHAR,DllBase, ExportDirectory->Name);

    if((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
    if((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
  }
  
  NumberOfNames = ExportDirectory->NumberOfNames;
  
  Functions = RVA2VA(PDWORD,DllBase, ExportDirectory->AddressOfFunctions);
  Names     = RVA2VA(PDWORD,DllBase, ExportDirectory->AddressOfNames);
  Ordinals  = RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);
  
  Table     = List->Entries;
  
  do {
    FunctionName = RVA2VA(PCHAR, DllBase, Names[NumberOfNames-1]);
    //
    // Is this a system call?
    //
    if(*(USHORT*)FunctionName == 'wZ') {
      //
      // Save Hash of system call and the address.
      //
      PCHAR pname = &FunctionName[2];
      DWORD len = strlen(FunctionName)-2;
      Table[Entries].Hash = SuperFastHash(pname, len);// HashSyscall(0x4e000074, &FunctionName[2]);
      Table[Entries].Address = Functions[Ordinals[NumberOfNames-1]];
      
      Entries++;
      if(Entries == MAX_SYSCALLS) break;
    }
  } while (--NumberOfNames);
  
  //
  // Save total number of system calls found.
  //
  List->Count = Entries;
  
  //
  // Sort the list by address in ascending order.
  //
  for(i=0; i<Entries - 1; i++) {
    for(j=0; j<Entries - i - 1; j++) {
      if(Table[j].Address > Table[j+1].Address) {
        //
        // Swap entries.
        //
        Entry.Hash = Table[j].Hash;
        Entry.Address = Table[j].Address;
        
        Table[j].Hash = Table[j+1].Hash;
        Table[j].Address = Table[j+1].Address;
        
        Table[j+1].Hash = Entry.Hash;
        Table[j+1].Address = Entry.Address;
      }
    }
  }
}

/*
quick disasm with https://defuse.ca/online-x86-assembler.htm#disassembly
ZwX:
   58                          pop     rax            ; return address
   41 5A                       pop     r10
   50                          push    rax            ; save in shadow space as _rcx
   51                          push    rcx            ; rax = ssn
   58                          pop     rax
   52                          push    rdx            ; rcx = arg1
   41 5A                       pop     r10
   41 50                       push    r8             ; rdx = arg2
   5A                          pop     rdx
   41 51                       push    r9             ; r8 = arg3
   41 58                       pop     r8             ; r9 = arg4
   4C 8B 4C 24 20              mov     r9, [rsp + 0x20]
   0F 05                       syscall
   FF 64 24 18                 jmp     qword[rsp + 0x0]
*/

//
// Get the System Service Number from list.
//
BOOL GetSSN(PSYSCALL_LIST List, DWORD Hash, PDWORD Ssn) {
    DWORD i;
    for(i=0; i<List->Entries; i++) {
      if(Hash == List->Entries[i].Hash) {
        *Ssn = i;
        return TRUE;
      }
    }
    return FALSE;
}

/*
fnAddr GetSyscallPtr(char* syscall_name, ...){
    SYSCALL_LIST   List;
    DWORD          SsnId, allocatevirtualmemory_hash, protectvirtualmemory_hash, oldProtect = 0;
    LPVOID         baseaddr;
    NTSTATUS       status;
    ULONG_PTR      zeroBits;
    PULONG         regionSize; 
    ULONG          flAllocationType; 
    ULONG          flProtect;
    DWORD          szRegion = 0x1000; // our call will never be over a page 

    // should encrypt maybe
    unsigned char gcall[GENERIC_CALL_LEN]  = { 0x58, 0x41, 0x5A, 0x50, 0x51, 0x58, 0x52, 0x41, 0x5A, 0x41, 0x50, 0x5A, 0x41, 0x51, 0x41, 0x58,  0x4C, 0x8B, 0x4C, 0x24, 0x20, 0x0F, 0x05, 0xFF, 0x64, 0x24, 0x0 };
    unsigned char encrypted_func[32] = {
        0xeb, 0xfd, 0x74, 0x50, 0xa7, 0x37, 0x77, 0x27, 0xf7, 0xda, 0x20, 0xc3, 0xd0, 0xef, 0x24, 0x72,
        0xd1, 0x7e, 0x46, 0x99, 0x08, 0x73, 0xe0, 0x11, 0x98, 0x41, 0xb5, 0xea, 0xcc, 0x73, 0x0f, 0x6a
    };    


    // Populate syscall code list 
    GetSyscallList(&List);
    
    // get ssn for and call ntvirtualallocatememory
    GetSSN(&List,SuperFastHash(syscall_name, strlen(syscall_name)),&SsnId);
    status = ZwX( SsnId, NtCurrentProcess(), &baseaddr, zeroBits, &szRegion, flAllocationType, flProtect );
    // if(baseaddr != NULL) { VirtualFree(baseaddr, 0, MEM_RELEASE | MEM_DECOMMIT); }
    if (status != STATUS_SUCCESS) { return NULL; }

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, encrypted_func, 32);
    memcpy(baseaddr, gcall, 27);

    // get ssn for and call ntvirtualallocatememory
    GetSSN(&List,SuperFastHash(syscall_name, strlen(syscall_name)),&SsnId);
    status = ZwX(SsnId, NtCurrentProcess(), &baseaddr, &szRegion, PAGE_EXECUTE_READWRITE, &oldProtect); // as ntvirtualprotect
    if (status != STATUS_SUCCESS) {return NULL;}

    // return a function ptr for desired syscall
    va_list ap;
    va_start(ap)
    return (fnAddr)baseaddr; 
}

// encrypted wrapper idea
void test_func()


*/
