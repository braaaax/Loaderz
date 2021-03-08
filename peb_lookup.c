#include "skunk.h"

/*
from a C project Through Assembly to Shellcode by hasherezade
modified to use SuperFastHash by me
*/
LPVOID get_module_by_name(WCHAR* module_name)
{
    // reading PEB of current process
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;
        WCHAR* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0) {
            //found
            return curr_module->BaseAddress;
        }
        // not found, try next:
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

LPVOID get_func_by_hash(LPVOID module, DWORD func_hash)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        DWORD comphash = (DWORD)SuperFastHash(curr_name, strlen(curr_name));
        if (comphash == func_hash) {
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}

DWORD FindProcByName(const char* proc_name){
    pCreateToolHelpSnapshot fCreateToolHelpSnapshot = (pCreateToolHelpSnapshot)get_func_by_hash((HMODULE)get_module_by_name((const LPWSTR)L"kernel32.dll"), (DWORD)2158221815); // [+] CreateToolhelp32Snapshot [Length: 24] = 2158221815
    pProcess32First fProcess32First = (pProcess32First)get_func_by_hash((HMODULE)get_module_by_name((const LPWSTR)L"kernel32.dll"), (DWORD)3181235790);                         // [+] Process32First [Length: 14] = 3181235790
    pProcess32Next fProcess32Next = (pProcess32Next)get_func_by_hash((HMODULE)get_module_by_name((const LPWSTR)L"kernel32.dll"), (DWORD)1441674826);                            // [+] Process32Next [Length: 13] = 1441674826
    pCloseHandle fCloseHandle = (pCloseHandle)get_func_by_hash((HMODULE)get_module_by_name((const LPWSTR)L"kernel32.dll"), (DWORD)4173592724);                                  // [+] CloseHandle [Length: 11] = 417359272

    PROCENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCENTRY32);
    HANDLE hSnapshot = fCreateToolHelpSnapshot(TH32CS_SNAPPROC, 0);
    if(hSnapshot)
    {
        if(fProcess32First(hSnapshot, &pe32))
        {
            do
            {
                if (strcmp(pe32.szExeFile, proc_name) == 0)
                {
                    return pe32.th32ProcessID;
                }
            } while(fProcess32Next(hSnapshot, &pe32));
            fCloseHandle(hSnapshot);
        }
    }
    return -1;
}
