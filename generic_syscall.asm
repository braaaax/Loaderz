; filled in the gaps from www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams
; nasm -f win64 generic_syscall.asm -o generic_syscall.lib
section .text
global ZwX


ZwX:
    pop     rax            ; return address
    pop     r10
    push    rax            ; save in shadow space as _rcx
    push    rcx            ; rax = ssn 
    pop     rax
    push    rdx            ; rcx = arg1
    pop     r10
    push    r8             ; rdx = arg2
    pop     rdx
    push    r9             ; r8 = arg3
    pop     r8
                           ; r9 = arg4
    mov     r9, [rsp + 0x20] 
    syscall
    jmp     qword[rsp]