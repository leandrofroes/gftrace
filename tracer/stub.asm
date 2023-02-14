EXTERN JmpBackAddr: QWORD
EXTERN hk_Asmstdcall: PROC

.code
AsmstdcallStub PROC PUBLIC

    ; Execute the patched Asmstdcall instructions.
    mov rdi, qword ptr gs:[30h]
    mov eax, dword ptr [rdi+68h]
    mov qword ptr [rcx+28h], rax

    ; Save rcx value.
    push rcx

    ; Call the Asmstdcall hook.
    call hk_Asmstdcall

    ; Restore rcx value.
    pop rcx

    ; Jump back to the original Asmstdcall function after the hooking point.
    jmp [JmpBackAddr]

AsmstdcallStub ENDP

END