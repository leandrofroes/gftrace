.MODEL flat, C

EXTERN JmpBackAddr: DWORD
EXTERN hk_Asmstdcall: PROC

ASSUME FS:NOTHING

.code
AsmstdcallStub PROC PUBLIC

    ; Execute the patched Asmstdcall instruction.
    mov eax, dword ptr fs:[34h]

    ; Save eax and ebx values.
    push eax
    push ebx

    ; Call the Asmstdcall hook.
    call hk_Asmstdcall

    ; Restore ebx and eax values.
    pop ebx
    pop eax

    ; Jump back to the original Asmstdcall function after the hooking point.
    jmp [JmpBackAddr]

AsmstdcallStub ENDP

END