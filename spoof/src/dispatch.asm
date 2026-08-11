.code

PUBLIC SpoofDispatch

SpoofDispatch PROC
    pop     r11
    add     rsp, 8
    mov     rax, [rsp + 24]

    mov     r10, [rax]
    mov     [rsp], r10

    mov     r10, [rax + 8]
    mov     [rax + 16], r11
    mov     [rax + 24], rbx

    lea     rbx, fixup
    mov     [rax], rbx
    mov     rbx, rax

    jmp     r10

fixup:
    sub     rsp, 16
    mov     rcx, rbx
    mov     rbx, [rcx + 24]
    jmp     qword ptr [rcx + 16]

SpoofDispatch ENDP

END