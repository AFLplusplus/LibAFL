public dll_main
public t1
public t2
public t3
public t4
public t5
public t6
public t7

.code

crash:
    mov rax, 0
    mov rax, [rax]
    ret

; dummy test which does not produce crashes or coverage
test_no_cov:
    ret

; test 64 bits mem/reg
t1:
    cmp rdx, 8
    jb @f
    mov rax, 01234567812345678h
    cmp qword ptr [rcx], rax ; demonstrate rax stack usage (see emit_comparison_handling function)
    je crash
@@:
    ret

; test 32 bits mem/reg
t2:
    cmp rdx, 4
    jb @f
    mov r8d, 012345678h
    mov rax, 100h ; test indes/scale usage
    cmp dword ptr [rcx + rax*2 - 200h], r8d
    je crash
@@:
    ret

; test 16 bits mem/reg
t3:
    cmp rdx, 2
    jb @f
    mov r8w, 01234h
    cmp word ptr [rcx], r8w
    je crash
@@:
    ret

; test 64 bit reg/reg
t4:
    cmp rdx, 8
    jb @f
    mov rax, 01234567812345678h
    mov rcx, qword ptr [rcx]
    cmp rax, rcx
    je crash
@@:
    ret

; test 32 bit reg/imm
t5:
    cmp rdx, 4
    jb @f
    mov rcx, qword ptr [rcx]
    cmp rcx, 012345678h
    je crash
@@:
    ret

; test 32 bit rsp-related reference
t6:
    cmp rdx, 4
    jb @f
    sub rsp, 8
    mov dword ptr [rsp], 012345678h
    mov ecx, dword ptr [rcx]
    cmp dword ptr [rsp], ecx
    je crash
    add rsp, 8
@@:
    ret

; test 32 bit rip-related reference
t7_rip_rel_ref:
    dq 012345678h
t7:
    cmp rdx, 4
    jb @f
    mov ecx, dword ptr [rcx]
    cmp dword ptr [t7_rip_rel_ref], ecx
    je crash
@@:
    ret

dll_main:
    mov eax, 1
    ret

END
