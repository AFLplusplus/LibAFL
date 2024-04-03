; LibAFL QEMU Windows ASM companion file. It should be used together with libafl_qemu.h
; Since Windows does not support extended inline assembly, it is more convenient to use asm files directly.

PUBLIC _libafl_sync_exit_call0, _libafl_sync_exit_call1, _libafl_sync_exit_call2
PUBLIC _libafl_backdoor_call0, _libafl_backdoor_call1, _libafl_backdoor_call2

LIBAFL_SYNC_EXIT_OPCODE MACRO
	dd 66f23a0fh
ENDM

LIBAFL_BACKDOOR_OPCODE MACRO
	dd 44f23a0fh
ENDM

.code

; Execute LibAFL sync exit (no argument)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL QEMU Command
_libafl_sync_exit_call0:
	mov rax, rcx

	LIBAFL_SYNC_EXIT_OPCODE

	ret

; Execute LibAFL sync exit (one argument)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL QEMU Command
;	[RDX, IN]  Arg1
_libafl_sync_exit_call1:
	push rdi

	mov rax, rcx
	mov rdi, rdx

	LIBAFL_SYNC_EXIT_OPCODE

	pop rdi

	ret

; Execute LibAFL sync exit (two arguments)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL QEMU Command
;	[RDX, IN]  Arg1
;	[R8,  IN]  Arg2
_libafl_sync_exit_call2:
	push rdi
	push rsi

	mov rax, rcx
	mov rdi, rdx
	mov rsi, r8

	LIBAFL_SYNC_EXIT_OPCODE

	pop rsi
	pop rdi

	ret

; Execute LibAFL backdoor (no argument)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL QEMU Command
_libafl_backdoor_call0:
	mov rax, rcx

	LIBAFL_BACKDOOR_OPCODE

	ret

; Execute LibAFL backdoor (one argument)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL QEMU Command
;	[RDX, IN]  Arg1
_libafl_backdoor_call1:
	push rdi

	mov rax, rcx
	mov rdi, rdx

	LIBAFL_BACKDOOR_OPCODE

	pop rdi

	ret

; Execute LibAFL backdoor (two arguments)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL QEMU Command
;	[RDX, IN]  Arg1
;	[R8,  IN]  Arg2
_libafl_backdoor_call2:
	push rdi
	push rsi

	mov rax, rcx
	mov rdi, rdx
	mov rsi, r8

	LIBAFL_BACKDOOR_OPCODE

	pop rsi
	pop rdi

	ret

END
