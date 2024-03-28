PUBLIC _libafl_exit_call0, _libafl_exit_call1, _libafl_exit_call2

LIBAFL_EXIT_OPCODE MACRO
	dd 66f23a0fh
ENDM

.code

; Execute LibAFL backdoor (no argument)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL Backdorr operation
_libafl_exit_call0:
	mov rax, rcx

IFNDEF _DEBUG
	LIBAFL_EXIT_OPCODE
ENDIF

	ret

; Execute LibAFL backdoor (one argument)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL Backdorr operation
;	[RDX, IN]  Arg1
_libafl_exit_call1:
	push rdi

	mov rax, rcx
	mov rdi, rdx

IFNDEF _DEBUG
	LIBAFL_EXIT_OPCODE
ENDIF

	pop rdi

	ret

; Execute LibAFL backdoor (two arguments)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  LibAFL Backdorr operation
;	[RDX, IN]  Arg1
;	[R8,  IN]  Arg2
_libafl_exit_call2:
	push rdi
	push rsi

	mov rax, rcx
	mov rdi, rdx
	mov rsi, r8

IFNDEF _DEBUG
	LIBAFL_EXIT_OPCODE
ENDIF
	pop rsi
	pop rdi

	ret

END