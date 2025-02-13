	.file	"foo.c"
	.text
	.section	.text.startup,"ax",@progbits
	.p2align 4
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	endbr64
	movzbl	32768, %edx
	movzbl	32769, %ecx
	xorl	%eax, %eax
	cmpb	%cl, %dl
	jle	.L2
	movl	$2, %eax
	cmpb	$32, %dl
	jle	.L2
	movl	$3, %eax
	cmpb	$80, %dl
	je	.L9
.L2:
	movsbl	%al, %eax
	ret
.L9:
	movl	$4, %eax
	cmpb	$36, %cl
	jne	.L2
	cmpb	$54, 32770
	sete	%al
	addl	$5, %eax
	jmp	.L2
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
