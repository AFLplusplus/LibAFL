	.arch armv8-a
	.file	"foo.c"
	.text
	.section	.text.startup,"ax",@progbits
	.align	2
	.p2align 4,,11
	.global	main
	.type	main, %function
main:
.LFB0:
	.cfi_startproc
	mov	x1, 32768
	mov	w0, 0
	ldrb	w2, [x1]
	ldrb	w3, [x1, 1]
	cmp	w2, w3
	bls	.L2
	cmp	w2, 32
	bls	.L4
	cmp	w2, 80
	beq	.L9
	mov	w0, 3
.L2:
	ret
.L4:
	mov	w0, 2
	ret
.L9:
	cmp	w3, 36
	beq	.L10
	mov	w0, 4
	ret
.L10:
	ldrb	w0, [x1, 2]
	cmp	w0, 54
	cset	w0, eq
	add	w0, w0, 5
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
