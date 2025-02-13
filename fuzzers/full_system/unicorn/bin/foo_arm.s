	.arch armv7-a
	.fpu vfpv3-d16
	.eabi_attribute 28, 1
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 2
	.eabi_attribute 34, 1
	.eabi_attribute 18, 4
	.file	"foo.c"
	.text
	.section	.text.startup,"ax",%progbits
	.align	1
	.p2align 2,,3
	.global	main
	.syntax unified
	.thumb
	.thumb_func
	.type	main, %function
main:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	mov	r3, #32768
	ldrb	r2, [r3]	@ zero_extendqisi2
	ldrb	r1, [r3, #1]	@ zero_extendqisi2
	cmp	r2, r1
	bls	.L3
	cmp	r2, #32
	bls	.L4
	cmp	r2, #80
	beq	.L9
	movs	r0, #3
	bx	lr
.L3:
	movs	r0, #0
	bx	lr
.L4:
	movs	r0, #2
	bx	lr
.L9:
	cmp	r1, #36
	beq	.L10
	movs	r0, #4
	bx	lr
.L10:
	ldrb	r3, [r3, #2]	@ zero_extendqisi2
	cmp	r3, #54
	ite	eq
	moveq	r0, #6
	movne	r0, #5
	bx	lr
	.size	main, .-main
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",%progbits
