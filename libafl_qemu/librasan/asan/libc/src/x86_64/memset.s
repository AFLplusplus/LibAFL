/*
 * https://git.musl-libc.org/cgit/musl/tree/src/string/x86_64/memset.s?h=v1.2.5
 *
 * This file has been copied from musl v1.2.5, which is licensed under the
 * following license:
 *
 * Copyright © 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

.global memset
.type memset,@function
memset:
	movzbq %sil,%rax
	mov $0x101010101010101,%r8
	imul %r8,%rax

	cmp $126,%rdx
	ja 2f

	test %edx,%edx
	jz 1f

	mov %sil,(%rdi)
	mov %sil,-1(%rdi,%rdx)
	cmp $2,%edx
	jbe 1f

	mov %ax,1(%rdi)
	mov %ax,(-1-2)(%rdi,%rdx)
	cmp $6,%edx
	jbe 1f

	mov %eax,(1+2)(%rdi)
	mov %eax,(-1-2-4)(%rdi,%rdx)
	cmp $14,%edx
	jbe 1f

	mov %rax,(1+2+4)(%rdi)
	mov %rax,(-1-2-4-8)(%rdi,%rdx)
	cmp $30,%edx
	jbe 1f

	mov %rax,(1+2+4+8)(%rdi)
	mov %rax,(1+2+4+8+8)(%rdi)
	mov %rax,(-1-2-4-8-16)(%rdi,%rdx)
	mov %rax,(-1-2-4-8-8)(%rdi,%rdx)
	cmp $62,%edx
	jbe 1f

	mov %rax,(1+2+4+8+16)(%rdi)
	mov %rax,(1+2+4+8+16+8)(%rdi)
	mov %rax,(1+2+4+8+16+16)(%rdi)
	mov %rax,(1+2+4+8+16+24)(%rdi)
	mov %rax,(-1-2-4-8-16-32)(%rdi,%rdx)
	mov %rax,(-1-2-4-8-16-24)(%rdi,%rdx)
	mov %rax,(-1-2-4-8-16-16)(%rdi,%rdx)
	mov %rax,(-1-2-4-8-16-8)(%rdi,%rdx)

1:	mov %rdi,%rax
	ret

2:	test $15,%edi
	mov %rdi,%r8
	mov %rax,-8(%rdi,%rdx)
	mov %rdx,%rcx
	jnz 2f

1:	shr $3,%rcx
	rep
	stosq
	mov %r8,%rax
	ret

2:	xor %edx,%edx
	sub %edi,%edx
	and $15,%edx
	mov %rax,(%rdi)
	mov %rax,8(%rdi)
	sub %rdx,%rcx
	add %rdx,%rdi
	jmp 1b
