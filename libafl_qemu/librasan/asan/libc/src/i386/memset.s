/*
 * https://git.musl-libc.org/cgit/musl/tree/src/string/i386/memset.s?h=v1.2.5
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
	mov 12(%esp),%ecx
	cmp $62,%ecx
	ja 2f

	mov 8(%esp),%dl
	mov 4(%esp),%eax
	test %ecx,%ecx
	jz 1f

	mov %dl,%dh

	mov %dl,(%eax)
	mov %dl,-1(%eax,%ecx)
	cmp $2,%ecx
	jbe 1f

	mov %dx,1(%eax)
	mov %dx,(-1-2)(%eax,%ecx)
	cmp $6,%ecx
	jbe 1f

	shl $16,%edx
	mov 8(%esp),%dl
	mov 8(%esp),%dh

	mov %edx,(1+2)(%eax)
	mov %edx,(-1-2-4)(%eax,%ecx)
	cmp $14,%ecx
	jbe 1f

	mov %edx,(1+2+4)(%eax)
	mov %edx,(1+2+4+4)(%eax)
	mov %edx,(-1-2-4-8)(%eax,%ecx)
	mov %edx,(-1-2-4-4)(%eax,%ecx)
	cmp $30,%ecx
	jbe 1f

	mov %edx,(1+2+4+8)(%eax)
	mov %edx,(1+2+4+8+4)(%eax)
	mov %edx,(1+2+4+8+8)(%eax)
	mov %edx,(1+2+4+8+12)(%eax)
	mov %edx,(-1-2-4-8-16)(%eax,%ecx)
	mov %edx,(-1-2-4-8-12)(%eax,%ecx)
	mov %edx,(-1-2-4-8-8)(%eax,%ecx)
	mov %edx,(-1-2-4-8-4)(%eax,%ecx)

1:	ret 	

2:	movzbl 8(%esp),%eax
	mov %edi,12(%esp)
	imul $0x1010101,%eax
	mov 4(%esp),%edi
	test $15,%edi
	mov %eax,-4(%edi,%ecx)
	jnz 2f

1:	shr $2, %ecx
	rep
	stosl
	mov 4(%esp),%eax
	mov 12(%esp),%edi
	ret
	
2:	xor %edx,%edx
	sub %edi,%edx
	and $15,%edx
	mov %eax,(%edi)
	mov %eax,4(%edi)
	mov %eax,8(%edi)
	mov %eax,12(%edi)
	sub %edx,%ecx
	add %edx,%edi
	jmp 1b
