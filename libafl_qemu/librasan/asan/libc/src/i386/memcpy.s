/*
 * https://git.musl-libc.org/cgit/musl/tree/src/string/i386/memcpy.s?h=v1.2.5
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

.global memcpy
.global __memcpy_fwd
.hidden __memcpy_fwd
.type memcpy,@function
memcpy:
__memcpy_fwd:
	push %esi
	push %edi
	mov 12(%esp),%edi
	mov 16(%esp),%esi
	mov 20(%esp),%ecx
	mov %edi,%eax
	cmp $4,%ecx
	jc 1f
	test $3,%edi
	jz 1f
2:	movsb
	dec %ecx
	test $3,%edi
	jnz 2b
1:	mov %ecx,%edx
	shr $2,%ecx
	rep
	movsl
	and $3,%edx
	jz 1f
2:	movsb
	dec %edx
	jnz 2b
1:	pop %edi
	pop %esi
	ret
