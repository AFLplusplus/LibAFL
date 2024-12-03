[bits 16] ; use 16 bits 
[org 0x7c00] ; sets the start address 

_start:
    mov dx, [0x041e]    ; BIOS Data Area (BDA) keyboard buffer
    mov cx, [0x0420]

    mov ah, 0x0E
    mov al, dh
    int 0x10
    mov al, dl
    int 0x10
    mov al, ch
    int 0x10
    mov al, cl
    int 0x10
    mov al, 0x0d    ; CR
    int 0x10
    mov al, 0x0a    ; LF
    int 0x10

    cmp dh, 'a'
    jne sleep_forever
    cmp dl, 'b'
    jne sleep_forever
    cmp ch, 'c'
    jne sleep_forever

loop:
    add cx, 1
    cmp cx, 'a'
    jne loop
    add cx, 1

shutdown:
    ; say bye to user
    mov ah, 0x0E
    mov al, 'B'
    int 0x10
    mov al, 'y'
    int 0x10
    mov al, 'e'
    int 0x10
    mov al, '!'
    int 0x10
    mov al, 0x0d    ; CR
    int 0x10
    mov al, 0x0a    ; LF
    int 0x10

    ; sleep a bit to make sure output is printed
    xor cx, cx
    mov dx, 0xffff
    mov ah, 0x86
    int 0x15

    ; actual shutdown
    mov ax, 0x1000
    mov ax, ss
    mov sp, 0xf000
    mov ax, 0x5307
    mov bx, 0x0001
    mov cx, 0x0003
    int 0x15

sleep_forever:
    mov cx, 0xffff
    mov dx, 0xffff
    mov ah, 0x86
    int 0x15
    jmp sleep_forever

times 510-($-$$) db 0 ; fill the output file with zeroes until 510 bytes are full 

dw 0xaa55 ; magic bytes that tell BIOS that this is bootable
