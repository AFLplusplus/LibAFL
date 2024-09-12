[bits 16] ; use 16 bits 
[org 0x7c00] ; sets the start address 

_start:
    mov cx, 0

bye:    
    mov ah, 0x0E    ; BIOS teletype function
    mov al, 'B'
    int 0x10
    mov al, 'y'
    int 0x10
    mov al, 'e'
    int 0x10
    mov al, '!'
    int 0x10

loop:
    add cx, 1
    cmp cx, 0xff
    jne loop
    add cx, 1
    mov al, cl
    add al, 0x20
    mov ah, 0x7c
    jmp ax ; will this be traced as a full address? yes

times 0x50 db 0x90 ; nop sled

shutdown:
    mov ax, 0x1000
    mov ax, ss
    mov sp, 0xf000
    mov ax, 0x5307
    mov bx, 0x0001
    mov cx, 0x0003
    int 0x15

times 510-($-$$) db 0 ; fill the output file with zeroes until 510 bytes are full 

dw 0xaa55 ; magic bytes that tell BIOS that this is bootable
