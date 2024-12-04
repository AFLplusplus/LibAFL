[bits 16] ; use 16 bits 
[org 0x7c00] ; sets the start address

%macro print_string 1   ; %1: Pointer to the string (null-terminated)
    mov si, %1          ; Load the pointer to the string
.print_char:
    lodsb               ; Load the next byte from [SI] into AL
    or al, al           ; Check if it's the null terminator
    jz .done            ; If zero, we are done
    mov ah, 0x0E        ; BIOS teletype function
    int 0x10            ; Call BIOS interrupt
    jmp .print_char     ; Repeat for the next character
.done:
    mov al, 0x0d        ; CR
    int 0x10
    mov al, 0x0a        ; LF
    int 0x10
%endmacro

start:
    mov ah, 0xc0
    int 0x15            ; ask for the system configuration parameters
    jc fail             ; carry must be 0
    cmp ah, 0           ; ah must be 0
    jne fail

    mov ax, [es:bx]     ; byte count
    cmp ax, 8
    jl fail

    mov ch, [es:bx + 2] ; Model
    mov cl, [es:bx + 3] ; Submodel
    mov dh, [es:bx + 4] ; BIOS revision

    cmp ch, 'a'
    jne fail
    cmp cl, 'b'
    jne fail
    cmp dh, 'c'
    jne fail

shutdown:
    print_string bye

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

fail:
    print_string fail_msg
sleep_forever:
    mov cx, 0xffff
    mov dx, 0xffff
    mov ah, 0x86
    int 0x15
    jmp sleep_forever

fail_msg db "I don't like your BIOS. :(", 0
bye db "Amazing <3 Bye!", 0

times 510-($-$$) db 0   ; fill the output file with zeroes until 510 bytes are full

dw 0xaa55               ; magic bytes that tell BIOS that this is bootable
