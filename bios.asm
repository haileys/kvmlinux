bits 16
org 0

%define MMIO_KVMLINUX_INT       0xff000

%macro isr 1
    push word %1
    jmp isr_common
    ; pad out ISR to 8 bytes - supervisor relies on this for ISR address
    nop
    nop
    nop
%endmacro

; generate ISRs
%assign nr 0
%rep 256
    isr nr
    %assign nr nr+1
%endrep

isr_common:
    ; don't clobber es or bx
    push es
    push bx

    ; load MMIO segment
    mov bx, MMIO_KVMLINUX_INT >> 4
    mov es, bx

    ; pull interrupt number from up stack and write to mmio
    mov bx, sp
    mov bx, [bx + 4]
    mov [es:0], bx

    ; restore es and bx
    pop bx
    pop es

    ; balance stack and return
    add sp, 2
    iret
