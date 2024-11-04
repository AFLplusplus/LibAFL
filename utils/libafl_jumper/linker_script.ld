MEMORY
{
  FLASH    (rx)    : ORIGIN = 0x20001000,   LENGTH = 512K
  RAM    (xrw)    : ORIGIN = 0x21000000,   LENGTH = 64K
}

SECTIONS
{
    .text : { *(.text*) } > FLASH
    .rodata : { *(.rodata*) } > FLASH
    .bss : { *(.bss*) } > RAM
}