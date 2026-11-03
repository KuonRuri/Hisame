OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80200000, LENGTH = 16M
}

SECTIONS {
    . = ORIGIN(RAM);
    .text : {
        KEEP(*(.text.entry))
        KEEP(*(.text.trap))
        *(.text .text.*)
    } > RAM
    .rodata : ALIGN(8) { *(.rodata .rodata.*) } > RAM
    .data : ALIGN(8) { *(.data .data.*) } > RAM
    .bss : ALIGN(8) {
        __bss_start = .;
        *(.bss .bss.*)
        __bss_end = .;
    } > RAM
    . = ALIGN(4096);
    . += 16K;
    __stack_top = .;
    /DISCARD/ : { *(.eh_frame) *(.note*) *(.comment*) }
}
