/* guest-sdk/guest.ld with ORIGIN raised to 0x10000, as guests-compiled/evm/evm.ld does and for its
   reason: the software Ed25519 carries SHA-512's 640-byte round-constant table and both curves'
   constants in .rodata, which the loader turns into a data prologue that must fit below the text
   (`Program::from_flat_image`; at ORIGIN 0x1000 there is room for 1 024 prologue words only). */
ENTRY(_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x10000, LENGTH = 0x00100000
}

SECTIONS {
  . = 0x10000;
  .text : {
    *(.text._start)
    *(.text .text.*)
  } > RAM
  .rodata : { *(.rodata .rodata.*) } > RAM
  .data : { *(.data .data.*) } > RAM
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } > RAM
  . = ALIGN(16); /* RISC-V psABI: sp must be 16-byte aligned */
  . = . + 0x10000; /* 64 KiB stack */
  __stack_top = .;
  /DISCARD/ : { *(.comment) *(.eh_frame*) *(.riscv.attributes) *(.note*) }
}
