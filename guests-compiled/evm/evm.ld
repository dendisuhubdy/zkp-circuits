/* guest-sdk/guest.ld with one change: ORIGIN is 0x10000 rather than 0x1000, leaving 0xf000 bytes
   (15 360 instructions) of program space below the text for the data prologue the loader
   synthesises (`Program::from_flat_image`, research/docs/01-isa.md). This guest's .rodata is
   2 428 bytes — jump tables, panic locations, the constants LLVM materialised — i.e. 607 words of
   which 585 are non-zero, costing 1 630 prologue instructions, so the room reserved here is about
   nine times what is needed.

   A guest with no data segment needs none of this and keeps using guest-sdk/guest.ld unchanged:
   its prologue is empty and its text stays at 0x1000 (`tests/isa.rs`'s
   `an_empty_data_segment_gives_exactly_the_flat_binary_program_and_hc`). */

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
