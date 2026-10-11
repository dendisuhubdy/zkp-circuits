/* guest-sdk/guest.ld with ORIGIN raised to 0x10000, as evm.ld does: this guest has a .rodata
   (the NTT ZETAS table, 256 words), which the loader writes with a prologue synthesised below
   the text (`Program::from_flat_image`).

   Stack: 64 KiB, unchanged. The measured peak is about 1.3 KB (task 7: the ring arrays live in
   the arena, the pk / sig words in .bss), so the reserve has a wide margin. The 21 KiB ring
   Arena and the 4 KiB of pk / sig words are .bss statics, before the stack, inside the 1 MiB
   RAM. */

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
