/* guest-sdk/guest.ld with ORIGIN raised to 0x10000, as evm.ld does: this guest has a .rodata (the
   NTT ZETAS table, 256 words), which the loader writes with a prologue synthesised below the text
   (`Program::from_flat_image`).

   Stack: 64 KiB, unchanged. dilithium_core::verify's measured frame is about 24 KB on RV32 and
   `main` adds the pk/sig/msg buffers (about 4 KB), so the stack peaks near 28 KB; the 64 KiB
   the SDK script reserves has more than 2x headroom and nothing is kept in statics. */

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
