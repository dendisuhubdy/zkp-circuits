/* guest-sdk/guest.ld with ORIGIN raised to 0x10000, as dilithium-verify.ld does: the guest links
   dilithium-core's .rodata (the NTT ZETAS table), which the loader writes with a prologue
   synthesised below the text (`Program::from_flat_image`).

   Stack: 64 KiB. dilithium_core::verify's frame is about 24 KB on RV32; `main` adds the pk/sig
   byte arrays (3.7 KB), the 328-word pk buffer, the 330-word hash buffer and the message, so
   the measured peak (task-5 report) stays well under half the reserve. Nothing is in statics. */

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
