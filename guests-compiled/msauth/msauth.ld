/* guest-sdk/guest.ld with ORIGIN raised to 0x10000, as dilithium-verify.ld does: the guest
   links dilithium-core's .rodata (the NTT ZETAS table), which the loader writes with a prologue
   synthesised below the text (`Program::from_flat_image`).

   Stack: 64 KiB. The measured peak is about 2.7 KB (the 330-word hash buffer, the message and
   the verifier's frame; `cycles_at_one_two_and_three_signers` prints it), so the reserve has a
   wide margin. The 21 KiB ring Arena and the pk / sig words are .bss statics, before the stack,
   inside the 1 MiB RAM. */

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
