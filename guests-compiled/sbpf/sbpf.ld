/* guest-sdk/guest.ld with one change: ORIGIN is 0x10000 rather than 0x1000, leaving 0xf000 bytes
   (15 360 instructions) of program space below the text for the data prologue the loader
   synthesises (`Program::from_flat_image`, research/docs/01-isa.md). This guest's `.rodata` is
   the `Halt::Trap(&'static str)` literals, the panic `Location`s and the opcode dispatch's jump
   tables; the Makefile prints its size at every build and `make` fails with
   `LoadError::PrologueRoom` long before the room here runs out.

   The 1 MiB RAM has to hold `abi::Workspace` in `.bss` — a 256 KiB ELF buffer, the 48 KiB
   instruction region, the 32 KiB sBPF stack and the 32 KiB heap, 368 KiB in all — plus this
   guest's own code and the 64 KiB RV32 stack below. */

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
