# Built with: rustc +1.98.1 --version
# RUSTC_VERSION = rustc 1.98.1 (48a229cea 2026-09-01)

TARGET := riscv32im-unknown-none-elf
ELF := target/$(TARGET)/release/sbpf-guest

# The whole rustflags set for this guest, passed through `cargo --config` rather than written in
# .cargo/config.toml, because the remap below needs this checkout's absolute path (see that file):
#
#  * -Tsbpf.ld         this guest's linker script: guest.ld with ORIGIN raised to 0x10000, leaving
#                      room below the text for the data prologue the loader synthesises.
#  * target-feature    a misaligned load/store is a constraint violation in this machine
#                      (research/docs/01-isa.md), so the compiler must never assume otherwise.
#  * remap-path-prefix makes the panic `Location` paths in .rodata independent of where this
#                      checkout lives, so `bin/sbpf.bin` reproduces byte for byte on any machine.
ROOT := $(shell cd ../.. && pwd)
RUSTFLAGS_LIST := ["-C","link-arg=-Tsbpf.ld","-C","target-feature=-unaligned-scalar-mem","--remap-path-prefix=$(ROOT)=/rand-circuits"]
CARGO_CONFIG := --config 'target.$(TARGET).rustflags=$(RUSTFLAGS_LIST)'

HOST := $(shell rustc +1.98.1 -vV | sed -n 's/host: //p')
SYSROOT := $(shell rustc +1.98.1 --print sysroot)
OBJDUMP := $(SYSROOT)/lib/rustlib/$(HOST)/bin/llvm-objdump

.PHONY: all clean check-toolchain install program
all: bin/sbpf.bin bin/sbpf.bin.sha256

# The copy that matters: `research/src/guests.rs` includes `guests-compiled/bin/sbpf.bin`, so a
# rebuild is only in effect once it lands there. `make install` is the one step that moves it, so
# nobody has to remember the `cp` (and measure a stale binary).
install: all
	cp bin/sbpf.bin bin/sbpf.bin.sha256 ../bin/

check-toolchain:
	rustup +1.98.1 target add $(TARGET)
	rustup +1.98.1 component add llvm-tools

$(ELF): src/main.rs ../sbpf-core/src/*.rs ../../guest-sdk/src/lib.rs sbpf.ld .cargo/config.toml Cargo.toml Makefile
	cargo +1.98.1 build --release --target $(TARGET) $(CARGO_CONFIG)

# Not `objcopy -O binary`: this guest has a data segment (.rodata — the `Halt::Trap` literals, the
# panic locations, the opcode dispatch's jump tables), and a flat image can only carry
# instructions. The image container (`../mkimage.py`, `Program::from_flat_image`) carries `.text`
# *and* the data, and the loader writes the data into RAM with a prologue it synthesises, so `hc`
# binds it.
bin/sbpf.bin: $(ELF) ../mkimage.py
	mkdir -p bin
	python3 ../mkimage.py $(ELF) $@

bin/sbpf.bin.sha256: bin/sbpf.bin
	cd bin && shasum -a 256 sbpf.bin > sbpf.bin.sha256

# Re-check the committed SPL Token ELF against its own sha256. The file is *fetched*, not built —
# there is no Solana toolchain on the build machines — so this is the only reproducibility check
# there is, and `programs/SPL_TOKEN.md` records the RPC call that produced it.
program:
	cd programs && shasum -a 256 -c spl_token.so.sha256

clean:
	cargo clean
	rm -rf bin
