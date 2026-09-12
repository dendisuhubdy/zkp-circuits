# Built with: rustc +1.98.1 --version
# RUSTC_VERSION = rustc 1.98.1 (48a229cea 2026-09-01)

TARGET := riscv32im-unknown-none-elf
ELF := target/$(TARGET)/release/keccak256-guest

# llvm-objcopy is not on PATH; it ships in the toolchain's own sysroot under
# lib/rustlib/<host-triple>/bin/. Resolved with `rustc -vV`/`--print sysroot` rather than a
# hardcoded host triple so the build is reproducible on any machine with the llvm-tools
# component installed, not just aarch64-apple-darwin.
HOST := $(shell rustc +1.98.1 -vV | sed -n 's/host: //p')
SYSROOT := $(shell rustc +1.98.1 --print sysroot)
OBJCOPY := $(SYSROOT)/lib/rustlib/$(HOST)/bin/llvm-objcopy

.PHONY: all clean check-toolchain
all: bin/keccak256.bin bin/keccak256.bin.sha256

check-toolchain:
	rustup +1.98.1 target add $(TARGET)
	rustup +1.98.1 component add llvm-tools

$(ELF): src/main.rs ../../guest-sdk/src/lib.rs ../../guest-sdk/guest.ld .cargo/config.toml Cargo.toml
	cargo +1.98.1 build --release --target $(TARGET)

bin/keccak256.bin: $(ELF)
	mkdir -p bin
	$(OBJCOPY) -O binary $(ELF) $@

bin/keccak256.bin.sha256: bin/keccak256.bin
	cd bin && shasum -a 256 keccak256.bin > keccak256.bin.sha256

clean:
	cargo clean
	rm -rf bin
