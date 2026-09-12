# Built with: rustc +1.98.1 --version
# RUSTC_VERSION = rustc 1.98.1 (48a229cea 2026-09-01)

TARGET := riscv32im-unknown-none-elf
ELF := target/$(TARGET)/release/evm-guest

# llvm-objcopy is not on PATH; it ships in the toolchain's own sysroot under
# lib/rustlib/<host-triple>/bin/. Resolved with `rustc -vV`/`--print sysroot` rather than a
# hardcoded host triple so the build is reproducible on any machine with the llvm-tools
# component installed, not just aarch64-apple-darwin.
HOST := $(shell rustc +1.98.1 -vV | sed -n 's/host: //p')
SYSROOT := $(shell rustc +1.98.1 --print sysroot)
OBJCOPY := $(SYSROOT)/lib/rustlib/$(HOST)/bin/llvm-objcopy

# `contracts` only: the pinned compiler of contracts/SOLC.md, overridable as
# `SOLC=/path/to/solc make contracts`. Nothing else in this Makefile — and no test anywhere —
# needs a solc at all; the runtime bytecode is committed.
SOLC ?= solc
SOLC_FLAGS := --optimize --optimize-runs 200 --evm-version shanghai --bin-runtime

.PHONY: all clean check-toolchain contracts
all: bin/evm.bin bin/evm.bin.sha256

check-toolchain:
	rustup +1.98.1 target add $(TARGET)
	rustup +1.98.1 component add llvm-tools

$(ELF): src/main.rs ../evm-core/src/*.rs ../../guest-sdk/src/lib.rs ../../guest-sdk/guest.ld .cargo/config.toml Cargo.toml
	cargo +1.98.1 build --release --target $(TARGET)

bin/evm.bin: $(ELF)
	mkdir -p bin
	$(OBJCOPY) -O binary $(ELF) $@

bin/evm.bin.sha256: bin/evm.bin
	cd bin && shasum -a 256 evm.bin > evm.bin.sha256

# Recompile ERC20.sol and diff against the committed runtime bytecode. Requires a solc of the
# version contracts/SOLC.md pins (a different 0.8.x optimises differently and will differ); skipped
# with a message when none is on PATH, so it is safe to run anywhere.
contracts:
	@if ! command -v $(SOLC) >/dev/null 2>&1; then \
		echo "contracts: no '$(SOLC)' on PATH — see contracts/SOLC.md for the pinned binary; nothing to check"; \
	else \
		$(SOLC) --version | tail -1; \
		$(SOLC) $(SOLC_FLAGS) contracts/ERC20.sol | tail -1 > /tmp/erc20.runtime.hex; \
		diff -u contracts/erc20.runtime.hex /tmp/erc20.runtime.hex && \
			echo "contracts: erc20.runtime.hex reproduces"; \
	fi

clean:
	cargo clean
	rm -rf bin
