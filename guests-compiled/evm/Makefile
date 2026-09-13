# Built with: rustc +1.98.1 --version
# RUSTC_VERSION = rustc 1.98.1 (48a229cea 2026-09-01)

TARGET := riscv32im-unknown-none-elf
ELF := target/$(TARGET)/release/evm-guest

# The whole rustflags set for this guest, passed through `cargo --config` rather than written in
# .cargo/config.toml, because the remap below needs this checkout's absolute path (see that file):
#
#  * -Tevm.ld          this guest's linker script: guest.ld with ORIGIN raised to 0x10000, leaving
#                      room below the text for the data prologue the loader synthesises.
#  * target-feature    a misaligned load/store is a constraint violation in this machine
#                      (research/docs/01-isa.md), so the compiler must never assume otherwise.
#  * remap-path-prefix makes the panic `Location` paths in .rodata independent of where this
#                      checkout lives, so `bin/evm.bin` reproduces byte for byte on any machine.
#
# Note what is *not* here: nothing suppresses the opcode dispatch's jump tables. Before the image
# container existed they had to be suppressed (`-C llvm-args=-max-jump-table-size=1`), because a
# jump table in an unloadable `.rodata` means a jump to `pc 0`. With the container carrying them
# they are simply faster, measured both ways on the ERC-20 transfer: 121 763 executed cycles and
# 17 983 program words with the tables (126 491 all in, counting the digest prefixes) against
# 123 659 and 17 065 with the compare-and-branch chain (128 158 all in) — the tables cost ~900 more
# program words and save ~1 900 execution cycles. (Both figures are from the same build pair; the
# committed image is ~130 cycles cheaper again after a later `storage.rs` tidy-up.)
ROOT := $(shell cd ../.. && pwd)
RUSTFLAGS_LIST := ["-C","link-arg=-Tevm.ld","-C","target-feature=-unaligned-scalar-mem","--remap-path-prefix=$(ROOT)=/rand-circuits"]
CARGO_CONFIG := --config 'target.$(TARGET).rustflags=$(RUSTFLAGS_LIST)'

# `contracts` only: the pinned compiler of contracts/SOLC.md, overridable as
# `SOLC=/path/to/solc make contracts`. Nothing else in this Makefile — and no test anywhere —
# needs a solc at all; the runtime bytecode is committed.
SOLC ?= solc
SOLC_FLAGS := --optimize --optimize-runs 200 --evm-version shanghai --bin-runtime
# The pinned version, asserted before the compile: a different 0.8.x optimises differently, so a
# silent version drift would show up as a mystifying hex diff rather than as the real problem.
SOLC_VERSION := 0.8.37

.PHONY: all clean check-toolchain contracts install
all: bin/evm.bin bin/evm.bin.sha256

# The copy that matters: `research/src/guests.rs` includes `guests-compiled/bin/evm.bin`, so a
# rebuild is only in effect once it lands there. `make install` is the one step that moves it, so
# nobody has to remember the `cp` (and measure a stale binary, as happened once).
install: all
	cp bin/evm.bin bin/evm.bin.sha256 ../bin/

check-toolchain:
	rustup +1.98.1 target add $(TARGET)
	rustup +1.98.1 component add llvm-tools

$(ELF): src/main.rs ../evm-core/src/*.rs ../../guest-sdk/src/lib.rs evm.ld .cargo/config.toml Cargo.toml Cargo.lock Makefile
	cargo +1.98.1 build --release --target $(TARGET) $(CARGO_CONFIG)

# Not `objcopy -O binary`: this guest has a data segment (.rodata — jump-table-free but still panic
# locations and the constants LLVM materialised), and a flat image can only carry instructions. The
# image container (`mkimage.py`, `Program::from_flat_image`) carries `.text` *and* the data, and the
# loader writes the data into RAM with a prologue it synthesises, so `hc` binds it.
bin/evm.bin: $(ELF) ../mkimage.py
	mkdir -p bin
	python3 ../mkimage.py $(ELF) $@

bin/evm.bin.sha256: bin/evm.bin
	cd bin && shasum -a 256 evm.bin > evm.bin.sha256

# Recompile ERC20.sol and diff against the committed runtime bytecode. Needs the exact solc
# contracts/SOLC.md pins — a different 0.8.x optimises differently and the hex will differ, so the
# version is asserted rather than trusted. With no solc on PATH the target says so and succeeds, so
# it is safe to run anywhere; no test needs it.
contracts:
	@if ! command -v $(SOLC) >/dev/null 2>&1; then \
		echo "contracts: no '$(SOLC)' on PATH — see contracts/SOLC.md for the pinned binary; nothing to check"; \
	else \
		v=$$($(SOLC) --version | tail -1); \
		echo "contracts: $$v"; \
		case "$$v" in *"$(SOLC_VERSION)"*) ;; *) \
			echo "contracts: FAIL — this is not the pinned solc $(SOLC_VERSION) (contracts/SOLC.md); its output will differ" >&2; \
			exit 1 ;; \
		esac; \
		tmp=$$(mktemp -t erc20.runtime.hex); \
		trap 'rm -f "$$tmp"' EXIT INT TERM; \
		$(SOLC) $(SOLC_FLAGS) contracts/ERC20.sol | tail -1 > "$$tmp"; \
		diff -u contracts/erc20.runtime.hex "$$tmp" && \
			echo "contracts: erc20.runtime.hex reproduces"; \
	fi

clean:
	cargo clean
	rm -rf bin
