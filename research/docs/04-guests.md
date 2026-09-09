# Guests: how Solidity and Solana enter R_exec

Only RISC-V executes natively in this machine. The other two chains the
protocol targets run as *software inside it*: an interpreter for their
bytecode, compiled to RV32IM like any other guest, with the target program's
own bytecode passed in as private input. Publishing a "confidential
contract" is registering `hc` for the interpreter plus a commitment to the
bytecode — never generating a new circuit per contract. This is the same
choice the whitepaper makes for its zkVM comparison.

## The Solidity path

`solc` compiles a contract to EVM bytecode as it always would. A `no_std`
EVM interpreter, itself compiled to RV32IM, receives that bytecode (as
private input, via `READ_INPUT`) and the call's calldata, and executes it
opcode by opcode inside the guest. Cheap opcodes (arithmetic, stack, memory,
control flow) map onto a handful of native RV32IM instructions each; the
expensive ones need dedicated coprocessor tables rather than a naive
byte-by-byte simulation, or Solidity guests would be orders of magnitude
slower than the RISC-V native path:

| EVM opcode(s) | Coprocessor needed | Notes |
|---|---|---|
| `KECCAK256` | Keccak-f\[1600\] table | `p3-keccak-air` already exists upstream and can be added as a sixth chip |
| `ADDMOD`, `MULMOD`, `EXP` | 256-bit modular arithmetic | native words are 32-bit; a 256-bit value is eight limbs, and mulmod/expmod need a dedicated multi-limb multiplier, not four chained 32-bit ALU ops |
| `ECRECOVER` (and any signature-checking precompile) | secp256k1 recovery | needs field/group arithmetic over a non-Goldilocks curve; this is exactly the CPI/secp256k1 gap noted for `randprotocol-svm` and is shared work |
| `SLOAD`/`SSTORE` | Merkle-witness syscalls | EVM storage is a sparse Merkle tree keyed by 256-bit slots; each access becomes a `MERKLE_VERIFY`-style syscall against a public state root, which is milestone 3 machinery, not milestone 4's |

## The Solana path

An sBPF ELF (the compiled form of an SPL program) is interpreted the same
way: an sBPF interpreter compiled to RV32IM, ELF bytes as private input.
sBPF is itself a small load/store ISA — 11 general registers, 64-bit
values — so unlike the EVM's stack machine, a direct sBPF→RV32 *translator*
(compiling sBPF instructions to native RV32IM ahead of execution, rather
than interpreting them one at a time) is a natural later optimisation once
correctness is established through the interpreter. Coprocessors this path
wants:

| SVM primitive | Coprocessor needed | Notes |
|---|---|---|
| `sol_sha256` | SHA-256 table | same shape of problem as Keccak: a fixed permutation run many times |
| `sol_ed25519` verify | Ed25519 | needed for signature-verifying programs; today's `randprotocol-svm` has no secp256k1 *or* Ed25519 support and no Instructions sysvar, which blocks this and the bridge use case alike |
| 64-bit multiply/shift | limb doubling | every sBPF register is 64 bits; each op costs roughly two RV32 operations interpreted, the RV64-vs-RV32 tradeoff from `docs/01-isa.md` showing up concretely here |

## Estimated cycle multipliers

Rough, not measured (no interpreter exists yet): a native RV32IM instruction
costs 1 cycle by definition. An interpreted EVM opcode costs on the order of
5–20 cycles (fetch bytecode byte, dispatch, execute — mostly dispatch
overhead for cheap opcodes); an interpreted sBPF instruction costs on the
order of 2–5 cycles for arithmetic (mostly the 64-bit-as-two-32-bit tax) but
1 for anything already word-sized. `KECCAK256`/`SHA-256`/`ECRECOVER`/
`sol_ed25519` are each worth thousands of native cycles if simulated
bit-by-bit — which is exactly why each needs its own AIR table rather than
running through the general-purpose ALU.

## What milestone 4 builds first

The EVM interpreter, because it is the more immediately useful target (an
ERC-20 `transfer` proving under `R_exec` is the milestone's own exit
criterion) and because `p3-keccak-air` already existing upstream removes the
single largest unknown. The sBPF interpreter and its coprocessors follow
once the general "interpreter guest + coprocessor table" pattern is proven
out once, on the EVM.
