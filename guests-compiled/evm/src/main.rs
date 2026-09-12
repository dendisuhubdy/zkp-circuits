#![no_std]
#![no_main]

use evm_core::abi::{run_call, Workspace};
use evm_core::Host;
use guest_sdk::{halt, keccak, poseidon2, read_input, write_output};

/// [`evm_core::Host`] as the machine's two syscalls. Everything else the interpreter needs — the
/// Keccak-256 sponge, the domain-tagged Poseidon2 wrapper, 256-bit arithmetic, the storage tree,
/// the opcode dispatch — is ordinary compiled guest code in `evm-core`, host-tested natively
/// (`research/tests/evm_*.rs`) and compiled here unchanged.
struct Syscalls;

impl Host for Syscalls {
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        keccak(state.as_mut_ptr());
    }
    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        poseidon2(words.as_mut_ptr(), n);
    }
}

/// The whole run's state — the decoded call (code, calldata, storage witnesses) and the
/// interpreter's stack, memory and jumpdest bitmap — in one 146 KiB object. `Workspace::ZERO` is a
/// `const` of all zeros, so this is `.bss`: no image bytes, and nothing on the 64 KiB stack, which
/// a `Workspace` is more than twice the size of. `abi`'s module docs carry the pattern.
static mut W: Workspace = Workspace::ZERO;

/// M4.3's guest: one EVM call. The private input is the vector `abi` lays out
/// (`[n_code, code…, n_calldata, calldata…, address, caller, callvalue, gas_limit, pre_root,
/// n_witnesses, witness…]`); the eight public outputs are `status` and the 224-bit
/// `hash(EVM_OUT, [codehash ‖ pre_root ‖ post_root ‖ return_hash ‖ logs_hash])` that binds the
/// contract, the state-root transition, the return data and the logs.
///
/// `len = u32::MAX` is the honest bound, not a missing check: `read_input` past the `n_in` the
/// proof committed to `H_IN` is unsatisfiable in-circuit (M4.1), so a truncated input vector
/// yields no proof at all rather than a short read — the machine is the cursor's length check.
/// See `evm_core::abi`'s module docs.
#[no_mangle]
pub extern "C" fn main() -> ! {
    // One `&mut` to the `.bss` workspace, taken once and never aliased: `addr_of_mut!` rather
    // than `&mut W` so no reference to the `static mut` is created by the macro itself.
    let w = unsafe { &mut *core::ptr::addr_of_mut!(W) };
    let out = run_call(&mut Syscalls, w, read_input, u32::MAX);
    let mut k = 0;
    while k < 8 {
        write_output(k as u32, out[k]);
        k += 1;
    }
    halt();
}
