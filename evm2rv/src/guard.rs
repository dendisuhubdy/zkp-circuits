//! The code guard: binds a translated image to the bytecode it was translated from.
//!
//! The translated logic is baked into the image, so `hc` binds it. The runtime's `evm_code`,
//! however, is the **input vector's** code, and `CODECOPY` and `CODESIZE` read it. Without a check,
//! one `hc` could run with code bytes the caller chose. So `translate` appends
//! [`code_digest_c`] to `contract.c`: a function returning [`code_digest`] of the source bytecode.
//! Before any translated code runs, the shim hashes the input vector's code the same way and
//! compares. A mismatch is the interpreter's `pre_halt`: `Halt::OutOfBounds`, status 2,
//! `gas_used` 0, since the call never began. This is accepted divergence #3: the interpreter would
//! run the other code, the translation refuses it.
//!
//! **The hash** is the machine's `POSEIDON2` sponge, not Keccak: on the ERC-20 `transfer`
//! (1 296 bytes of code) a Keccak-256 of the code measured +8 798 cycles, a `POSEIDON2` sponge
//! +2 720 with a plain copy loop, and the shim's copy (eight volatile words at a time, as
//! sbpf2rv's ELF guard) is cheaper still.
//!
//! **And it is the only hash of the code the guest computes** (ZKVM-117). `EVM_OUT` carries
//! `keccak256(code)`, which the harness used to compute in the guest after the run — a second
//! pass over the same bytes, ten permutations for the ERC-20. The translator knows the code, so
//! it bakes that Keccak into the image too ([`code_keccak_words`], the second half of the table
//! [`code_digest_c`] emits), and the shim hands it to the harness **only once the guard has
//! passed** (`evm_core::abi::run_call_with_executor_and_codehash`): the guard has then shown the
//! input's code to be the bytes the baked hash is of. When the guard refuses the code the shim
//! says nothing and the harness hashes whatever code it was given, as before, so the refusal's
//! output still names the code that was presented. The baked hash is part of the image, so `hc`
//! binds it; a translator that baked another would produce another `hc`, which is how every other
//! deviation in the translated logic shows.
//!
//! **The message** is [`code_words`]: the code's length in bytes, then the code four bytes per
//! word little-endian, the last word zero-padded. The length is needed: `60` and `6000` pack to
//! the same word. It is hashed as [`chained_digest`] hashes it, in [`DIGEST_CHUNK`]-word
//! `POSEIDON2` calls, because one call takes at most 4 096 words and code may be 24 576 bytes
//! (6 145 words with the length). This is sbpf2rv's `chained_digest`, word for word.

/// Words per `POSEIDON2` call (`isa::POSEIDON2_MAX_WORDS`): the guard hashes its message in chunks
/// of this many words, each after the first beginning with the previous chunk's 8-word digest.
pub const DIGEST_CHUNK: usize = 4096;

/// The guard's message for `code`: its length in bytes, then its bytes four per word little-endian,
/// the last word zero-padded.
pub fn code_words(code: &[u8]) -> Vec<u32> {
    let mut w = Vec::with_capacity(1 + code.len().div_ceil(4));
    w.push(code.len() as u32);
    w.extend(code.chunks(4).map(|c| {
        let mut b = [0u8; 4];
        b[..c.len()].copy_from_slice(c);
        u32::from_le_bytes(b)
    }));
    w
}

/// The `POSEIDON2` sponge over `words`, chained in [`DIGEST_CHUNK`]-word calls: the first over the
/// first 4 096 words, each later one over the previous digest followed by the next 4 088. Exactly
/// what the shim's guard computes, one syscall per chunk.
pub fn chained_digest(words: &[u32]) -> [u32; 8] {
    let first = words.len().min(DIGEST_CHUNK);
    let mut digest = rand_zkvm::hash::sponge_hash(&words[..first]);
    let mut pos = first;
    while pos < words.len() {
        let take = (words.len() - pos).min(DIGEST_CHUNK - 8);
        let mut msg = digest.to_vec();
        msg.extend_from_slice(&words[pos..pos + take]);
        digest = rand_zkvm::hash::sponge_hash(&msg);
        pos += take;
    }
    digest
}

/// The code guard's digest of `code`: [`chained_digest`] of [`code_words`].
pub fn code_digest(code: &[u8]) -> [u32; 8] {
    chained_digest(&code_words(code))
}

/// `keccak256(code)` as the eight words `EVM_OUT` carries it in (`evm_core::abi::hash_words`:
/// `word[i] = LE(bytes[4i..4i+4])`). Baked into the image beside the guard's digest, so that the
/// harness need not hash the code again once the guard has shown the input's code to be this one.
pub fn code_keccak_words(code: &[u8]) -> [u32; 8] {
    let h = rand_zkvm::keccak::keccak256(code);
    std::array::from_fn(|i| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]))
}

/// The C that `translate` appends to `contract.c`: `evm_code_digest()`, returning sixteen words —
/// `digest` (the guard's, [`code_digest`]) and then `keccak` ([`code_keccak_words`]).
///
/// A function rather than a global constant, and its table a function-scope `static`, so that
/// several translations can share one C file with only the function renamed (the tests' host
/// library and multi-contract image do this).
pub fn code_digest_c(digest: &[u32; 8], keccak: &[u32; 8]) -> String {
    let words: Vec<String> = digest.iter().chain(keccak).map(|w| format!("0x{w:08x}u")).collect();
    format!(
        "\n/* The code guard (evm2rv::guard::code_digest): d[0..8] is the digest of the bytecode this file was\n   translated from. Before any of the code above runs, the shim hashes the input vector's code the same\n   way and refuses any other (OutOfBounds, status 2, gas_used 0). d[8..16] is keccak256 of that bytecode\n   as EVM_OUT's eight words: once the guard has passed, the harness publishes it without hashing the\n   code again. */\nconst uint32_t *evm_code_digest(void);\nconst uint32_t *evm_code_digest(void) {{\n    static const uint32_t d[16] = {{{}}};\n    return d;\n}}\n",
        words.join(", ")
    )
}
