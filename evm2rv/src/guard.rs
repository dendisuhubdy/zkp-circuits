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
//! **The hash** is the machine's `POSEIDON2` sponge, not Keccak. The harness does hash the code
//! with Keccak for `EVM_OUT`, but only after the executor returns (`evm_core::abi::public_output`),
//! and reusing that hash would need an `evm-core` change, which would move the pinned `evm.bin`.
//! So the guard hashes once more, with the cheaper coprocessor hash. On the ERC-20 `transfer`
//! (1 296 bytes of code) a Keccak-256 of the code measured +8 798 cycles, a `POSEIDON2` sponge
//! +2 720 with a plain copy loop; the shim's copy (eight volatile words at a time, as sbpf2rv's
//! ELF guard) is cheaper still.
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

/// The C that `translate` appends to `contract.c`: `evm_code_digest()`, returning `digest`.
///
/// A function rather than a global constant, and its table a function-scope `static`, so that
/// several translations can share one C file with only the function renamed (the tests' host
/// library and multi-contract image do this).
pub fn code_digest_c(digest: &[u32; 8]) -> String {
    let words: Vec<String> = digest.iter().map(|w| format!("0x{w:08x}u")).collect();
    format!(
        "\n/* The code guard (evm2rv::guard::code_digest): the digest of the bytecode this file was translated\n   from. Before any of the code above runs, the shim hashes the input vector's code the same way and\n   refuses any other (OutOfBounds, status 2, gas_used 0). */\nconst uint32_t *evm_code_digest(void);\nconst uint32_t *evm_code_digest(void) {{\n    static const uint32_t d[8] = {{{}}};\n    return d;\n}}\n",
        words.join(", ")
    )
}
