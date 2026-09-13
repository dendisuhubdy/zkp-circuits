# `spl_token.so` — provenance

The SPL Token program's sBPF ELF, fetched once from Solana mainnet-beta and committed. There is no
Solana toolchain on the build machines (`cargo build-sbf`), so the on-chain bytes are the canonical
artifact and this file plus `spl_token.so.sha256` are the whole reproducibility story. Re-check the
committed file at any time with `make program` in the parent directory.

| | |
|---|---|
| program id | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| program-data account | `3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2` |
| owner (loader) | `BPFLoaderUpgradeab1e11111111111111111111111` |
| upgrade authority | **none** — the program is immutable |
| deployed at slot | 419 472 000 |
| fetched at slot | 446 590 705 (2026-09-13) |
| endpoint | `https://api.mainnet-beta.solana.com` |
| size | 108 600 bytes |
| sha256 | `8190d3f7ceb6cb7a7a8d8924bff89f9f611e15ce1f806f2b6237f3311a98f697` |

## Not BPFLoader2: what the fetch actually found

The M4.4 plan expected a **non-upgradeable `BPFLoader2111111111111111111111111111111111`** program,
whose account data *is* the ELF, and gave this one-liner:

```sh
curl -s https://api.mainnet-beta.solana.com -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",{"encoding":"base64"}]}' \
  | jq -r '.result.value.data[0]' | base64 -d > programs/spl_token.so
```

That is not what the account holds. `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` is owned by the
**upgradeable** loader, and its 36 bytes of data are an `UpgradeableLoaderState::Program` — a 4-byte
little-endian enum tag (`2`) followed by the program-data account's 32-byte pubkey. So the fetch is
two calls, and the second one's data carries a header the ELF sits behind:

```sh
# 1. the program account -> the program-data address
curl -s https://api.mainnet-beta.solana.com -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",{"encoding":"base64"}]}' \
  > program.json
# tag 2 = Program { programdata_address }; bytes 4..36 are that pubkey, base58-encoded
# -> 3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2

# 2. the program-data account, minus its 45-byte header
curl -s https://api.mainnet-beta.solana.com -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2",{"encoding":"base64"}]}' \
  | jq -r '.result.value.data[0]' | base64 -d | tail -c +46 > spl_token.so
shasum -a 256 spl_token.so > spl_token.so.sha256
```

The header is `UpgradeableLoaderState::ProgramData`: the 4-byte tag (`3`), the 8-byte deployment
slot, and `Option<Pubkey> upgrade_authority_address`. Agave reserves a **fixed 45 bytes** for it
(`UpgradeableLoaderState::size_of_programdata_metadata()`) whatever the option is, so the ELF always
starts at offset 45 — which is where `\x7fELF` was found, with the option byte `0` and the 32 pubkey
bytes left as zeros. A `None` upgrade authority means the authority has been revoked: the program is
immutable in practice, which is what made the plan's "non-upgradeable" reasoning right about the
thing that matters (these bytes cannot change under us) and wrong only about the loader.

The account's data is 108 645 bytes, i.e. exactly 45 + 108 600 with no `--max-len` slack, and the
ELF's own section header table ends at byte 108 600, so nothing was trimmed or padded.

## What the file is

An `ET_DYN`, `EM_BPF` (machine 263), little-endian ELF64, stripped, `e_flags = 0` (so **not** the
reserved `0x20` v2 format), `e_entry = 0x828`. Nine sections; `.text`, `.rodata` and `.data.rel.ro`
form one contiguous run at `sh_addr == sh_offset`, which is the borrow path
`sbpf_core::elf::load` implements:

| section | type | addr = offset | size |
|---|---|---|---|
| `.text` | PROGBITS | `0x120` | 102 608 (12 826 slots) |
| `.rodata` | PROGBITS | `0x191f0` | 2 503 |
| `.data.rel.ro` | PROGBITS | `0x19bb8` | 344 |
| `.dynamic` | DYNAMIC | `0x19d10` | 176 |
| `.dynsym` | DYNSYM | `0x19dc0` | 216 (9 symbols) |
| `.dynstr` | STRTAB | `0x19e98` | 103 |
| `.rel.dyn` | REL | `0x19f00` | 1 712 (107 entries) |
| `.shstrtab` | STRTAB | — | 72 |

**Relocations: two types only**, both already implemented — 90 × `R_BPF_64_RELATIVE` (61 of them in
`.text`, i.e. `lddw` sites; 29 in the data sections, i.e. eight-byte pointers in v1's
low-32-bits-in-the-second-word encoding) and 17 × `R_BPF_64_32` (syscall sites). There is **no**
`R_BPF_64_64` in this file.

**Calls:** all 158 `call imm` sites carry `src = 1`, eBPF's `BPF_PSEUDO_CALL`. 141 are real
pc-relative calls with the target already in the immediate and no relocation; 17 are the syscall
sites, `imm = -1` plus an `R_BPF_64_32`. `sbpf_core::elf::load` normalises the file's marker away
before applying relocations (see its `call imm` pass; the plan's loader refused `src != 0` outright
and so refused this file).

**Syscalls named:** `sol_log_`, `sol_memcpy_`, `sol_memcmp_`, `sol_memset_`, `sol_panic_` — all
implemented — plus `sol_set_return_data` and `sol_get_sysvar`, which are **not**. Neither is on the
`Transfer` path (`GetAccountDataSize`/`AmountToUiAmount`/`UiAmountToAmount` set return data, and
`InitializeAccount` reads the rent sysvar), so they are a scope boundary rather than dead code: an
instruction that reaches one gets `Halt::UnknownSyscall`, which is status 2 over the pre-state.
`research/tests/sbpf_elf.rs::spl_token_elf_loads_with_relocations_applied` pins the exact set.
