#!/usr/bin/env python3
"""Poseidon2 round constants for width-8 Goldilocks by the Grain LFSR, standard library only.

An independent second implementation of `research/src/poseidon2_grain.rs` (which the test suite
runs); this one exists so the table can be re-derived without building the crate:

    python3 research/tools/poseidon2_grain/grain.py            # prints the Rust table
    python3 research/tools/poseidon2_grain/grain.py --check    # compares with the committed table

The procedure is the Poseidon paper's (Grassi et al., USENIX Security 2021, section 4.3 and
appendix F), used as the Poseidon2 reference script uses it (`poseidon2_rust_params.sage`):

  1. An 80-bit state, most significant bit first: field type (2 bits, 1 = prime field),
     S-box (4 bits, 0 = x^alpha), n = field bits (12), t = width (12), R_F (10), R_P (10),
     then thirty 1 bits.
  2. Update: b[i+80] = b[i+62] ^ b[i+51] ^ b[i+38] ^ b[i+23] ^ b[i+13] ^ b[i]. Discard the
     first 160 output bits.
  3. Output bits are taken in pairs: a pair (1, x) yields x, a pair (0, x) yields nothing.
  4. A field element is n yielded bits, most significant first; a value >= p is discarded
     (rejection sampling), so every constant is canonical and uniform.
  5. Poseidon2 draws R_F * t + R_P elements, in this order: the first R_F/2 full rounds
     (t each), the R_P partial rounds (one each, lane 0), the last R_F/2 full rounds.
"""
import re, sys, pathlib

P = 2**64 - 2**32 + 1      # Goldilocks
FIELD, SBOX, N, T, R_F, R_P = 1, 0, 64, 8, 8, 22   # prime field, x^7, 64 bits, width 8, 8 full + 22 partial


def grain_bits():
    bits = []
    for value, width in ((FIELD, 2), (SBOX, 4), (N, 12), (T, 12), (R_F, 10), (R_P, 10), (2**30 - 1, 30)):
        bits += [(value >> (width - 1 - i)) & 1 for i in range(width)]
    assert len(bits) == 80

    def step():
        new = bits[62] ^ bits[51] ^ bits[38] ^ bits[23] ^ bits[13] ^ bits[0]
        bits.pop(0)
        bits.append(new)
        return new

    for _ in range(160):
        step()
    while True:
        first, second = step(), step()
        if first:
            yield second


def constants():
    gen = grain_bits()
    out = []
    while len(out) < R_F * T + R_P:
        x = 0
        for _ in range(N):
            x = (x << 1) | next(gen)
        if x < P:
            out.append(x)
    half = R_F // 2 * T
    initial = [out[i * T:(i + 1) * T] for i in range(R_F // 2)]
    internal = out[half:half + R_P]
    terminal = [out[half + R_P + i * T: half + R_P + (i + 1) * T] for i in range(R_F // 2)]
    return initial, internal, terminal


def rust(initial, internal, terminal):
    row = lambda r: "    [" + ", ".join(f"0x{x:016x}" for x in r) + "],"
    lines = ["pub const INITIAL: [[u64; 8]; 4] = ["] + [row(r) for r in initial] + ["];", ""]
    lines += ["pub const INTERNAL: [u64; 22] = ["]
    lines += ["    " + ", ".join(f"0x{x:016x}" for x in internal[i:i + 4]) + "," for i in range(0, R_P, 4)]
    lines += ["];", "", "pub const TERMINAL: [[u64; 8]; 4] = ["] + [row(r) for r in terminal] + ["];"]
    return "\n".join(lines)


if __name__ == "__main__":
    table = rust(*constants())
    if "--check" in sys.argv:
        src = (pathlib.Path(__file__).resolve().parents[2] / "src" / "poseidon2_constants_next.rs").read_text()
        want = [int(x, 16) for x in re.findall(r"0x[0-9a-f]{16}", table)]
        got = [int(x, 16) for x in re.findall(r"0x[0-9a-f]{16}", src.split("pub const INITIAL")[1].split("pub fn")[0])]
        if want != got:
            sys.exit("poseidon2_constants_next.rs is NOT the Grain derivation")
        print(f"ok: {len(got)} constants in poseidon2_constants_next.rs are the Grain derivation")
    else:
        print(table)
