#!/usr/bin/env python3
"""Writes precompile_fuzz_vectors.h: random inputs to the nine precompiles with the answers of an
independent implementation (Task 6, ruling 3), which precompile_fuzz_test.c checks the C against
(gas, success, output) in the host suite.

The oracles, none of them the C:
  * ecrecover: signatures made here (random key and message, RFC-6979-free random nonce) and a
    recovery written here in plain Python over secp256k1 (the key must be a point: r an x on the
    curve, 0 < r, s < n, v the whole word 27 or 28); the address is Keccak-256 of the key through
    pycryptodome. Plus the other parity, high s, random r/s, v != 27/28, short inputs.
  * sha256: hashlib. ripemd160: pycryptodome. identity: the input.
  * modexp: Python's pow over random base/exponent/modulus lengths 0..64 (modulus 0 and 1, base
    longer than the modulus, empty exponent, truncated inputs), gas by gen_precompile_vectors.py's
    EIP-2565 formula (itself checked against go-ethereum's vectors there).
  * bn256 add/mul/pairing: py_ecc's bn128 (8.x): multiples of the generators, doubling, P + (-P),
    the point at infinity, scalars 0, 1, r - 1, r, 2^256 - 1, truncated and over-long inputs, and
    invalid encodings (a coordinate >= p, a point off the curve or off the twist); a pairing
    product that is 1 (e(aP, bQ) e(-abP, Q)) and one that is not.
  * blake2f: EIP-152's F written here from RFC 7693, checked first against hashlib.blake2b (a
    one-block message at 12 rounds is one F call); then random states with 0..24 rounds, the final
    flag 0 or 1, and the invalid encodings: a length of 212 or 214, a final flag of 2.

Deterministic: one fixed seed. Needs py_ecc and pycryptodome; refuses to run without them.
Run from this directory:  python3 gen_precompile_fuzz.py > precompile_fuzz_vectors.h
"""
import hashlib
import random
import struct
import sys

from Crypto.Hash import RIPEMD160, keccak
from py_ecc import bn128

import gen_precompile_vectors as g

SEED = 20260918
R = random.Random(SEED)
P = g.P
N = g.N_SECP
SP = 2**256 - 2**32 - 977
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
vectors = []  # (name, addr, in hex, out hex, gas, ok)


def add(name, addr, inp, out, gas, ok=1):
    vectors.append((name, addr, inp.hex(), out.hex(), gas, ok))


def rb(n):
    return bytes(R.getrandbits(8) for _ in range(n))


def w32(v):
    return v.to_bytes(32, "big")


# ---- secp256k1 ----
def s_add(A, B):
    if A is None:
        return B
    if B is None:
        return A
    if A[0] == B[0] and (A[1] + B[1]) % SP == 0:
        return None
    if A == B:
        l = 3 * A[0] * A[0] * pow(2 * A[1], SP - 2, SP) % SP
    else:
        l = (B[1] - A[1]) * pow(B[0] - A[0], SP - 2, SP) % SP
    x = (l * l - A[0] - B[0]) % SP
    return (x, (l * (A[0] - x) - A[1]) % SP)


def s_mul(k, A):
    out = None
    while k:
        if k & 1:
            out = s_add(out, A)
        A = s_add(A, A)
        k >>= 1
    return out


def kec(b):
    k = keccak.new(digest_bits=256)
    k.update(b)
    return k.digest()


def ecrecover(inp):
    b = (inp + bytes(128))[:128]
    h, v, r, s = b[:32], int.from_bytes(b[32:64], "big"), int.from_bytes(b[64:96], "big"), int.from_bytes(b[96:], "big")
    if v not in (27, 28) or not (0 < r < N) or not (0 < s < N):
        return b""
    x = r
    y2 = (x**3 + 7) % SP
    y = pow(y2, (SP + 1) // 4, SP)
    if y * y % SP != y2:
        return b""
    if y % 2 != v - 27:
        y = SP - y
    e = int.from_bytes(h, "big") % N
    ri = pow(r, N - 2, N)
    Q = s_add(s_mul((-e * ri) % N, (GX, GY)), s_mul(s * ri % N, (x, y)))
    if Q is None:
        return b""
    return bytes(12) + kec(w32(Q[0]) + w32(Q[1]))[12:]


def sign(d, h):
    while True:
        k = R.randrange(1, N)
        Rp = s_mul(k, (GX, GY))
        r = Rp[0] % N
        s = pow(k, N - 2, N) * (int.from_bytes(h, "big") + r * d) % N
        if r and s and Rp[0] < N:
            return 27 + (Rp[1] & 1), r, s


def ecrecover_vectors():
    for i in range(40):
        d = R.randrange(1, N)
        h = rb(32)
        v, r, s = sign(d, h)
        pub = s_mul(d, (GX, GY))
        want = bytes(12) + kec(w32(pub[0]) + w32(pub[1]))[12:]
        kind = i % 8
        if kind == 1:  # high s, the other parity: the same key
            s, v = N - s, 55 - v
        if kind == 2:  # the wrong parity: another key
            v = 55 - v
        if kind == 3:  # random r and s
            r, s = R.randrange(1, N), R.randrange(1, N)
        if kind == 4:  # v a wider word, or out of range
            v = R.choice([0, 1, 26, 29, 27 + 2**8, 2**255 + 27])
        if kind == 5:  # r or s out of range
            if R.random() < 0.5:
                r = R.choice([0, N, N + 1, 2**256 - 1])
            else:
                s = R.choice([0, N, 2**256 - 1])
        inp = h + w32(v) + w32(r) + w32(s)
        if kind == 6:  # extra bytes are ignored
            inp += rb(R.randrange(1, 40))
        if kind == 7:  # truncated: zero-padded
            inp = inp[: R.randrange(0, 128)]
        out = ecrecover(inp)
        if kind in (0, 1, 6):
            assert out == want
        add(f"ecrecover {i} (kind {kind})", 1, inp, out, 3000)


def hash_vectors():
    for i in range(24):
        m = rb(R.choice([0, 1, 31, 32, 33, 55, 56, 63, 64, 65, R.randrange(0, 400)]))
        add(f"sha256 {i} ({len(m)} bytes)", 2, m, hashlib.sha256(m).digest(), 60 + 12 * g.words(len(m)))
        add(f"ripemd160 {i} ({len(m)} bytes)", 3, m, bytes(12) + RIPEMD160.new(m).digest(), 600 + 120 * g.words(len(m)))
        add(f"identity {i} ({len(m)} bytes)", 4, m, m, 15 + 3 * g.words(len(m)))


def modexp_vectors():
    for i in range(60):
        bl, el, ml = R.randrange(0, 65), R.choice([0, 1, 2, 8, 32, 33, R.randrange(0, 65)]), R.randrange(0, 65)
        if i % 10 == 0:
            ml = 1
        base, exp, mod = rb(bl), rb(el), rb(ml)
        if i % 10 == 1 and ml:
            mod = bytes(ml)  # modulus 0
        if i % 10 == 2:
            exp = bytes(el)  # exponent 0
        inp = w32(bl) + w32(el) + w32(ml) + base + exp + mod
        if i % 10 == 3:
            inp = inp[: R.randrange(96, len(inp) + 1)]  # truncated: zero-padded
        body = inp[96:] + bytes(bl + el + ml)
        b = int.from_bytes(body[:bl], "big")
        e = int.from_bytes(body[bl:bl + el], "big")
        m = int.from_bytes(body[bl + el:bl + el + ml], "big")
        if bl == 0 and ml == 0:
            out = b""
        elif m == 0:
            out = bytes(ml)
        else:
            out = pow(b, e, m).to_bytes(ml, "big") if ml else b""
        add(f"modexp {i} ({bl}, {el}, {ml})", 5, inp, out, g.modexp_gas(inp))


# ---- alt_bn128 ----
def enc1(pt):
    if pt is None:
        return bytes(64)
    return w32(int(pt[0])) + w32(int(pt[1]))


def enc2(pt):
    if pt is None:
        return bytes(128)
    x, y = pt
    return w32(x.coeffs[1].n if hasattr(x.coeffs[1], "n") else int(x.coeffs[1])) + \
        w32(x.coeffs[0].n if hasattr(x.coeffs[0], "n") else int(x.coeffs[0])) + \
        w32(y.coeffs[1].n if hasattr(y.coeffs[1], "n") else int(y.coeffs[1])) + \
        w32(y.coeffs[0].n if hasattr(y.coeffs[0], "n") else int(y.coeffs[0]))


def rand_g1():
    return bn128.multiply(bn128.G1, R.randrange(1, bn128.curve_order))


def bn_vectors():
    order = bn128.curve_order
    for i in range(30):
        kind = i % 6
        a, b = rand_g1(), rand_g1()
        if kind == 1:
            b = a  # doubling
        if kind == 2:
            b = bn128.neg(a)  # P + (-P) = infinity
        if kind == 3:
            a = None
        inp = enc1(a) + enc1(b)
        ok = 1
        if kind == 4:  # invalid: x >= p, or off the curve
            if R.random() < 0.5:
                inp = w32(P + R.randrange(0, 5)) + inp[32:]
            else:
                inp = inp[:32] + w32((int.from_bytes(inp[32:64], "big") + 1) % P) + inp[64:]
            ok = 0
        if kind == 5:  # truncated or over-long
            inp = inp[: R.randrange(0, 128)] if R.random() < 0.5 else inp + rb(R.randrange(1, 40))
        pad = (inp + bytes(128))[:128]
        if ok:
            pa = None if pad[:64] == bytes(64) else (bn128.FQ(int.from_bytes(pad[:32], "big")), bn128.FQ(int.from_bytes(pad[32:64], "big")))
            pb = None if pad[64:] == bytes(64) else (bn128.FQ(int.from_bytes(pad[64:96], "big")), bn128.FQ(int.from_bytes(pad[96:], "big")))
            for q in (pa, pb):
                if q is not None and not bn128.is_on_curve(q, bn128.b):
                    ok = 0
        out = enc1(bn128.add(pa, pb)) if ok else b""
        add(f"bn256 add {i} (kind {kind})", 6, inp, out, 150, ok)
    for i in range(30):
        kind = i % 5
        a = rand_g1()
        k = R.choice([0, 1, 2, order - 1, order, order + 1, 2**256 - 1, R.getrandbits(256), R.getrandbits(64)])
        inp = enc1(a) + w32(k)
        ok = 1
        if kind == 1:
            a = None
            inp = bytes(64) + w32(k)
        if kind == 2:
            inp = w32(1) + w32(3) + w32(k)  # (1, 3): off the curve
            ok = 0
        if kind == 3:
            inp = inp[: R.randrange(0, 96)] if R.random() < 0.5 else inp + rb(R.randrange(1, 40))
        pad = (inp + bytes(96))[:96]
        if ok:
            pa = None if pad[:64] == bytes(64) else (bn128.FQ(int.from_bytes(pad[:32], "big")), bn128.FQ(int.from_bytes(pad[32:64], "big")))
            if pa is not None and not bn128.is_on_curve(pa, bn128.b):
                ok = 0
        out = enc1(bn128.multiply(pa, int.from_bytes(pad[64:], "big")) if pa is not None else None) if ok else b""
        add(f"bn256 mul {i} (kind {kind})", 7, inp, out, 6000, ok)
    # The pairing (py_ecc's is slow: a few only).
    a, b = R.randrange(1, order), R.randrange(1, order)
    P1 = bn128.multiply(bn128.G1, a)
    Q1 = bn128.multiply(bn128.G2, b)
    P2 = bn128.neg(bn128.multiply(bn128.G1, a * b % order))
    one = bn128.pairing(Q1, P1) * bn128.pairing(bn128.G2, P2) == bn128.FQ12.one()
    assert one
    inp = enc1(P1) + enc2(Q1) + enc1(P2) + enc2(bn128.G2)
    add("pairing: e(aP, bQ) e(-abP, Q) = 1", 8, inp, w32(1), 45000 + 2 * 34000)
    P3 = bn128.multiply(bn128.G1, a + 1)
    one = bn128.pairing(Q1, P3) * bn128.pairing(bn128.G2, P2) == bn128.FQ12.one()
    assert not one
    inp = enc1(P3) + enc2(Q1) + enc1(P2) + enc2(bn128.G2)
    add("pairing: e((a+1)P, bQ) e(-abP, Q) != 1", 8, inp, w32(0), 45000 + 2 * 34000)
    bad = enc1(P1) + enc2(Q1)
    bad = bad[:64] + w32((int.from_bytes(bad[64:96], "big") + 1) % P) + bad[96:]
    add("pairing: G2 off the twist", 8, bad, b"", 45000 + 34000, 0)
    add("pairing: 0 pairs (= 1)", 8, b"", w32(1), 45000)
    add("pairing: 385 bytes", 8, rb(385), b"", 45000 + 2 * 34000, 0)


# ---- blake2f (RFC 7693's F, EIP-152's encoding) ----
IV = [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
      0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179]
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]
M64 = 2**64 - 1


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def F(rounds, h, m, t0, t1, f):
    v = h[:] + IV[:]
    v[12] ^= t0
    v[13] ^= t1
    if f:
        v[14] ^= M64

    def G(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M64
        v[d] = rotr(v[d] ^ v[a], 32)
        v[c] = (v[c] + v[d]) & M64
        v[b] = rotr(v[b] ^ v[c], 24)
        v[a] = (v[a] + v[b] + y) & M64
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & M64
        v[b] = rotr(v[b] ^ v[c], 63)

    for r in range(rounds):
        s = SIGMA[r % 10]
        G(0, 4, 8, 12, m[s[0]], m[s[1]])
        G(1, 5, 9, 13, m[s[2]], m[s[3]])
        G(2, 6, 10, 14, m[s[4]], m[s[5]])
        G(3, 7, 11, 15, m[s[6]], m[s[7]])
        G(0, 5, 10, 15, m[s[8]], m[s[9]])
        G(1, 6, 11, 12, m[s[10]], m[s[11]])
        G(2, 7, 8, 13, m[s[12]], m[s[13]])
        G(3, 4, 9, 14, m[s[14]], m[s[15]])
    return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]


def blake2f_vectors():
    # F against hashlib first: a one-block message is one F at 12 rounds.
    for n in [0, 1, 64, 127, 128]:
        msg = rb(n)
        h = IV[:]
        h[0] ^= 0x01010040
        m = list(struct.unpack("<16Q", (msg + bytes(128))[:128]))
        out = F(12, h, m, n, 0, True)
        assert struct.pack("<8Q", *out) == hashlib.blake2b(msg).digest(), n
    for i in range(30):
        rounds = R.choice([0, 1, 2, 3, 12, R.randrange(0, 25)])
        h = [R.getrandbits(64) for _ in range(8)]
        m = [R.getrandbits(64) for _ in range(16)]
        t0, t1 = R.getrandbits(64), R.getrandbits(64)
        f = R.randrange(0, 2)
        inp = struct.pack(">I", rounds) + struct.pack("<8Q", *h) + struct.pack("<16Q", *m) + struct.pack("<2Q", t0, t1) + bytes([f])
        out = struct.pack("<8Q", *F(rounds, h, m, t0, t1, f))
        add(f"blake2f {i} ({rounds} rounds, f {f})", 9, inp, out, rounds)
    good = struct.pack(">I", 3) + rb(208) + b"\x01"
    add("blake2f: final flag 2", 9, good[:212] + b"\x02", b"", 3, 0)
    add("blake2f: 212 bytes", 9, good[:212], b"", 0, 0)
    add("blake2f: 214 bytes", 9, good + b"\x00", b"", 0, 0)


def main():
    ecrecover_vectors()
    hash_vectors()
    modexp_vectors()
    bn_vectors()
    blake2f_vectors()
    out = sys.stdout
    out.write("/* GENERATED by evm-rt/test/gen_precompile_fuzz.py (seed %d) - do not edit. Random inputs to\n"
              " * the nine precompiles with the answers of that script's independent implementations\n"
              " * (py_ecc, pycryptodome, hashlib, Python's pow, RFC 7693's F): name, address, input and output\n"
              " * hex, RequiredGas, and whether the call succeeds. */\n" % SEED)
    out.write("typedef struct {\n    const char *name;\n    unsigned addr;\n    const char *in, *out;\n"
              "    unsigned long long gas;\n    int ok;\n} pc_fuzz_vector;\n")
    out.write("static const pc_fuzz_vector PC_FUZZ[] = {\n")
    for (name, addr, inp, o, gas, ok) in vectors:
        out.write(f"    {{\"{name}\", {addr},\n     \"{inp}\",\n     \"{o}\", {gas}ull, {ok}}},\n")
    out.write("};\n")


if __name__ == "__main__":
    main()
