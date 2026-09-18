#!/usr/bin/env python3
"""Writes precompile_vectors.h: the known answers evm-rt's nine precompiles (precompiles.c,
evm_secp256k1.c, evm_bn254.c) are checked against by precompiles_test.c, on the host and on the
machine (test/rv32-precompiles).

Every vector carries its source. They are:

  * go-ethereum's precompile test data at commit b381804eb145684a39653aca42936bb17388a7fb
    (core/vm/testdata/precompiles/<file>.json: inputs, outputs and gas, used verbatim):
      ecRecover.json, modexp_eip2565.json (EIP-2565 gas, Berlin and later), bn256Add.json,
      bn256ScalarMul.json, bn256Pairing.json (Istanbul gas, EIP-1108), blake2F.json and
      fail-blake2f.json. modexp.json is the same inputs under the pre-Berlin EIP-198 gas: its
      outputs are used, its gas is not (Shanghai charges EIP-2565's).
  * sha256: FIPS 180-2 Appendix B's messages ("abc", the 448-bit and the 896-bit ones) and the
    empty string; the digests are re-derived with hashlib, so a transcription slip fails here.
  * ripemd160: the test suite on Bosselaers' RIPEMD-160 page (homes.esat.kuleuven.be/~bosselae/
    ripemd160.html), re-derived with pycryptodome's RIPEMD160 when it is installed.
  * identity: the output is the input.
  * The rejections the geth files do not cover, built here from the precompiles' own rules (the
    Yellow Paper appendix E, EIP-196/197 and go-ethereum's contracts.go, which say what fails):
    ecrecover's r = 0, s = 0, s = n, r = n, v = 29, and a short input (v reads as 0) - each a success
    with empty output; alt_bn128 add/mul with a point off the curve or a coordinate >= p; the
    pairing with a length that is not a multiple of 192, a G1 point off the curve, a G2 point off
    the twist, and a G2 point on the twist but outside the r-torsion subgroup (derived with py_ecc
    8.x's bn128 arithmetic: on the twist, and r times it is not the point at infinity).

Gas is each file's where it has one; otherwise the Shanghai formula, stated beside the vector.

Run from this directory:
    python3 gen_precompile_vectors.py <dir holding the geth .json files> > precompile_vectors.h
(fetch them from https://raw.githubusercontent.com/ethereum/go-ethereum/<commit>/core/vm/testdata/precompiles/)
"""
import hashlib
import json
import os
import sys

GETH_COMMIT = "b381804eb145684a39653aca42936bb17388a7fb"
P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

vectors = []  # (source, name, addr, input hex, output hex, gas, ok)


def add(source, name, addr, inp, out, gas, ok=1):
    vectors.append((source, name, addr, inp.lower(), out.lower(), gas, ok))


def words(n):
    return (n + 31) // 32


def geth(d, fname, addr, use_gas=True, gas_fn=None):
    for e in json.load(open(os.path.join(d, fname + ".json"))):
        inp = e["Input"]
        if "ExpectedError" in e:
            add(f"geth {fname}.json", e["Name"], addr, inp, "", gas_fn(bytes.fromhex(inp)), 0)
        else:
            gas = e["Gas"] if use_gas else gas_fn(bytes.fromhex(inp))
            add(f"geth {fname}.json", e["Name"], addr, inp, e["Expected"], gas)


def h32(n):
    return format(n, "064x")


# ---- modexp gas (EIP-2565, as go-ethereum's bigModExp.RequiredGas and the execution specs) ----
def modexp_gas(inp):
    inp = inp + bytes(max(0, 96 - len(inp)))
    bl, el, ml = (int.from_bytes(inp[i:i + 32], "big") for i in (0, 32, 64))
    body = inp[96:]
    eh_len = min(el, 32)
    head = body[bl:bl + eh_len]
    head = head + bytes(eh_len - len(head))
    head = int.from_bytes(head, "big") if eh_len else 0
    msb = head.bit_length() - 1 if head else 0
    if el <= 32:
        it = msb
    else:
        it = 8 * (el - 32) + msb
    it = max(it, 1)
    mc = words_8(max(bl, ml)) ** 2
    g = mc * it // 3
    if g >= 2**64:
        return 2**64 - 1
    return max(200, g)


def words_8(n):
    return (n + 7) // 8


def main():
    d = sys.argv[1]
    # 1 ecrecover
    geth(d, "ecRecover", 1)
    msg = "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
    v = h32(28)
    r = "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
    s = "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"
    src = "derived: geth ecRecover.json ValidKey with one field broken (Yellow Paper appendix E)"
    add(src, "r = 0", 1, msg + v + h32(0) + s, "", 3000)
    add(src, "s = n", 1, msg + v + r + h32(N_SECP), "", 3000)
    add(src, "r = n", 1, msg + v + h32(N_SECP) + s, "", 3000)
    add(src, "v = 29", 1, msg + h32(29) + r + s, "", 3000)
    add(src, "v = 27, the other parity", 1, msg + h32(27) + r + s,
        "000000000000000000000000" + OTHER_PARITY_ADDR, 3000)
    add(src, "64 bytes: v reads as 0", 1, msg + h32(0), "", 3000)
    add(src, "s = 0", 1, msg + v + r + h32(0), "", 3000)

    # 2 sha256
    fips = [
        ("empty", b""),
        ("FIPS 180-2 B.1 abc", b"abc"),
        ("FIPS 180-2 B.2 448 bits", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        ("FIPS 180-2 896 bits", b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        ("55 bytes (one block, the length fits)", b"a" * 55),
        ("56 bytes (the length spills a block)", b"a" * 56),
        ("64 bytes", b"a" * 64),
        ("200 bytes", bytes(range(200))),
    ]
    want = {
        "FIPS 180-2 B.1 abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "FIPS 180-2 B.2 448 bits": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "FIPS 180-2 896 bits": "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        "empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    for name, m in fips:
        dig = hashlib.sha256(m).hexdigest()
        if name in want:
            assert dig == want[name], name
        add("FIPS 180-2 / hashlib", name, 2, m.hex(), dig, 60 + 12 * words(len(m)))

    # 3 ripemd160
    bos = [
        ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        ("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"),
        ("1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    ]
    try:
        from Crypto.Hash import RIPEMD160
    except ImportError:
        RIPEMD160 = None
    for m, dig in bos:
        if RIPEMD160 is not None:
            assert RIPEMD160.new(m.encode()).hexdigest() == dig, m
        add("Bosselaers RIPEMD-160 page", repr(m)[:40], 3, m.encode().hex(), "00" * 12 + dig,
            600 + 120 * words(len(m)))

    # 4 identity
    for name, m in [("empty", b""), ("one byte", b"\x42"), ("33 bytes", bytes(range(33))), ("100 bytes", bytes(range(100)))]:
        add("identity: the output is the input", name, 4, m.hex(), m.hex(), 15 + 3 * words(len(m)))

    # 5 modexp
    geth(d, "modexp_eip2565", 5)
    seen = {v[3] for v in vectors if v[2] == 5}
    for e in json.load(open(os.path.join(d, "modexp.json"))):
        if e["Input"].lower() not in seen:
            add("geth modexp.json (output; EIP-2565 gas by formula)", e["Name"], 5, e["Input"],
                e["Expected"], modexp_gas(bytes.fromhex(e["Input"])))
    for v_ in vectors:
        if v_[2] == 5:
            assert modexp_gas(bytes.fromhex(v_[3])) == v_[5], v_[1]
    srcm = "derived: EIP-198 semantics (go-ethereum bigModExp.Run)"
    # base 3, exp 5, mod 0 (mod length 1): the output is mod-length zero bytes
    add(srcm, "modulus 0", 5, h32(1) + h32(1) + h32(1) + "030500", "00", 200)
    add(srcm, "base and mod lengths 0", 5, h32(0) + h32(1) + h32(0) + "05", "", 200)
    add(srcm, "exponent 0 mod 1", 5, h32(1) + h32(1) + h32(1) + "030001", "00", 200)
    add(srcm, "exponent 0 mod 7", 5, h32(1) + h32(1) + h32(1) + "030007", "01", 200)
    add(srcm, "base past the input (zero)", 5, h32(2) + h32(1) + h32(2), "0000", 200)
    add(srcm, "empty input", 5, "", "", 200)
    # 2^(2^256-1)... too slow; a 33-byte exponent exercises the >32 iteration count
    e33 = "01" + "00" * 32
    add(srcm, "33-byte exponent", 5, h32(1) + h32(33) + h32(1) + "02" + e33 + "0b",
        format(pow(2, int(e33, 16), 11), "02x"), modexp_gas(bytes.fromhex(h32(1) + h32(33) + h32(1) + "02" + e33 + "0b")))

    # modulus length 0 with a base: the output is empty (mod-length bytes), whatever the base
    add(srcm, "modulus length 0, base length 1", 5, h32(1) + h32(1) + h32(0) + "0305", "",
        modexp_gas(bytes.fromhex(h32(1) + h32(1) + h32(0) + "0305")))
    # A 1025-byte exponent: longer than the modulus cap, which the exponent is not held to (it is
    # streamed from the input, never stored). 3^e mod 251, e's bytes a fixed pattern.
    e1025 = bytes((7 * i + 1) & 0xff for i in range(1025)).hex()
    inp = h32(1) + h32(1025) + h32(1) + "03" + e1025 + "fb"
    add(srcm, "1025-byte exponent, 1-byte modulus", 5, inp, format(pow(3, int(e1025, 16), 251), "02x"),
        modexp_gas(bytes.fromhex(inp)))

    # 6, 7, 8 alt_bn128
    geth(d, "bn256Add", 6)
    geth(d, "bn256ScalarMul", 7)
    geth(d, "bn256Pairing", 8)
    srcb = "derived: EIP-196/197 validity rules (go-ethereum newCurvePoint/newTwistPoint)"
    add(srcb, "add: (1, 3) is not on the curve", 6, h32(1) + h32(3) + h32(1) + h32(2), "", 150, 0)
    add(srcb, "add: x = p", 6, h32(P) + h32(2) + h32(1) + h32(2), "", 150, 0)
    add(srcb, "add: y = p + 2 (= the generator's y)", 6, h32(1) + h32(P + 2) + h32(0) + h32(0), "", 150, 0)
    add(srcb, "add: the first point valid (G1), the second (1, 3) off the curve", 6,
        h32(1) + h32(2) + h32(1) + h32(3), "", 150, 0)
    add(srcb, "mul: (1, 3) is not on the curve", 7, h32(1) + h32(3) + h32(2), "", 6000, 0)
    add(srcb, "mul: y = p", 7, h32(0) + h32(P) + h32(2), "", 6000, 0)
    g1 = h32(1) + h32(2)
    g2 = ("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
          "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
          "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
          "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
    add(srcb, "pairing: 191 bytes", 8, (g1 + g2)[:382], "", 45000, 0)
    add(srcb, "pairing: 193 bytes", 8, g1 + g2 + "00", "", 45000 + 34000, 0)
    add(srcb, "pairing: G1 (1, 3) off the curve", 8, h32(1) + h32(3) + g2, "", 79000, 0)
    add(srcb, "pairing: G1 x = p", 8, h32(P) + h32(2) + g2, "", 79000, 0)
    bad_twist = g2[:192] + h32(int(g2[192:256], 16) ^ 1)
    add(srcb, "pairing: G2 off the twist", 8, g1 + bad_twist, "", 79000, 0)
    add(srcb, "pairing: G2 coordinate = p", 8, g1 + h32(P) + g2[64:], "", 79000, 0)
    add(srcb, "pairing: G2 on the twist, outside the subgroup", 8, g1 + G2_NOT_IN_SUBGROUP, "", 79000, 0)
    add(srcb, "pairing: G1 infinity with a G2 outside the subgroup", 8, h32(0) + h32(0) + G2_NOT_IN_SUBGROUP, "", 79000, 0)
    add(srcb, "pairing: G1 infinity, G2 generator (e = 1)", 8, h32(0) + h32(0) + g2, h32(1), 79000)
    add(srcb, "pairing: G1 generator, G2 infinity (e = 1)", 8, g1 + "00" * 128, h32(1), 79000)

    # 9 blake2f
    geth(d, "blake2F", 9)
    geth(d, "fail-blake2f", 9, gas_fn=lambda b: int.from_bytes(b[:4], "big") if len(b) == 213 else 0)

    out = sys.stdout
    out.write("/* GENERATED by evm-rt/test/gen_precompile_vectors.py - do not edit. Sources: that script's\n"
              f" * docstring; go-ethereum's at commit {GETH_COMMIT}. Each vector: its source, name,\n"
              " * precompile address, input and output hex, the gas the precompile charges (RequiredGas) and\n"
              " * whether the call succeeds (0: the input is invalid and the call fails, no output). */\n")
    out.write("typedef struct {\n    const char *source, *name;\n    unsigned addr;\n"
              "    const char *in, *out;\n    unsigned long long gas;\n    int ok;\n} pc_vector;\n")
    out.write("static const pc_vector PC_VECTORS[] = {\n")
    for (src, name, addr, inp, o, gas, ok) in vectors:
        out.write(f"    {{{json.dumps(src)}, {json.dumps(name)}, {addr},\n     \"{inp}\",\n     \"{o}\", {gas}ull, {ok}}},\n")
    out.write("};\n")


# geth ecRecover.json's ValidKey (r, s, message) recovered with v = 27 instead of 28: a different
# public key. Its address, derived with the pure-Python recovery in sbpf-rt's gen_crypto_vectors.py
# (and re-derived below).
OTHER_PARITY_ADDR = None

# A point on the twist y^2 = x^3 + 3/(9+i) that is not in the order-r subgroup: the smallest
# x = k + 0i whose right-hand side is a square, y that square root as algorithm 9 computes it;
# find_g2_not_in_subgroup asserts both properties with py_ecc.
G2_NOT_IN_SUBGROUP = None


def fp2_sqrt(a, FQ2):
    # Adj & Rodriguez-Henriquez 2012, algorithm 9 (p = 3 mod 4).
    a1 = a ** ((P - 3) // 4)
    alpha = a1 * a1 * a
    a0 = alpha ** P * alpha
    if a0 == FQ2([P - 1, 0]):
        return None
    x0 = a1 * a
    if alpha == FQ2([P - 1, 0]):
        return FQ2([0, 1]) * x0
    b = (FQ2([1, 0]) + alpha) ** ((P - 1) // 2)
    return b * x0


def find_g2_not_in_subgroup():
    from py_ecc.bn128 import FQ2, b2, multiply, curve_order, is_on_curve
    x = 1
    while True:
        X = FQ2([x, 0])
        y = fp2_sqrt(X ** 3 + b2, FQ2)
        if y is not None and y * y == X ** 3 + b2:
            pt = (X, y)
            assert is_on_curve(pt, b2)
            assert multiply(pt, curve_order) is not None
            c = lambda f: h32(f.coeffs[1].n if hasattr(f.coeffs[1], "n") else int(f.coeffs[1])) + \
                h32(f.coeffs[0].n if hasattr(f.coeffs[0], "n") else int(f.coeffs[0]))
            return c(X) + c(y)
        x += 1


def recover_addr(msg_hex, v, r, s):
    # secp256k1 public-key recovery in plain Python, then keccak256 via pycryptodome.
    p = 2**256 - 2**32 - 977
    n = N_SECP
    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def add_(P1, P2):
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        if P1[0] == P2[0] and (P1[1] + P2[1]) % p == 0:
            return None
        if P1 == P2:
            l = 3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p) % p
        else:
            l = (P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p) % p
        x = (l * l - P1[0] - P2[0]) % p
        return (x, (l * (P1[0] - x) - P1[1]) % p)

    def mul_(k, P1):
        R = None
        while k:
            if k & 1:
                R = add_(R, P1)
            P1 = add_(P1, P1)
            k >>= 1
        return R

    x = r
    y = pow((x ** 3 + 7) % p, (p + 1) // 4, p)
    if y % 2 != (v - 27):
        y = p - y
    e = int(msg_hex, 16) % n
    ri = pow(r, n - 2, n)
    Q = add_(mul_((-e * ri) % n, (gx, gy)), mul_(s * ri % n, (x, y)))
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256)
    k.update(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))
    return k.hexdigest()[24:]


if __name__ == "__main__":
    try:
        OTHER_PARITY_ADDR = recover_addr(
            "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c", 27,
            0x73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f,
            0xeeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549)
        # The same routine must reproduce geth's ValidKey (v = 28) answer.
        assert recover_addr(
            "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c", 28,
            0x73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f,
            0xeeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549) == \
            "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
        G2_NOT_IN_SUBGROUP = find_g2_not_in_subgroup()
        assert G2_NOT_IN_SUBGROUP is not None
    except ImportError as e:
        sys.exit(f"needs pycryptodome and py_ecc: {e}")
    main()
