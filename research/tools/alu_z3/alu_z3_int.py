#!/usr/bin/env python3
"""z3 model of circuits b9ffc39 research/src/tables/alu.rs AluAir::eval (lines 170-436),
(issue #66's optional SMT harness: see README.md beside this file; not part of `cargo test`)
transcribed constraint by constraint over Goldilocks (p = 2^64 - 2^32 + 1).

Every witness column is a canonical field element (BV256 < p). Field ops reduce mod p.
Lookups become membership predicates on the canonical representative:
  RANGE8[x]      : x < 256
  AND4/OR4/XOR4[x,y,z]: x<16, y<16, z == x op y
  POW2[s, w]     : s < 32, w == 2^s
Each lookup is active iff its gate (a sum of one-hot flags, concretised per op) is 1.

Query per op: exists a satisfying row whose C differs from AluOp::eval(A, B) (isa.rs:85).
unsat => the constrained output is uniquely the reference result for every in-range input.
Also: exists a satisfying row with A >= 2^32 or B >= 2^32 (operand range soundness).
"""
import sys, time
from z3 import *
import z3

P = 2**64 - 2**32 + 1
W = 256
OPS = ["Add","Sub","And","Or","Xor","Sll","Srl","Sra","Slt","Sltu","Eq",
       "Mul","Mulh","Mulhu","Mulhsu","Div","Divu","Rem","Remu"]
INV16 = 17293822565076172801
assert (16 * INV16) % P == 1



_ctr = [0]
DROP = set()   # sensitivity harness: tags of constraints to omit
class E:
    def __init__(self, v): self.v = v
def lift(x): return x if isinstance(x, E) else E(x)
def K(x): return E(x % P)
def fadd(*xs):
    t = 0
    for x in xs: t = t + lift(x).v
    return E(t)
def fneg(x): return E(-lift(x).v)
def fsub(x, y): return E(lift(x).v - lift(y).v)
def fmul(*xs):
    t = 1
    for x in xs:
        v = lift(x).v
        if isinstance(v, int) and v == 0: return E(0)
        t = t * v
    return E(t)
def is_const(e): return isinstance(e.v, int)
def is_var(x): return (not isinstance(x, int)) and z3.is_const(x) and x.decl().kind() == Z3_OP_UNINTERPRETED
def zero(s, e):
    e = lift(e)
    if isinstance(e.v, int):
        assert e.v % P == 0, "constant constraint fails"; return
    v = simplify(e.v)
    if z3.is_int_value(v):
        assert v.as_long() % P == 0; return
    _ctr[0] += 1
    k = Int(f"k{_ctr[0]}")
    s.add(v == k * P)
def canon_lt(s, e, bound, name):
    e = lift(e)
    if is_var(e.v):
        s.add(e.v < bound); return e.v
    _ctr[0] += 1
    c = Int(f"{name}_{_ctr[0]}"); s.add(c >= 0, c < bound)
    zero(s, fsub(e, E(c)))
    return c
def bits4(s, c, name):
    _ctr[0] += 1
    bs = [Int(f"{name}b{_ctr[0]}_{i}") for i in range(4)]
    for x in bs: s.add(Or(x == 0, x == 1))
    s.add(c == sum(bs[i] * (1 << i) for i in range(4)))
    return bs
def model(opname, extra=None):
    s = Solver()
    cols = {}
    def col(name):
        if name not in cols:
            v = Int(name); cols[name] = v
            s.add(v >= 0, v < P)
        return E(cols[name])
    flag = {o: K(1 if o == opname else 0) for o in OPS}
    fv = {o: (1 if o == opname else 0) for o in OPS}
    A, B, C = col("A"), col("B"), col("C")
    Al = [col(f"A{i}") for i in range(4)]; Bl = [col(f"B{i}") for i in range(4)]
    Cl = [col(f"C{i}") for i in range(4)]; Ql = [col(f"Q{i}") for i in range(4)]
    Sl = [col(f"S{i}") for i in range(4)]; Tl = [col(f"T{i}") for i in range(4)]
    SA, SB, SHH, PW = col("SA"), col("SB"), col("SHH"), col("PW")
    CR = [col(f"CARRY{i}") for i in range(4)]
    INV, AH3, BH_N, QH3, DIVZ, INVB, DB2, DB3 = [col(n) for n in ["INV","AH3","BH_N","QH3","DIVZ","INVB","DB2","DB3"]]
    one = K(1)
    def z(e): zero(s, e)
    def raw(x): return x.v  # a single-column E
    def boolc(x):  # x(x-1)=0 over a field  <=>  x in {0,1}  (x is a canonical column)
        s.add(Or(raw(x) == 0, raw(x) == 1))
    def canon(e): return canon_lt(s, e, P, 'cn')
    def c8(k): return K(1 << (8 * k))
    def word(l): return fadd(l[0], fmul(l[1], c8(1)), fmul(l[2], c8(2)), fmul(l[3], c8(3)))
    def RANGE8(x, g):
        if g: canon_lt(s, x, 256, "r8")
    def NIB(kind, x, y, zz, g):
        if not g: return
        xc = canon_lt(s, x, 16, "nx"); yc = canon_lt(s, y, 16, "ny")
        xb, yb = bits4(s, xc, "x"), bits4(s, yc, "y")
        if kind == "and": r = sum(xb[i] * yb[i] * (1 << i) for i in range(4))
        elif kind == "or": r = sum((xb[i] + yb[i] - xb[i] * yb[i]) * (1 << i) for i in range(4))
        else: r = sum((xb[i] + yb[i] - 2 * xb[i] * yb[i]) * (1 << i) for i in range(4))
        z(fsub(zz, E(r)))
    def POW2(sh, w, g):
        if not g: return
        shc = canon_lt(s, sh, 32, "sh")
        wv = canon_lt(s, w, P, "pw")
        s.add(Or(*[And(shc == i, wv == (1 << i)) for i in range(32)]))
    f = fv
    # is_real = 1, MULT free (irrelevant on a real row); flags one-hot (sum == is_real) by construction
    # limb recomposition 202-204
    z(fsub(word(Al), A)); z(fsub(word(Bl), B)); z(fsub(word(Cl), C))
    g_ab = 1 - f["And"] - f["Or"] - f["Xor"]
    g_c = g_ab - f["Slt"] - f["Sltu"] - f["Eq"]
    for i in range(4):
        RANGE8(Al[i], g_ab); RANGE8(Bl[i], g_ab); RANGE8(Cl[i], g_c)
    cmp = f["Slt"] + f["Sltu"]; rshift = f["Srl"] + f["Sra"]; shift = f["Sll"] + rshift
    for i in range(4):
        RANGE8(Sl[i], cmp + rshift); RANGE8(Tl[i], rshift); RANGE8(Ql[i], shift)
    # adder 247-256
    adder = f["Add"] + f["Sub"] + cmp
    for i in range(4):
        x = fadd(fmul(flag["Add"], Al[i]), fmul(flag["Sub"], Bl[i]), fmul(K(cmp), Bl[i]))
        y = fadd(fmul(flag["Add"], Bl[i]), fmul(flag["Sub"], Cl[i]), fmul(K(cmp), Sl[i]))
        zz = fadd(fmul(flag["Add"], Cl[i]), fmul(K(f["Sub"] + cmp), Al[i]))
        cin = K(0) if i == 0 else CR[i - 1]
        boolc(CR[i])
        z(fmul(K(1 - adder), CR[i]))
        z(fsub(fadd(x, y, cin), fadd(zz, fmul(CR[i], K(256)))))
    borrow = CR[3]
    # sign bits 266-276
    need_sa = f["Slt"] + f["Sra"] + f["Mulh"] + f["Mulhsu"] + f["Div"] + f["Rem"]
    need_sb = f["Slt"] + f["Mulh"] + f["Div"] + f["Rem"]
    boolc(SA); boolc(SB)
    a3_lo = fsub(Al[3], fmul(K(16), AH3))
    NIB("and", a3_lo, K(0), K(0), need_sa)
    NIB("and", AH3, K(8), fmul(SA, K(8)), need_sa)
    b3_lo = fsub(Bl[3], fmul(K(16), BH_N))
    NIB("and", b3_lo, K(0), K(0), need_sb)
    NIB("and", BH_N, K(8), fmul(SB, K(8)), need_sb)
    z(fmul(flag["Srl"], SA))
    # compares 279-285
    if cmp + f["Eq"]: boolc(C)  # (cmp+eq)*C*(C-1)=0
    z(fmul(flag["Sltu"], fsub(C, borrow)))
    sx = fsub(fadd(SA, SB), fmul(SA, SB, K(2)))
    z(fmul(flag["Slt"], fsub(C, fadd(fmul(fsub(one, sx), borrow), fmul(sx, SA)))))
    diff = fsub(A, B)
    # eq*(diff*INV + C - 1)=0 and eq*C*diff=0: exact solution set over F_p (INV free):
    #   diff==0 -> C=1 ; diff!=0 -> C*diff=0 forces C=0 (INV=1/diff exists)
    if f["Eq"]:
        dc = canon(diff)
        s.add(Or(And(dc == 0, raw(C) == 1), And(dc != 0, raw(C) == 0)))
    # bitwise 291-302
    for i in range(4):
        al, bl, cl = Ql[i], Sl[i], Tl[i]
        # ah = (A_i - al)*16^-1 looked up in [0,16): equivalently (x16, a field bijection) there is a
        # c in [0,16) with A_i - al == 16c. Encoded in that exactly-equivalent form (z3 cannot
        # invert INV16 quickly). Only when a bitwise flag is set (the lookups are gated).
        if f["And"] + f["Or"] + f["Xor"]:
            def hn(byte, lo, nm):
                _ctr[0] += 1
                c = Int(f"{nm}{_ctr[0]}"); s.add(c >= 0, c < 16)
                z(fsub(fsub(byte, lo), fmul(K(16), E(c)))); return E(c)
            ah, bh, ch = hn(Al[i], al, "ah"), hn(Bl[i], bl, "bh"), hn(Cl[i], cl, "ch")
        else:
            ah = bh = ch = K(0)
        for kind, nm in (("and", "And"), ("or", "Or"), ("xor", "Xor")):
            NIB(kind, al, bl, cl, f[nm]); NIB(kind, ah, bh, ch, f[nm])
    # shifts 308-328
    b0_lo = fsub(Bl[0], fmul(K(16), BH_N))
    NIB("and", b0_lo, K(0), K(0), shift)
    NIB("and", BH_N, K(1), SHH, shift)
    sh = fadd(b0_lo, fmul(K(16), SHH))
    POW2(sh, PW, shift)
    q = word(Ql); r = word(Sl); t = word(Tl)
    two32 = K(1 << 32)
    z(fmul(flag["Sll"], fsub(fmul(A, PW), fadd(fmul(q, two32), C))))
    q3_lo = fsub(Ql[3], fmul(K(16), QH3))
    NIB("and", q3_lo, K(0), K(0), f["Sll"])
    if "sll_qh3" not in DROP: NIB("and", QH3, K(8), K(0), f["Sll"])
    def flip(x): return fadd(x, fmul(SA, fsub(K(255), fmul(x, K(2)))))
    a_prime = word([flip(Al[i]) for i in range(4)])
    z(fmul(K(rshift), fsub(a_prime, fadd(fmul(q, PW), r))))
    if "rshift_t" not in DROP: z(fmul(K(rshift), fsub(fsub(PW, one), fadd(r, t))))
    for i in range(4): z(fmul(K(rshift), fsub(Cl[i], flip(Ql[i]))))
    # mul 333-369
    is_mul = f["Mul"] + f["Mulh"] + f["Mulhu"] + f["Mulhsu"]
    al_, ah_ = fadd(Al[0], fmul(c8(1), Al[1])), fadd(Al[2], fmul(c8(1), Al[3]))
    bl_, bh_ = fadd(Bl[0], fmul(c8(1), Bl[1])), fadd(Bl[2], fmul(c8(1), Bl[3]))
    mt0, mt1, mt2, carry = Ql
    z(fmul(K(is_mul), fsub(mt0, fmul(al_, bl_))))
    z(fmul(K(is_mul), fsub(mt1, fadd(fmul(al_, bh_), fmul(ah_, bl_)))))
    z(fmul(K(is_mul), fsub(mt2, fmul(ah_, bh_))))
    carry_limbs = fadd(Sl[1], fmul(c8(1), Sl[2]), fmul(c8(2), Sl[3]))
    z(fmul(K(is_mul), fsub(carry, carry_limbs)))
    for c in Sl[1:]: RANGE8(c, is_mul)
    lo = fsub(fadd(mt0, fmul(K(1 << 16), mt1)), fmul(K(1 << 32), carry))
    hi = fadd(mt2, carry)
    if "mul_lo_limbs" not in DROP:
        z(fmul(K(is_mul), fsub(word(Tl), lo)))
        for i in range(4): RANGE8(Tl[i], is_mul)
    mborrow = Sl[0]
    if f["Mulh"] + f["Mulhsu"] and "mulh_borrow_bool" not in DROP: boolc(mborrow)
    hi_signed = fadd(fsub(fsub(hi, fmul(SA, B)), fmul(flag["Mulh"], SB, A)), fmul(mborrow, K(1 << 32)))
    z(fmul(flag["Mul"], fsub(C, lo)))
    z(fmul(flag["Mulhu"], fsub(C, hi)))
    z(fmul(K(f["Mulh"] + f["Mulhsu"]), fsub(C, hi_signed)))
    # div 375-430
    is_div = f["Div"] + f["Divu"] + f["Rem"] + f["Remu"]
    boolc(DIVZ)
    # is-zero gadget on B (INVB free): exact solution set
    if is_div:
        if "divz_b" in DROP:   # only B*INVB = 1-DIVZ: DIVZ=1 with INVB=0 is allowed for any B
            s.add(Or(And(raw(DIVZ) == 1, cols["INVB"] == 0), And(raw(DIVZ) == 0, raw(B) != 0)))
        else:
            s.add(Or(And(raw(DIVZ) == 1, raw(B) == 0), And(raw(DIVZ) == 0, raw(B) != 0)))
    abs_a = fadd(A, fmul(SA, fsub(K(1 << 32), fmul(K(2), A))))
    abs_b = fadd(B, fmul(SB, fsub(K(1 << 32), fmul(K(2), B))))
    for i in range(4): RANGE8(Ql[i], is_div); RANGE8(Sl[i], is_div)
    q = word(Ql); r = word(Sl)
    normal = fmul(K(is_div), fsub(one, DIVZ))
    z(fmul(normal, fsub(abs_a, fadd(fmul(q, abs_b), r))))
    dif = fsub(fsub(abs_b, r), one)
    diff_limbs = fadd(SHH, fmul(c8(1), PW), fmul(c8(2), DB2), fmul(c8(3), DB3))
    z(fmul(normal, fsub(dif, diff_limbs)))
    # RANGE8 with gate `normal` (not a constant): active iff normal == 1
    if is_div:
        dz = cols["DIVZ"]
        for nm in ("SHH", "PW", "DB2", "DB3"):
            s.add(Implies(dz == 0, cols[nm] < 256))
    mag = fadd(fmul(K(f["Div"] + f["Divu"]), q), fmul(K(f["Rem"] + f["Remu"]), r))
    # is-zero gadget on mag (INV free), active iff normal (DIVZ==0): exact solution set
    if is_div:
        mc = canon(mag)
        s.add(Implies(raw(DIVZ) == 0, Or(And(mc == 0, raw(QH3) == 1), And(mc != 0, raw(QH3) == 0))))
    neg = fadd(fmul(flag["Div"], fsub(fadd(SA, SB), fmul(K(2), SA, SB))), fmul(flag["Rem"], SA))
    c_signed = fadd(mag, fmul(neg, fsub(one, QH3), fsub(K(1 << 32), fmul(K(2), mag))))
    z(fmul(normal, fsub(C, c_signed)))
    z(fmul(DIVZ, K(f["Div"] + f["Divu"]), fsub(C, K(0xffffffff))))
    z(fmul(DIVZ, K(f["Rem"] + f["Remu"]), fsub(C, A)))
    z(fmul(K(f["Divu"] + f["Remu"]), fadd(SA, SB)))
    return s, cols

def ref(opname, a, b):
    """isa.rs AluOp::eval over BV32."""
    sh = b & 31
    Z = BitVecVal(0, 32); O = BitVecVal(1, 32)
    b2i = lambda c: If(c, O, Z)
    a64s, b64s = SignExt(32, a), SignExt(32, b)
    a64u, b64u = ZeroExt(32, a), ZeroExt(32, b)
    MIN, M1 = BitVecVal(0x80000000, 32), BitVecVal(0xffffffff, 32)
    return {
        "Add": a + b, "Sub": a - b, "And": a & b, "Or": a | b, "Xor": a ^ b,
        "Sll": a << sh, "Srl": LShR(a, sh), "Sra": a >> sh,
        "Slt": b2i(a < b), "Sltu": b2i(ULT(a, b)), "Eq": b2i(a == b),
        "Mul": a * b,
        "Mulh": Extract(63, 32, a64s * b64s),
        "Mulhu": Extract(63, 32, a64u * b64u),
        "Mulhsu": Extract(63, 32, a64s * b64u),
        "Div": If(b == 0, M1, If(And(a == MIN, b == M1), MIN, a / b)),
        "Divu": If(b == 0, M1, UDiv(a, b)),
        "Rem": If(b == 0, a, If(And(a == MIN, b == M1), Z, SRem(a, b))),
        "Remu": If(b == 0, a, URem(a, b)),
    }[opname]

def ref_int(s, opname, A, B):
    """isa.rs AluOp::eval as integer arithmetic on A, B in [0, 2^32) (no bit-vectors)."""
    T = 2**32
    def wrap(x): return If(x >= T, x - T, If(x < 0, x + T, x))
    def sgn(x): return If(x >= 2**31, x - T, x)
    def m32(x): return x % T   # SMT-LIB mod: result in [0, T) for T > 0
    sA, sB = sgn(A), sgn(B)
    if opname in ("And", "Or", "Xor"):
        ab = [Int(f"refa{i}") for i in range(32)]; bb = [Int(f"refb{i}") for i in range(32)]
        for x in ab + bb: s.add(Or(x == 0, x == 1))
        s.add(A == Sum([ab[i] * 2**i for i in range(32)]), B == Sum([bb[i] * 2**i for i in range(32)]))
        g = {"And": lambda x, y: x * y, "Or": lambda x, y: x + y - x * y, "Xor": lambda x, y: x + y - 2 * x * y}[opname]
        return Sum([g(ab[i], bb[i]) * 2**i for i in range(32)])
    if opname in ("Sll", "Srl", "Sra"):
        sh = B % 32
        cases = []
        for i in range(32):
            v = {"Sll": m32(A * 2**i), "Srl": A / 2**i, "Sra": m32(sA / 2**i)}[opname]  # Int div floors for a positive divisor
            cases.append((i, v))
        r = cases[-1][1]
        for i, v in reversed(cases[:-1]): r = If(sh == i, v, r)
        return r
    if opname == "Add": return wrap(A + B)
    if opname == "Sub": return wrap(A - B)
    if opname == "Slt": return If(sA < sB, 1, 0)
    if opname == "Sltu": return If(A < B, 1, 0)
    if opname == "Eq": return If(A == B, 1, 0)
    if opname == "Mul": return m32(A * B)
    if opname == "Mulhu": return (A * B) / T
    if opname == "Mulh": return m32((sA * sB) / T)
    if opname == "Mulhsu": return m32((sA * B) / T)
    if opname in ("Div", "Rem"):
        aa = If(sA < 0, -sA, sA); bb = If(sB < 0, -sB, sB)
        q = aa / bb; r = aa % bb
        qs = If((sA < 0) != (sB < 0), -q, q); rs = If(sA < 0, -r, r)
        if opname == "Div": return If(B == 0, T - 1, m32(qs))
        return If(B == 0, A, m32(rs))
    if opname == "Divu": return If(B == 0, T - 1, A / B)
    if opname == "Remu": return If(B == 0, A, A % B)
    raise KeyError(opname)

def run(opname, timeout_ms, only=None):
    out = {}
    if only in (None, "oob"):
        s, cols = model(opname)
        s.set("timeout", timeout_ms)
        s.add(Or(cols["A"] >= 2**32, cols["B"] >= 2**32))
        out["operand_oob"] = str(s.check())
    if only in (None, "out"):
        s, cols = model(opname)
        s.set("timeout", timeout_ms)
        A, B, C = cols["A"], cols["B"], cols["C"]
        s.add(A < 2**32, B < 2**32)
        s.add(C != ref_int(s, opname, A, B))
        r = s.check(); out["wrong_output"] = str(r)
        if r == sat:
            m = s.model()
            out["witness"] = {k: m.eval(v).as_long() for k, v in cols.items()}
    return out

if __name__ == "__main__":
    # usage: python3 alu_z3_int.py [--timeout SECONDS] [--query out|oob] [OP ...]
    #   default: every op, both queries, 1800 s each. z3 is sensitive to the order it sees queries in
    #   (fresh variable names shift): `--query out` alone is how the review timed MUL at ~1 s.
    args = sys.argv[1:]
    timeout_s, only = 1800, None
    while args[:1] in (["--timeout"], ["--query"]):
        if args[0] == "--timeout": timeout_s = int(args[1])
        else: only = args[1]
        args = args[2:]
    ops = args or OPS
    for o in ops:
        t = time.time()
        res = run(o, timeout_s * 1000, only)
        print(o, res, f"{time.time()-t:.1f}s", flush=True)
