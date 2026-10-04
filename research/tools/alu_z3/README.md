# `alu_z3` — an SMT model of the ALU AIR (issue #66)

`alu_z3_int.py` transcribes `research/src/tables/alu.rs`'s `AluAir::eval` constraint by constraint
over the Goldilocks integers (every column a canonical element of `[0, p)`, field equations as
`e = k·p`, each lookup as membership in its fixed table) and asks z3, per op, for a satisfying row
with an operand past 32 bits or a `C` other than `AluOp::eval(A, B)`. `unsat` means the constrained
output is unique. The #62 review (circuits `b9ffc39`) got `unsat` for both questions on ADD, SUB,
SLT, SLTU, EQ, MUL, MULHU, DIVU and SRL, and `unsat` on the operand question for all 19 ops; the
bitwise ops, the other shifts, MULH, MULHSU, DIV, REM and REMU time out and are covered by written
arguments and by `tests/alu_coverage.rs` / `tests/cheating.rs`. `sanity.py` checks the model is
not over-constrained (every honest edge and random pair is satisfiable) and, with
`--sensitivity`, that dropping any of five historically load-bearing constraints makes z3 find the
old forgery again.

Optional, not part of `cargo test`. Needs Python 3 and `pip install z3-solver` (tested with 4.x/5.1):

```
cd research/tools/alu_z3
# output uniqueness, one op per process (z3's search depends on the fresh-variable names a previous
# query in the same process consumed; this is how the review ran it): each ~1 s, SRL ~4 min
for op in Add Sub Slt Sltu Eq Mul Mulhu Divu Srl; do python3 alu_z3_int.py --timeout 600 --query out $op; done
python3 alu_z3_int.py --timeout 60 --query oob       # no operand past 32 bits, every op
python3 sanity.py --sensitivity                      # the five drop-a-constraint forgeries, ~2 s
python3 sanity.py Add Slt Divu                       # completeness on edge + random pairs, ~15 s
```

The model is a transcription, not generated from `eval`: re-check it against `alu.rs` whenever the
ALU's constraints change.
