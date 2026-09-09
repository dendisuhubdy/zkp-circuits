pragma circom 2.1.0;

// The same circuit as src/cubic.rs, in circom's DSL.
// circom compiles this to the identical R1CS shape (3 constraints);
// snarkjs or ark-circom then runs the same Groth16 setup/prove/verify.
//
//   circom cubic.circom --r1cs --wasm --sym
//
template Cubic() {
    signal input  x;      // private by default
    signal input  out;    // made public in `main` below
    signal        sym1;
    signal        y;

    sym1 <== x * x;            // constraint 1
    y    <== sym1 * x;         // constraint 2
    out  === y + x + 5;        // constraint 3  (linear + equality)
}

component main { public [out] } = Cubic();
