pragma circom 2.1.0;

// The same circuit as src/mimc.rs. x^7 per round via three multiplications.
template MiMC7Round() {
    signal input  x;
    signal input  k;
    signal input  c;
    signal output out;

    signal t;  t  <== x + k + c;
    signal t2; t2 <== t * t;
    signal t4; t4 <== t2 * t2;
    signal t6; t6 <== t4 * t2;
    out <== t6 * t;
}

template MimcPreimage(nRounds) {
    signal input x;     // private preimage
    signal input k;     // public key
    signal input h;     // public hash

    component r[nRounds];
    signal acc[nRounds + 1];
    acc[0] <== x;
    for (var i = 0; i < nRounds; i++) {
        r[i] = MiMC7Round();
        r[i].x <== acc[i];
        r[i].k <== k;
        r[i].c <== (i + 1) * 7919;
        acc[i + 1] <== r[i].out;
    }
    h === acc[nRounds] + k;
}

component main { public [k, h] } = MimcPreimage(10);
