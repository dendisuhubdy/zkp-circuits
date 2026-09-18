#!/usr/bin/env python3
"""Writes crypto_vectors.h: the known answers sbpf-rt's software Ed25519 verify and secp256k1
recover are checked against by host_test.c.

Sources, all independent of the C under test:
  * Ed25519: RFC 8032 section 7.1, TEST 1, TEST 2, TEST 3 and TEST SHA(abc), copied verbatim from
    the RFC and re-derived here with OpenSSL (`cryptography`'s Ed25519PrivateKey) so a transcription
    slip fails this script; plus OpenSSL-signed messages whose lengths straddle SHA-512's 111/112 and
    128-byte padding boundaries, and negative cases built from them (a flipped message bit, a flipped
    R bit, S replaced by S + L, a public key whose y is not on the curve).
  * secp256k1: go-ethereum's crypto/signature_test.go ecrecover vector (testmsg, testsig,
    testpubkey), checked by the pure-Python recovery below; plus OpenSSL (`cryptography`'s
    SECP256K1 ECDSA) signatures by fixed private keys (1 — Bitcoin's generator-as-public-key case —
    and others), whose recovery id is the one of 0..3 under which the pure-Python recovery returns
    OpenSSL's own public key; plus the rejection cases Solana's sol_secp256k1_recover returns an
    error code for (recovery id >= 4, r or s zero, r or s >= n, x = r + n >= p, x not on the curve).

Run from this directory: python3 gen_crypto_vectors.py > crypto_vectors.h
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ---- Ed25519 ---------------------------------------------------------------------------------
L = 2**252 + 27742317777372353535851937790883648493

RFC = [
    ("RFC 8032 TEST 1",
     "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("RFC 8032 TEST 2",
     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("RFC 8032 TEST 3",
     "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("RFC 8032 TEST SHA(abc)",
     "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     hashlib.sha512(b"abc").hexdigest(),
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


def ed_pub(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed_ok(pk, msg, sig):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


ed = []  # (name, pk, msg, sig, valid)
for name, skh, pkh, mh, sigh in RFC:
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(skh))
    assert ed_pub(sk).hex() == pkh, name
    assert sk.sign(bytes.fromhex(mh)).hex() == sigh, name
    ed.append((name, bytes.fromhex(pkh), bytes.fromhex(mh), bytes.fromhex(sigh), True))

for i, n in enumerate([1, 63, 64, 111, 112, 127, 128, 129, 300]):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"sbpf-rt ed25519 %d" % i).digest())
    msg = bytes((7 * j + n) & 0xff for j in range(n))
    sig = sk.sign(msg)
    ed.append((f"OpenSSL, {n}-byte message", ed_pub(sk), msg, sig, True))

name, pk, msg, sig, _ = ed[1]  # TEST 2
bad = bytearray(msg); bad[0] ^= 1
ed.append(("TEST 2, message bit flipped", pk, bytes(bad), sig, False))
bad = bytearray(sig); bad[3] ^= 0x10
ed.append(("TEST 2, R bit flipped", pk, msg, bytes(bad), False))
s = int.from_bytes(sig[32:], "little") + L
ed.append(("TEST 2, S + L (non-canonical S)", pk, msg, sig[:32] + s.to_bytes(32, "little"), False))
bad = bytearray(sig); bad[40] ^= 1
ed.append(("TEST 2, S bit flipped", pk, msg, bytes(bad), False))
# y = 2: x^2 = (y^2 - 1) / (d y^2 + 1) has no square root, so the key does not decode.
ed.append(("TEST 2, public key off the curve", (2).to_bytes(32, "little"), msg, sig, False))
bad = bytearray(ed[0][1]); bad[31] ^= 0x80  # TEST 1's key with the x sign flipped: a different point
ed.append(("TEST 1, public key sign bit flipped", bytes(bad), ed[0][2], ed[0][3], False))
for name, pk, msg, sig, valid in ed:
    assert ed_ok(pk, msg, sig) == valid, name

# ---- secp256k1 -------------------------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def padd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def pmul(k, pt):
    r = None
    while k:
        if k & 1:
            r = padd(r, pt)
        pt = padd(pt, pt)
        k >>= 1
    return r


def recover(h, recid, sig):
    """Solana's sol_secp256k1_recover over libsecp256k1: 0 and the 64-byte key, or an error code
    (2 InvalidRecoveryId, 3 InvalidSignature)."""
    if recid > 3:
        return 2, None
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return 3, None
    x = r + (recid >> 1) * N
    if x >= P:
        return 3, None
    y2 = (x**3 + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return 3, None
    if (y & 1) != (recid & 1):
        y = P - y
    e = int.from_bytes(h, "big") % N
    ri = pow(r, -1, N)
    q = padd(pmul((-e * ri) % N, G), pmul(s * ri % N, (x, y)))
    if q is None:
        return 3, None
    return 0, q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")


sec = []  # (name, hash, recid, sig64, expect_code, pubkey64)
gh = bytes.fromhex("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
gs = bytes.fromhex("90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
gp = bytes.fromhex("04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
code, key = recover(gh, gs[64], gs[:64])
assert code == 0 and key == gp[1:], "go-ethereum vector"
sec.append(("go-ethereum signature_test.go", gh, gs[64], gs[:64], 0, gp[1:]))

for d in [1, 2, 3, 0x289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032, N - 1,
          int.from_bytes(hashlib.sha256(b"sbpf-rt secp256k1").digest(), "big") % N]:
    sk = ec.derive_private_key(d, ec.SECP256K1())
    nums = sk.public_key().public_numbers()
    want = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    for m in [b"", b"abc", b"sbpf-rt"]:
        h = hashlib.sha256(m + d.to_bytes(32, "big")).digest()
        r, s = utils.decode_dss_signature(sk.sign(h, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        ids = [i for i in range(4) if recover(h, i, sig) == (0, want)]
        assert len(ids) == 1, (d, m)
        sec.append((f"OpenSSL, d = {d:#x}"[:60] + f", msg {m!r}", h, ids[0], sig, 0, want))
        # The other parity recovers a different key (or none): never OpenSSL's.
        other = ids[0] ^ 1
        c, k = recover(h, other, sig)
        assert k != want
        sec.append((f"  ... with the wrong parity (recid {other})", h, other, sig, c, k or bytes(64)))

h, rid, sig = gh, gs[64], gs[:64]
r = int.from_bytes(sig[:32], "big")
s = int.from_bytes(sig[32:], "big")
sec.append(("recovery id 4", h, 4, sig, 2, bytes(64)))
sec.append(("recovery id 255", h, 255, sig, 2, bytes(64)))
sec.append(("recovery id 2^32 + 1 (does not fit a u8)", h, 2**32 + 1, sig, 2, bytes(64)))
sec.append(("r = 0", h, rid, bytes(32) + sig[32:], 3, bytes(64)))
sec.append(("s = 0", h, rid, sig[:32] + bytes(32), 3, bytes(64)))
sec.append(("r = n", h, rid, N.to_bytes(32, "big") + sig[32:], 3, bytes(64)))
sec.append(("s = n", h, rid, sig[:32] + N.to_bytes(32, "big"), 3, bytes(64)))
sec.append(("x = r + n = p (recid 2)", h, 2, (P - N).to_bytes(32, "big") + sig[32:], 3, bytes(64)))
# r = 5: 5^3 + 7 = 132 is not a square mod p, so there is no point with x = 5.
assert recover(h, 0, (5).to_bytes(32, "big") + sig[32:])[0] == 3
sec.append(("x = 5 not on the curve", h, 0, (5).to_bytes(32, "big") + sig[32:], 3, bytes(64)))
# recid 2 and 3 with the smallest r whose x = r + n is on the curve: the second-x recovery that
# only a signature with r < p - n can reach.
r2 = next(r for r in range(1, 1000) if recover(h, 2, r.to_bytes(32, "big") + sig[32:])[0] == 0)
for rid2 in (2, 3):
    c, k = recover(h, rid2, r2.to_bytes(32, "big") + sig[32:])
    assert c == 0
    sec.append((f"x = {r2} + n (recid {rid2})", h, rid2, r2.to_bytes(32, "big") + sig[32:], c, k))
# A hash >= n: e is reduced mod n, as libsecp256k1's Message::parse does.
hn = (N + 5).to_bytes(32, "big")
c, k = recover(hn, rid, sig)
assert c == 0 and k == recover((5).to_bytes(32, "big"), rid, sig)[1]
sec.append(("hash = n + 5 (reduced mod n)", hn, rid, sig, c, k))


def carr(b):
    return "{" + ",".join(f"0x{x:02x}" for x in b) + "}" if b else "{0}"


print("/* Generated by gen_crypto_vectors.py — do not edit. See that script for the sources. */")
print("#ifndef SBPF_RT_CRYPTO_VECTORS_H\n#define SBPF_RT_CRYPTO_VECTORS_H\n#include <stdint.h>\n")
print("typedef struct { const char *name; uint8_t pk[32]; uint32_t msg_len; const uint8_t *msg; uint8_t sig[64]; int valid; } ed25519_vector;")
for i, (name, pk, msg, sig, valid) in enumerate(ed):
    print(f"static const uint8_t ed_msg_{i}[] = {carr(msg)};")
print("static const ed25519_vector ED25519_VECTORS[] = {")
for i, (name, pk, msg, sig, valid) in enumerate(ed):
    print(f'  {{"{name}", {carr(pk)}, {len(msg)}, ed_msg_{i}, {carr(sig)}, {int(valid)}}},')
print("};\n")
print("typedef struct { const char *name; uint8_t hash[32]; uint64_t recid; uint8_t sig[64]; uint64_t code; uint8_t pubkey[64]; } secp256k1_vector;")
print("static const secp256k1_vector SECP256K1_VECTORS[] = {")
for name, h, rid, sig, code, key in sec:
    name = name.replace('"', "'")
    print(f'  {{"{name}", {carr(h)}, {rid}ull, {carr(sig)}, {code}, {carr(key)}}},')
print("};\n#endif")
