#!/usr/bin/env python3
"""Independent known-answer vectors for BlackSilk seed format v1 and the keys
a wallet derives from it (docs/blocks.md §10, docs/px.md §3.1).

TEST TOOLING ONLY, NOT CORE. Nothing in the node, wallet or kernel runs this
file. It produces `wallet/tests/data/seed_v1_vectors.txt`, which
`wallet/tests/seed_vectors.rs` checks against the Rust implementation.

Independence (what this script shares with the Rust code, and what it does not):
- It is written from the specification in docs/blocks.md §10 and docs/px.md
  §3.1, not from the Rust sources: the bit layout, GF(2^11) with x^11 + x^2 + 1,
  the Reed-Solomon code (roots alpha and alpha^2), the check-word tweak, the
  master derivation, the hedge keys, the PX account and address derivation and
  the vault secret.
- BLAKE2b comes from Python's hashlib; the domain tag framing
  (`u8(len(tag)) || tag`, tag = "BlackSilk/v1/" || name) from docs/transactions.md
  §1.2. Scalars are reduced modulo l with Python integers.
- PX `Hk` is the independent Poseidon2 implementation of
  `tools/vectors/poseidon2_hk.py` (itself checked against Plonky3's own KAT).
- The word list is read from `crypto/src/wordlist.rs`, and its canonical text
  (one word per line, LF) is checked against the SHA-256 published with BIP-39
  (2f5eed53...dbda). That pins the list to upstream, not to the Rust code.

Usage:
  python tools/vectors/seed_v1.py            # print the vector file
  python tools/vectors/seed_v1.py --write    # rewrite wallet/tests/data/seed_v1_vectors.txt
  python tools/vectors/seed_v1.py --check    # compare with the committed file

Python standard library only.
"""

import argparse
import hashlib
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")

_spec = importlib.util.spec_from_file_location("poseidon2_hk", os.path.join(HERE, "poseidon2_hk.py"))
p2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p2)
hk, DOMAINS, hexd = p2.hk, p2.DOMAINS, p2.hexd

# --- Word list ---------------------------------------------------------------

BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def load_words():
    src = open(os.path.join(ROOT, "crypto", "src", "wordlist.rs"), encoding="utf-8").read()
    body = src[src.index("pub static ENGLISH"):]
    body = body[:body.index("];")]
    words = re.findall(r'"([a-z]+)"', body)
    assert len(words) == 2048
    text = ("\n".join(words) + "\n").encode()
    assert hashlib.sha256(text).hexdigest() == BIP39_ENGLISH_SHA256, "not the BIP-39 English list"
    return words, text


WORDS, WORDS_TEXT = load_words()

# --- Hashing (docs/transactions.md §1.2) ----------------------------------------

L = 2 ** 252 + 27742317777372353535851937790883648493


def framed(name):
    tag = ("BlackSilk/v1/" + name).encode()
    return bytes([len(tag)]) + tag


def h32(name, *parts):
    return hashlib.blake2b(framed(name) + b"".join(parts), digest_size=32).digest()


def h64(name, *parts):
    return hashlib.blake2b(framed(name) + b"".join(parts), digest_size=64).digest()


def hs(name, *parts):
    return (int.from_bytes(h64(name, *parts), "little") % L).to_bytes(32, "little")


# --- GF(2^11), modulus x^11 + x^2 + 1, alpha = x --------------------------------

MOD = (1 << 11) | (1 << 2) | 1


def gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x800:
            a ^= MOD
    return r


def gf_pow(a, e):
    r = 1
    for _ in range(e):
        r = gf_mul(r, a)
    return r


def gf_inv(a):
    return gf_pow(a, 2046)


ALPHA = 2
assert gf_pow(ALPHA, 2047) == 1 and gf_pow(ALPHA, 23) != 1 and gf_pow(ALPHA, 89) != 1, "not primitive"

N, K = 27, 25
TWEAK = 0x253  # low 11 bits of ASCII "BS" (0x4253), XOR-ed into word 26


def poly_eval(c, x):
    """C(x) = sum c_i x^(26-i) (Horner, first word = highest degree)."""
    acc = 0
    for s in c:
        acc = gf_mul(acc, x) ^ s
    return acc


def rs_check(data):
    """The two check symbols making C(alpha) = C(alpha^2) = 0, solved directly
    from the two linear equations (not by polynomial division, as in Rust)."""
    a1, a2 = ALPHA, gf_mul(ALPHA, ALPHA)
    s1 = poly_eval(list(data) + [0, 0], a1)
    s2 = poly_eval(list(data) + [0, 0], a2)
    # c25 * a + c26 = s1 and c25 * a^2 + c26 = s2 (char 2: minus = plus).
    c25 = gf_mul(s1 ^ s2, gf_inv(a1 ^ a2))
    c26 = s1 ^ gf_mul(c25, a1)
    full = list(data) + [c25, c26]
    assert poly_eval(full, a1) == 0 and poly_eval(full, a2) == 0
    return c25, c26


# --- Seed v1 (docs/blocks.md §10) ----------------------------------------------

VERSION = 1
NETWORKS = {"mainnet": 0, "testnet": 1, "regtest": 2}
EPOCH_BITS = 14


def encode(entropy, network, birthday, features=0):
    bits = int.from_bytes(entropy, "big")
    for value, width in ((VERSION, 5), (network, 2), (birthday, 10), (features, 2)):
        assert 0 <= value < 1 << width
        bits = (bits << width) | value
    data = [(bits >> (11 * (K - 1 - i))) & 0x7FF for i in range(K)]
    c25, c26 = rs_check(data)
    symbols = data + [c25 ^ TWEAK, c26]
    return " ".join(WORDS[s] for s in symbols), symbols


def master_of(entropy, network, features=0):
    return h32("seed/master/v1", bytes([VERSION, network, features]), entropy)


def limbs16(b):
    return [int.from_bytes(b[2 * i:2 * i + 2], "little") for i in range(16)]


def le_bytes(d):
    return b"".join(x.to_bytes(4, "little") for x in d)


def split(x):
    return [x & 0xFFFF, x >> 16]


KEY_DOMAINS = {"DIV_KEY": 0x505A01, "IVK": 0x505A02, "DIV_RANGE": 0x505A03,
               "IVK_RANGE": 0x505A04, "DIVERSIFIER_V2": 0x505A05, "SK_ACCOUNT": 0x505A06}


def px_account(master, account):
    root = hk(DOMAINS["SK"], limbs16(master))
    sk = hk(KEY_DOMAINS["SK_ACCOUNT"], root + split(account))
    return root, sk


def px_owner(sk, index):
    nk, ak = hk(DOMAINS["NK"], sk), hk(DOMAINS["AK"], sk)
    dk = hk(KEY_DOMAINS["DIV_KEY"], sk)
    dk_range = hk(KEY_DOMAINS["DIV_RANGE"], dk + split(index >> 16))
    d = hk(KEY_DOMAINS["DIVERSIFIER_V2"], dk_range + split(index))
    return hk(DOMAINS["OWNER"], ak + nk + d)


def vault_secret(hk_px, network, contract, rho):
    s = h32("px/wallet/vault-secret/v1", hk_px, bytes([network]), le_bytes(contract), le_bytes(rho))
    return [int.from_bytes(s[4 * i:4 * i + 4], "little") & ((1 << 30) - 1) for i in range(8)]


CASES = [
    ("a", bytes(range(32)), "regtest", 0),
    ("b", bytes([0xFF] * 32), "testnet", 1023),
    ("c", bytes(32), "mainnet", 5),
    ("d", hashlib.blake2b(b"seed_v1 case d", digest_size=32).digest(), "testnet", 77),
]
CONTRACT = [0x1234 + k for k in range(8)]
RHO = [0x7000_0000 + 17 * k for k in range(8)]


def vectors():
    out = [
        ("wordlist.sha256", hashlib.sha256(WORDS_TEXT).hexdigest()),
        ("wordlist.blake2b256", hashlib.blake2b(WORDS_TEXT, digest_size=32).hexdigest()),
    ]
    for name, entropy, net, birthday in CASES:
        network = NETWORKS[net]
        words, _ = encode(entropy, network, birthday)
        master = master_of(entropy, network)
        k_s = hs("wallet/spend-key", master)
        k_v = hs("wallet/view-key", master)
        root, sk0 = px_account(master, 0)
        _, sk1 = px_account(master, 1)
        hk_px = h32("px/wallet/hedge-key/v1", le_bytes(sk0))
        p = "%s." % name
        out += [
            (p + "entropy", entropy.hex()),
            (p + "network", net),
            (p + "birthday", str(birthday)),
            (p + "words", words),
            (p + "master", master.hex()),
            (p + "k_s", k_s.hex()),
            (p + "k_v", k_v.hex()),
            (p + "hk_v1", h32("wallet/hedge-key/v1", k_s).hex()),
            (p + "px.root", hexd(root)),
            (p + "px.sk0", hexd(sk0)),
            (p + "px.sk1", hexd(sk1)),
            (p + "px.nk0", hexd(hk(DOMAINS["NK"], sk0))),
            (p + "px.ak0", hexd(hk(DOMAINS["AK"], sk0))),
            (p + "px.hk_px0", hk_px.hex()),
            (p + "px.owner0.0", hexd(px_owner(sk0, 0))),
            (p + "px.owner0.70001", hexd(px_owner(sk0, 70001))),
            (p + "px.owner1.0", hexd(px_owner(sk1, 0))),
            (p + "vault_secret", hexd(vault_secret(hk_px, network, CONTRACT, RHO))),
        ]
    return out


HEADER = """\
# BlackSilk seed v1 and wallet key known-answer vectors.
# Generated by tools/vectors/seed_v1.py (independent Python implementation; see
# its docstring). Checked by wallet/tests/seed_vectors.rs.
# Format: name = value. Digests of field elements: 8 big-endian hex digits each.
# Byte strings (entropy, master, scalars, hedge keys): hex, in byte order.
# vault_secret: contract = [0x1234 + k], rho = [0x70000000 + 17k], k = 0..7.
"""


def render():
    return HEADER + "".join("%s = %s\n" % kv for kv in vectors())


def main():
    target = os.path.join(ROOT, "wallet", "tests", "data", "seed_v1_vectors.txt")
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = render()
    if args.write:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    elif args.check:
        with open(target, encoding="utf-8") as f:
            if f.read().replace("\r\n", "\n") != text:
                sys.exit("MISMATCH: %s differs from this script's output" % target)
        print("ok: %s matches" % target)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
