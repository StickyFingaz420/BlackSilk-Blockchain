//! Target body: the 27-word seed parser (wallet/src/seed.rs, docs/blocks.md
//! §10; W2-37), `Seed::parse` and `Seed::parse_correcting`.
//!
//! The includer provides a module `seed` at its root exporting `Seed` and
//! `SeedError` (the wallet crate's own module in the wallet test; the same
//! source file included by path in the fuzz target, see
//! fuzz/fuzz_targets/seed_words.rs).
//!
//! Input: a mode byte, then
//! - mode 0 (text): arbitrary text (lossy UTF-8);
//! - mode 1 (seed): entropy (32), network (1), birthday (LE16), then edits;
//! - mode 2 (symbols): 25 data symbols (LE16 each, 11 bits kept), encoded
//!   with an independent Reed–Solomon encoder written here from the spec (so
//!   every version, network, birthday and feature value is reachable with
//!   valid check words), then edits.
//!
//! Edits (3 bytes each, at most 16): replace, swap, remove or insert a word,
//! abbreviate one to 4 to 8 letters, change its case, replace it by a
//! non-word, change the separators.
//!
//! Invariants, beyond "no panic":
//! - the wallet's encoder agrees with the spec encoder (mode 1);
//! - an accepted seed re-encodes identically: `words()` is the input with
//!   every word expanded to its full lower-case form, and parsing it again
//!   gives the same words and the same master secret;
//! - verdicts against the spec, from the number `d` of words whose symbol
//!   differs from the encoded seed: `d = 0` decodes exactly as the fields
//!   say (version, network, features); `d = 1` is refused, the hint names
//!   the changed word and `parse_correcting` restores the original seed
//!   (when the original is valid); `d = 2` is always refused by `parse`
//!   (distance 3 detects any two errors);
//! - `parse` and `parse_correcting` agree: the same errors for the word
//!   count, unknown words and field errors, and a hint `Some(p)` exactly when
//!   `parse_correcting` corrects word `p`, into a seed differing from the
//!   input in word `p` only.

use super::seed::{Seed, SeedError};
use blacksilk_consensus::Network;
use blacksilk_crypto::wordlist::{index_of, index_of_prefix, ENGLISH};

const WORDS: usize = 27;
const DATA: usize = 25;
/// The tweak on the first check word (the low 11 bits of ASCII "BS").
const TWEAK: u16 = 0x253;
/// x^11 + x^2 + 1.
const MODULUS: u32 = 0x805;

fn gf_mul(a: u16, b: u16) -> u16 {
    let (mut a, mut b, mut r) = (a as u32, b as u32, 0u32);
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x800 != 0 {
            a ^= MODULUS;
        }
    }
    r as u16
}

fn gf_inv(a: u16) -> u16 {
    // a^(2^11 - 2) = a^2046.
    let (mut r, mut base, mut e) = (1u16, a, 2046u32);
    while e != 0 {
        if e & 1 != 0 {
            r = gf_mul(r, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    r
}

/// `Σ c_i · a^(26 - i)` (Horner).
fn eval(symbols: &[u16], a: u16) -> u16 {
    symbols.iter().fold(0, |acc, &c| gf_mul(acc, a) ^ c)
}

/// The codeword of 25 data symbols: `C(α) = C(α²) = 0` with `α = x`.
pub fn encode_symbols(data: &[u16; DATA]) -> [u16; WORDS] {
    let mut c = [0u16; WORDS];
    c[..DATA].copy_from_slice(data);
    let (a1, a2) = (2u16, 4u16);
    let (d1, d2) = (eval(&c, a1), eval(&c, a2));
    // d1 + c25·α + c26 = 0 and d2 + c25·α² + c26 = 0.
    let c25 = gf_mul(d1 ^ d2, gf_inv(a1 ^ a2));
    let c26 = d1 ^ gf_mul(c25, a1);
    c[25] = c25;
    c[26] = c26;
    assert_eq!((eval(&c, a1), eval(&c, a2)), (0, 0), "a codeword");
    c
}

/// The 25 data symbols of a 275-bit big-endian bit string.
fn pack(fields: &[(u32, u32)]) -> [u16; DATA] {
    let mut s = [0u16; DATA];
    let mut pos = 0usize;
    for &(value, bits) in fields {
        for k in (0..bits).rev() {
            if value >> k & 1 != 0 {
                s[pos / 11] |= 1 << (10 - pos % 11);
            }
            pos += 1;
        }
    }
    assert_eq!(pos, DATA * 11);
    s
}

fn bits(s: &[u16; DATA], start: usize, n: usize) -> u32 {
    (start..start + n).fold(0, |v, p| v << 1 | (s[p / 11] >> (10 - p % 11) & 1) as u32)
}

fn words_of(code: &[u16; WORDS]) -> Vec<String> {
    code.iter()
        .enumerate()
        .map(|(i, &c)| {
            let c = if i == DATA { c ^ TWEAK } else { c };
            ENGLISH[c as usize].to_string()
        })
        .collect()
}

fn network(code: u32) -> Option<Network> {
    match code {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet),
        2 => Some(Network::Regtest),
        _ => None,
    }
}

/// The index of a typed word, as the parser reads it.
fn lookup(token: &str) -> Option<u16> {
    let lower = token.to_ascii_lowercase();
    index_of(&lower).or_else(|| index_of_prefix(&lower))
}

/// The spec encoding of a seed: its words and the verdict decoding must give.
struct Encoded {
    words: Vec<String>,
    verdict: Result<(Network, u16), Vec<SeedError>>,
}

fn from_data(data: [u16; DATA]) -> Encoded {
    let (version, net, birthday, features) = (
        bits(&data, 256, 5),
        bits(&data, 261, 2),
        bits(&data, 263, 10) as u16,
        bits(&data, 273, 2),
    );
    let mut errors = Vec::new();
    if version != 1 {
        errors.push(SeedError::Version(version as u8));
    }
    if net == 3 {
        errors.push(SeedError::Network);
    }
    if features != 0 {
        errors.push(SeedError::Features(features as u8));
    }
    let verdict = if errors.is_empty() {
        Ok((network(net).expect("0, 1 or 2"), birthday))
    } else {
        Err(errors)
    };
    Encoded {
        words: words_of(&encode_symbols(&data)),
        verdict,
    }
}

pub fn run(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            let text = String::from_utf8_lossy(rest);
            consistent(&text);
        }
        1 if rest.len() >= 35 => {
            let entropy: [u8; 32] = rest[..32].try_into().expect("32 bytes");
            let net_code = rest[32] % 3;
            let net = network(net_code as u32).expect("0, 1 or 2");
            let birthday = u16::from_le_bytes([rest[33], rest[34]]);
            let seed = Seed::new(entropy, net, birthday);
            let mut fields: Vec<(u32, u32)> = entropy.iter().map(|&b| (b as u32, 8)).collect();
            fields.extend([
                (1, 5),
                (net_code as u32, 2),
                (birthday.min(1023) as u32, 10),
                (0, 2),
            ]);
            let enc = from_data(pack(&fields));
            assert_eq!(
                *seed.words(),
                enc.words.join(" "),
                "the wallet's encoder is the spec's"
            );
            edited(&enc, &rest[35..]);
        }
        2 if rest.len() >= 2 * DATA => {
            let mut d = [0u16; DATA];
            for (i, s) in d.iter_mut().enumerate() {
                *s = u16::from_le_bytes([rest[2 * i], rest[2 * i + 1]]) & 0x7ff;
            }
            let enc = from_data(d);
            if let Ok((net, birthday)) = enc.verdict {
                // The entropy is the first 256 bits.
                let mut e = [0u8; 32];
                for (i, b) in e.iter_mut().enumerate() {
                    *b = bits(&d, 8 * i, 8) as u8;
                }
                let w = Seed::new(e, net, birthday).words();
                assert_eq!(
                    *w,
                    enc.words.join(" "),
                    "the spec's encoder is the wallet's"
                );
            }
            edited(&enc, &rest[2 * DATA..]);
        }
        _ => {}
    }
}

/// Applies the edits in `ops` to the words of `enc`, then checks the verdict.
fn edited(enc: &Encoded, ops: &[u8]) {
    let mut tokens = enc.words.clone();
    let mut sep = " ";
    let mut pad = false;
    for &[o, a, b] in ops.as_chunks::<3>().0.iter().take(16) {
        let (a, b) = (a as usize, b as usize);
        let n = tokens.len();
        match o % 8 {
            0 if n > 0 => {
                let w = (((o >> 3) as usize) << 8 | b) % ENGLISH.len();
                tokens[a % n] = ENGLISH[w].to_string();
            }
            1 if n > 0 => tokens.swap(a % n, b % n),
            2 if n > 0 => {
                let t = &mut tokens[a % n];
                let keep = 4 + b % 5;
                if t.len() > keep {
                    t.truncate(keep);
                }
            }
            3 if n > 0 => {
                let t = &mut tokens[a % n];
                *t = if b & 1 != 0 {
                    t.to_ascii_uppercase()
                } else {
                    let mut c = t.clone();
                    if let Some(first) = c.get_mut(..1) {
                        first.make_ascii_uppercase();
                    }
                    c
                };
            }
            4 => {
                sep = ["  ", "\t", "\n", " \r\n "][b % 4];
                pad = a & 1 != 0;
            }
            5 if n > 0 => {
                tokens.remove(a % n);
            }
            6 => tokens.insert(
                a % (n + 1),
                ENGLISH[(b * 8 + a % 8) % ENGLISH.len()].to_string(),
            ),
            7 if n > 0 => tokens[a % n] = ["abc", "zzzz", "abandonx", "é", "0"][b % 5].to_string(),
            _ => {}
        }
    }
    let mut text = tokens.join(sep);
    if pad {
        text = format!(" \t{text}\n");
    }
    let parsed = Seed::parse(&text);
    if tokens.len() != WORDS {
        assert_eq!(
            parsed.as_ref().err(),
            Some(&SeedError::WordCount(tokens.len()))
        );
    } else if let Some(i) = tokens.iter().position(|t| lookup(t).is_none()) {
        assert_eq!(
            parsed.as_ref().err(),
            Some(&SeedError::UnknownWord { position: i + 1 })
        );
    } else {
        let changed: Vec<usize> = tokens
            .iter()
            .zip(&enc.words)
            .enumerate()
            .filter(|(_, (t, w))| lookup(t) != lookup(w))
            .map(|(i, _)| i)
            .collect();
        match (changed.len(), &enc.verdict) {
            (0, Ok((net, birthday))) => {
                let s = parsed.as_ref().expect("the encoded seed parses");
                assert_eq!(*s.words(), enc.words.join(" "), "re-encodes identically");
                assert_eq!((s.network(), s.birthday()), (*net, *birthday));
            }
            (0, Err(errors)) => {
                let e = parsed.as_ref().expect_err("an invalid field is refused");
                assert!(errors.contains(e), "{e:?} is not one of {errors:?}");
            }
            (1, verdict) => {
                let wrong_word = verdict.is_ok().then_some(changed[0] + 1);
                assert_eq!(
                    parsed.as_ref().err(),
                    Some(&SeedError::Checksum { wrong_word }),
                    "one wrong word is detected and located"
                );
                match (Seed::parse_correcting(&text), verdict) {
                    (Ok((s, at)), Ok(_)) => {
                        assert_eq!(at, wrong_word);
                        assert_eq!(*s.words(), enc.words.join(" "), "corrected to the original");
                    }
                    (Err(e), Err(errors)) => assert!(errors.contains(&e), "{e:?}"),
                    (got, _) => panic!("parse_correcting: {:?}", got.map(|(_, at)| at)),
                }
            }
            (2, _) => assert!(
                matches!(parsed, Err(SeedError::Checksum { .. })),
                "two wrong words are always detected"
            ),
            _ => {}
        }
    }
    consistent(&text);
}

/// Checks the invariants any text satisfies.
fn consistent(text: &str) {
    let parsed = Seed::parse(text);
    let corrected = Seed::parse_correcting(text);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let full: Vec<Option<&str>> = tokens
        .iter()
        .map(|t| lookup(t).map(|i| ENGLISH[i as usize]))
        .collect();
    match &parsed {
        Ok(s) => {
            let w = s.words();
            let expanded: Vec<&str> = full.iter().map(|f| f.expect("a known word")).collect();
            assert_eq!(
                *w,
                expanded.join(" "),
                "an accepted seed re-encodes identically"
            );
            let again = Seed::parse(&w).expect("the canonical words parse");
            assert_eq!(*again.words(), *w);
            assert_eq!(*again.master(), *s.master());
            let (c, at) = corrected.expect("parse_correcting accepts it too");
            assert_eq!(at, None);
            assert_eq!(*c.words(), *w);
        }
        Err(SeedError::Checksum {
            wrong_word: Some(p),
        }) => {
            let (c, at) = corrected.expect("a located word is correctable");
            assert_eq!(at, Some(*p));
            let w = c.words();
            let fixed: Vec<&str> = w.split(' ').collect();
            for (i, (f, t)) in fixed.iter().zip(&full).enumerate() {
                assert_eq!(i + 1 == *p, Some(*f) != *t, "only word {p} changes");
            }
        }
        Err(SeedError::Checksum { wrong_word: None }) => match corrected {
            Err(SeedError::Checksum { wrong_word: None })
            | Err(SeedError::Version(_))
            | Err(SeedError::Network)
            | Err(SeedError::Features(_)) => {}
            other => panic!(
                "parse found no correctable word, parse_correcting: {:?}",
                other.map(|(_, at)| at)
            ),
        },
        Err(e) => assert_eq!(corrected.err().as_ref(), Some(e)),
    }
}

fn valid_symbols(e: &[u8; 32]) -> Vec<u8> {
    let mut fields: Vec<(u32, u32)> = e.iter().map(|&b| (b as u32, 8)).collect();
    fields.extend([(1, 5), (2, 2), (5, 10), (0, 2)]);
    let mut v = vec![2];
    for s in pack(&fields) {
        v.extend_from_slice(&s.to_le_bytes());
    }
    v.extend_from_slice(&[3, 0, 1]);
    v
}

fn seed_input(entropy: [u8; 32], net: u8, birthday: u16, ops: &[u8]) -> Vec<u8> {
    let mut v = vec![1];
    v.extend_from_slice(&entropy);
    v.push(net);
    v.extend_from_slice(&birthday.to_le_bytes());
    v.extend_from_slice(ops);
    v
}

/// Seed inputs (named).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let e: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(7));
    let canonical = Seed::new(e, Network::Testnet, 300).words().to_string();
    let mut symbols = vec![2];
    for i in 0..DATA as u16 {
        symbols.extend_from_slice(&(i.wrapping_mul(97) & 0x7ff).to_le_bytes());
    }
    vec![
        ("seed", seed_input(e, 1, 300, &[])),
        ("seed_mainnet", seed_input([0xa5; 32], 0, 1023, &[])),
        ("one_wrong_word", seed_input(e, 2, 7, &[0, 5, 200])),
        (
            "two_wrong_words",
            seed_input(e, 1, 7, &[0, 5, 200, 8, 9, 3]),
        ),
        ("swapped", seed_input(e, 1, 7, &[1, 3, 4])),
        (
            "abbreviated_upper",
            seed_input(e, 1, 7, &[2, 1, 0, 3, 2, 1, 4, 1, 1]),
        ),
        ("word_count", seed_input(e, 1, 7, &[5, 0, 0])),
        ("unknown_word", seed_input(e, 1, 7, &[7, 4, 1])),
        ("symbols", symbols),
        ("symbols_valid", valid_symbols(&e)),
        ("text", [&[0][..], canonical.as_bytes()].concat()),
        (
            "text_bip39",
            [&[0][..], "abandon ".repeat(23).as_bytes(), b"art"].concat(),
        ),
    ]
}
