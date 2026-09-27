//! Seed format v1: 27 words carrying 256 bits of entropy, a version, the
//! network, a birthday and feature bits, protected by two Reed–Solomon check
//! words (docs/blocks.md §10; dossier 37 §3.1).
//!
//! ```text
//! data (275 bits) = entropy (256) ‖ version (5) ‖ network (2) ‖ birthday (10) ‖ features (2)
//!                   big-endian bit string, cut into 25 symbols of 11 bits (d_0 .. d_24)
//! code            = systematic Reed–Solomon over GF(2^11) (modulus x^11 + x^2 + 1,
//!                   α = x), n = 27, k = 25, distance 3: C(x) = Σ c_i·x^(26-i) with
//!                   C(α) = C(α²) = 0, c_i = d_i for i < 25
//! words           = the BIP-39 English list (blacksilk_crypto::wordlist) of
//!                   c_0 .. c_24, c_25 XOR 0x253, c_26
//! master = H32("seed/master/v1", u8 version ‖ u8 network ‖ u8 features ‖ entropy)
//! ```
//!
//! - **Version** 1. Every other value is refused: a future version may derive
//!   differently, and a wallet must never guess.
//! - **Network**: 0 mainnet, 1 testnet, 2 regtest; 3 is reserved and refused.
//!   It enters `master`, so the same entropy gives unrelated keys on each
//!   network (no cross-network address linkage).
//! - **Birthday**: `min(height >> 14, 1023)`, the 2^14-block epoch of the
//!   chain height at creation. Restore scans from `max(1, birthday · 2^14)`.
//!   It does not enter `master`: a wrong birthday changes where scanning
//!   starts, never the keys.
//! - **Features**: bit 0 is reserved for a passphrase, bit 1 is reserved.
//!   Both must be 0 in version 1.
//! - **Check words**: any one or two wrong words (a transposition of two
//!   words included) are detected. A single wrong word can be located and
//!   corrected ([`Seed::parse_correcting`]), but a correction is only a hint:
//!   two wrong words can look like a different single one, so the wallet
//!   reports the position and asks for the seed again instead of applying it.
//!   The tweak (the low 11 bits of ASCII "BS") keeps other 27-symbol codes
//!   from checking.
//! - 27 is not a BIP-39 length, so BIP-39 wallets refuse these words and
//!   this parser refuses BIP-39 phrases.
//! - Entry is case-insensitive and accepts the first four (or more) letters
//!   of a word.

use blacksilk_consensus::Network;
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_crypto::wordlist;
use zeroize::{Zeroize, Zeroizing};

/// Words in a seed.
pub const SEED_WORDS: usize = 27;
/// Data symbols (the rest are check symbols).
const DATA_WORDS: usize = 25;
/// The seed format version this build writes and reads.
pub const SEED_VERSION: u8 = 1;
/// Blocks per birthday epoch: 2^14 (about 22.8 days at 120 s).
pub const EPOCH_BITS: u32 = 14;
/// The largest birthday (10 bits).
pub const MAX_BIRTHDAY: u16 = 1023;
/// XOR-ed into the first check word.
const TWEAK: u16 = 0x253;

// ---- GF(2^11) ----

const MODULUS: u32 = 0x805; // x^11 + x^2 + 1
const ORDER: usize = 2047;

const fn tables() -> ([u16; 2 * ORDER], [u16; ORDER + 1]) {
    let mut exp = [0u16; 2 * ORDER];
    let mut log = [0u16; ORDER + 1];
    let mut x: u32 = 1;
    let mut i = 0;
    while i < ORDER {
        exp[i] = x as u16;
        exp[i + ORDER] = x as u16;
        log[x as usize] = i as u16;
        x <<= 1;
        if x & 0x800 != 0 {
            x ^= MODULUS;
        }
        i += 1;
    }
    (exp, log)
}

const TABLES: ([u16; 2 * ORDER], [u16; ORDER + 1]) = tables();
const EXP: [u16; 2 * ORDER] = TABLES.0;
const LOG: [u16; ORDER + 1] = TABLES.1;

fn mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

/// `a / b` for `b ≠ 0`.
fn div(a: u16, b: u16) -> u16 {
    debug_assert!(b != 0);
    if a == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + ORDER - LOG[b as usize] as usize]
    }
}

/// `α^e`.
fn alpha(e: usize) -> u16 {
    EXP[e % ORDER]
}

/// `C(x)` at `x` (Horner; the first symbol is the highest degree).
fn eval(symbols: &[u16; SEED_WORDS], x: u16) -> u16 {
    symbols.iter().fold(0, |acc, &s| mul(acc, x) ^ s)
}

/// The two check symbols: the remainder of `D(x)·x²` divided by
/// `g(x) = (x + α)(x + α²) = x² + (α + α²)x + α³`.
fn check_symbols(data: &[u16]) -> [u16; 2] {
    let g1 = alpha(1) ^ alpha(2);
    let g0 = alpha(3);
    let mut r = [0u16; 2];
    for &d in data {
        let fb = d ^ r[0];
        r = [r[1] ^ mul(fb, g1), mul(fb, g0)];
    }
    r
}

// ---- bit packing ----

struct Bits<'a> {
    symbols: &'a mut [u16],
    pos: usize,
}

impl Bits<'_> {
    fn put(&mut self, value: u32, width: u32) {
        for k in (0..width).rev() {
            let bit = ((value >> k) & 1) as u16;
            self.symbols[self.pos / 11] |= bit << (10 - self.pos % 11);
            self.pos += 1;
        }
    }

    fn get(&mut self, width: u32) -> u32 {
        let mut v = 0;
        for _ in 0..width {
            let bit = (self.symbols[self.pos / 11] >> (10 - self.pos % 11)) & 1;
            v = (v << 1) | bit as u32;
            self.pos += 1;
        }
        v
    }
}

/// The seed's code of network `n` (also bound by the derived vault secret).
pub(crate) fn network_code(n: Network) -> u8 {
    match n {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
    }
}

/// Why seed words were refused. The messages never contain a word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// Not 27 words.
    WordCount(usize),
    /// Word `position` (1-based) is not in the list and is not the unique
    /// completion of four or more letters.
    UnknownWord { position: usize },
    /// The check words do not match. `wrong_word` (1-based) is the single
    /// word whose replacement would make the seed valid, if there is one; it
    /// is a hint, never applied (two errors can look like one).
    Checksum { wrong_word: Option<usize> },
    /// An unsupported seed version.
    Version(u8),
    /// The reserved network code 3.
    Network,
    /// Reserved feature bits are set (a passphrase is not supported yet).
    Features(u8),
    /// A valid seed of another network than the one asked for: a seed is
    /// never restored on another network (its keys differ there anyway).
    WrongNetwork {
        seed: &'static str,
        wanted: &'static str,
    },
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::WordCount(24) => write!(
                f,
                "24 words: the 24-word (BIP-39) format is not supported; a BlackSilk seed has \
                 {SEED_WORDS} words"
            ),
            SeedError::WordCount(n) => write!(f, "{n} words; a BlackSilk seed has {SEED_WORDS}"),
            SeedError::UnknownWord { position } => {
                write!(f, "word {position} is not a seed word")
            }
            SeedError::Checksum {
                wrong_word: Some(p),
            } => write!(
                f,
                "the check words do not match; word {p} is probably wrong. Check it and \
                 enter the seed again"
            ),
            SeedError::Checksum { wrong_word: None } => write!(
                f,
                "the check words do not match: at least one word is wrong or two words are \
                 swapped"
            ),
            SeedError::Version(v) => write!(
                f,
                "seed version {v} is not supported by this wallet (it reads version \
                 {SEED_VERSION})"
            ),
            SeedError::Network => write!(f, "the seed names a reserved network"),
            SeedError::WrongNetwork { seed, wanted } => write!(
                f,
                "the seed belongs to {seed}, not {wanted}; a seed is restored only on its own network"
            ),
            SeedError::Features(b) => write!(
                f,
                "the seed uses features this wallet does not support (bits {b:#04b})"
            ),
        }
    }
}

impl std::error::Error for SeedError {}

/// A wallet seed (format v1). The entropy is wiped when dropped and never
/// printed.
#[derive(Clone)]
pub struct Seed {
    entropy: [u8; 32],
    network: Network,
    birthday: u16,
    features: u8,
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Seed {{ network: {:?}, birthday: {}, .. }}",
            self.network, self.birthday
        )
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

impl Seed {
    /// A seed from 32 bytes of CSPRNG entropy. `birthday` above
    /// [`MAX_BIRTHDAY`] is clamped (scanning then starts earlier, never later).
    pub fn new(entropy: [u8; 32], network: Network, birthday: u16) -> Seed {
        Seed {
            entropy,
            network,
            birthday: birthday.min(MAX_BIRTHDAY),
            features: 0,
        }
    }

    /// A new seed from the OS CSPRNG, born at chain height `height`.
    pub fn generate(network: Network, height: u64) -> Result<Seed, getrandom::Error> {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)?;
        let s = Seed::new(entropy, network, Seed::birthday_of(height));
        entropy.zeroize();
        Ok(s)
    }

    /// The birthday of a wallet created at chain height `height`.
    pub fn birthday_of(height: u64) -> u16 {
        (height >> EPOCH_BITS).min(MAX_BIRTHDAY as u64) as u16
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn birthday(&self) -> u16 {
        self.birthday
    }

    /// The first block a restore scans: the start of the birthday epoch.
    pub fn scan_start(&self) -> u64 {
        ((self.birthday as u64) << EPOCH_BITS).max(1)
    }

    /// The raw entropy (persisted in the encrypted wallet file).
    pub(crate) fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }

    /// The 32-byte master secret every wallet key derives from.
    pub fn master(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(h32(
            tags::SEED_MASTER,
            &[
                &[SEED_VERSION, network_code(self.network), self.features],
                &self.entropy,
            ],
        ))
    }

    /// The 27 code symbols.
    fn symbols(&self) -> Zeroizing<[u16; SEED_WORDS]> {
        let mut s = Zeroizing::new([0u16; SEED_WORDS]);
        let mut bits = Bits {
            symbols: &mut s[..DATA_WORDS],
            pos: 0,
        };
        for &b in &self.entropy {
            bits.put(b as u32, 8);
        }
        bits.put(SEED_VERSION as u32, 5);
        bits.put(network_code(self.network) as u32, 2);
        bits.put(self.birthday as u32, 10);
        bits.put(self.features as u32, 2);
        debug_assert_eq!(bits.pos, DATA_WORDS * 11);
        let check = check_symbols(&s[..DATA_WORDS]);
        s[DATA_WORDS..].copy_from_slice(&check);
        s
    }

    /// The seed words, space-separated. Written into a buffer large enough
    /// never to be reallocated, and wiped when dropped.
    pub fn words(&self) -> Zeroizing<String> {
        let mut symbols = self.symbols();
        symbols[DATA_WORDS] ^= TWEAK;
        // 27 words of at most 8 letters and 26 spaces: 242 bytes.
        let mut out = Zeroizing::new(String::with_capacity(256));
        for (i, &s) in symbols.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(wordlist::ENGLISH[s as usize]);
        }
        out
    }

    /// Parses seed words, refusing any that do not check (see the module
    /// docs). Case-insensitive; a word may be given by its first four or
    /// more letters.
    pub fn parse(text: &str) -> Result<Seed, SeedError> {
        let symbols = Self::read_symbols(text)?;
        let s = syndromes(&symbols);
        if s != [0, 0] {
            let wrong_word = correct(&symbols, s)
                .filter(|(fixed, _)| Self::decode(fixed).is_ok())
                .map(|(_, i)| i + 1);
            return Err(SeedError::Checksum { wrong_word });
        }
        Self::decode(&symbols)
    }

    /// Like [`Seed::parse`], but corrects a single wrong word. Returns the
    /// seed and the 1-based position of the corrected word, if any.
    ///
    /// Two wrong words may be "corrected" into another valid seed (about
    /// 1.3% of two-word errors): use only when the result can be checked,
    /// for example against a known address.
    pub fn parse_correcting(text: &str) -> Result<(Seed, Option<usize>), SeedError> {
        let symbols = Self::read_symbols(text)?;
        let s = syndromes(&symbols);
        if s == [0, 0] {
            return Self::decode(&symbols).map(|seed| (seed, None));
        }
        match correct(&symbols, s) {
            Some((fixed, i)) => Self::decode(&fixed).map(|seed| (seed, Some(i + 1))),
            None => Err(SeedError::Checksum { wrong_word: None }),
        }
    }

    /// The code symbols of the words, the tweak removed.
    fn read_symbols(text: &str) -> Result<Zeroizing<[u16; SEED_WORDS]>, SeedError> {
        let count = text.split_whitespace().count();
        if count != SEED_WORDS {
            return Err(SeedError::WordCount(count));
        }
        let mut symbols = Zeroizing::new([0u16; SEED_WORDS]);
        for (i, word) in text.split_whitespace().enumerate() {
            let lower = Zeroizing::new(word.to_ascii_lowercase());
            symbols[i] = wordlist::index_of(&lower)
                .or_else(|| wordlist::index_of_prefix(&lower))
                .ok_or(SeedError::UnknownWord { position: i + 1 })?;
        }
        symbols[DATA_WORDS] ^= TWEAK;
        Ok(symbols)
    }

    /// The seed of a valid codeword (tweak removed).
    fn decode(symbols: &[u16; SEED_WORDS]) -> Result<Seed, SeedError> {
        let mut copy = Zeroizing::new(*symbols);
        let mut bits = Bits {
            symbols: &mut copy[..DATA_WORDS],
            pos: 0,
        };
        let mut entropy = Zeroizing::new([0u8; 32]);
        for b in entropy.iter_mut() {
            *b = bits.get(8) as u8;
        }
        let version = bits.get(5) as u8;
        let network = bits.get(2) as u8;
        let birthday = bits.get(10) as u16;
        let features = bits.get(2) as u8;
        if version != SEED_VERSION {
            return Err(SeedError::Version(version));
        }
        let network = match network {
            0 => Network::Mainnet,
            1 => Network::Testnet,
            2 => Network::Regtest,
            _ => return Err(SeedError::Network),
        };
        if features != 0 {
            return Err(SeedError::Features(features));
        }
        Ok(Seed {
            entropy: *entropy,
            network,
            birthday,
            features,
        })
    }
}

/// `[C(α), C(α²)]`.
fn syndromes(symbols: &[u16; SEED_WORDS]) -> [u16; 2] {
    [eval(symbols, alpha(1)), eval(symbols, alpha(2))]
}

/// The codeword at distance 1 from `symbols`, and the index of the changed
/// symbol, if there is one. For one error `e` at degree `p`:
/// `S1 = e·α^p`, `S2 = e·α^2p`, so `α^p = S2/S1` and `e = S1/α^p`.
fn correct(
    symbols: &[u16; SEED_WORDS],
    s: [u16; 2],
) -> Option<(Zeroizing<[u16; SEED_WORDS]>, usize)> {
    let [s1, s2] = s;
    if s1 == 0 || s2 == 0 {
        return None;
    }
    let x = div(s2, s1);
    let p = LOG[x as usize] as usize;
    if p >= SEED_WORDS {
        return None;
    }
    let i = SEED_WORDS - 1 - p;
    let mut fixed = Zeroizing::new(*symbols);
    fixed[i] ^= div(s1, x);
    (syndromes(&fixed) == [0, 0]).then_some((fixed, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> Seed {
        let mut e = [0u8; 32];
        for (i, b) in e.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(n);
        }
        Seed::new(e, Network::Testnet, 300 + n as u16)
    }

    fn words(s: &Seed) -> Vec<String> {
        s.words().split(' ').map(String::from).collect()
    }

    #[test]
    fn the_field_is_gf_2048_with_a_primitive_modulus() {
        // α has order 2047 = 23 · 89: the modulus is primitive.
        assert_eq!(alpha(ORDER), 1);
        assert_ne!(alpha(23), 1);
        assert_ne!(alpha(89), 1);
        let mut seen = std::collections::BTreeSet::new();
        for e in 0..ORDER {
            assert!(seen.insert(alpha(e)));
        }
        for a in 1..=ORDER as u16 {
            assert_eq!(mul(a, div(1, a)), 1);
            assert_eq!(div(mul(a, 1234), 1234), a);
        }
    }

    #[test]
    fn seeds_round_trip() {
        for n in 0..20 {
            let s = seed(n);
            let back = Seed::parse(&s.words()).unwrap();
            assert_eq!(back.entropy, s.entropy);
            assert_eq!(back.network, s.network);
            assert_eq!(back.birthday, s.birthday);
            assert_eq!(*back.master(), *s.master());
            assert_eq!(words(&s).len(), SEED_WORDS);
        }
        let s = seed(0);
        let w = s.words();
        assert_eq!(w.capacity(), 256, "written into the preallocated buffer");
    }

    #[test]
    fn every_network_and_the_birthday_round_trip() {
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            for birthday in [0, 1, 511, MAX_BIRTHDAY] {
                let s = Seed::new([0xA5; 32], network, birthday);
                let back = Seed::parse(&s.words()).unwrap();
                assert_eq!(back.network(), network);
                assert_eq!(back.birthday(), birthday);
                assert_eq!(back.scan_start(), ((birthday as u64) << 14).max(1));
            }
        }
        // Heights map to epochs; far heights clamp (scanning starts earlier).
        assert_eq!(Seed::birthday_of(0), 0);
        assert_eq!(Seed::birthday_of((1 << 14) - 1), 0);
        assert_eq!(Seed::birthday_of(1 << 14), 1);
        assert_eq!(Seed::birthday_of(u64::MAX), MAX_BIRTHDAY);
        assert_eq!(Seed::new([0; 32], Network::Mainnet, 5000).birthday(), 1023);
        let s = Seed::new([0; 32], Network::Mainnet, Seed::birthday_of(123_456));
        assert!(s.scan_start() <= 123_456);
        assert!(123_456 - s.scan_start() < 1 << 14);
    }

    /// The network enters the master secret; the birthday does not.
    #[test]
    fn the_network_enters_the_master_and_the_birthday_does_not() {
        let e = [9u8; 32];
        let m = |n, b| *Seed::new(e, n, b).master();
        assert_ne!(m(Network::Mainnet, 0), m(Network::Testnet, 0));
        assert_ne!(m(Network::Testnet, 0), m(Network::Regtest, 0));
        assert_eq!(m(Network::Testnet, 0), m(Network::Testnet, 900));
    }

    /// Every single-word substitution, at every position, is detected by
    /// `parse` (which names the word) and corrected by `parse_correcting`.
    #[test]
    fn every_single_wrong_word_is_detected_and_corrected() {
        let s = seed(3);
        let good = words(&s);
        let mut checked = 0;
        for pos in 0..SEED_WORDS {
            for (v, w) in wordlist::ENGLISH.iter().enumerate() {
                if *w == good[pos] {
                    continue;
                }
                // All 2047 substitutions at the first, a check and the last
                // position; a stride elsewhere (the code is linear, so every
                // position behaves alike).
                if !(pos == 0 || pos == DATA_WORDS || pos == SEED_WORDS - 1) && v % 61 != 0 {
                    continue;
                }
                let mut bad = good.clone();
                bad[pos] = w.to_string();
                let text = bad.join(" ");
                assert_eq!(
                    Seed::parse(&text).err(),
                    Some(SeedError::Checksum {
                        wrong_word: Some(pos + 1)
                    }),
                    "position {pos}, word {w}"
                );
                let (fixed, at) = Seed::parse_correcting(&text).unwrap();
                assert_eq!(at, Some(pos + 1));
                assert_eq!(fixed.entropy, s.entropy);
                checked += 1;
            }
        }
        assert!(checked > 3 * 2047);
    }

    /// Every transposition of two different words and a sample of two-word
    /// substitutions are detected (distance 3).
    #[test]
    fn two_wrong_words_are_always_detected() {
        let s = seed(4);
        let good = words(&s);
        for i in 0..SEED_WORDS {
            for j in i + 1..SEED_WORDS {
                if good[i] == good[j] {
                    continue;
                }
                let mut bad = good.clone();
                bad.swap(i, j);
                assert!(
                    matches!(Seed::parse(&bad.join(" ")), Err(SeedError::Checksum { .. })),
                    "swap {i} {j}"
                );
                let mut bad = good.clone();
                let k = (i * 31 + j * 7) % 2048;
                bad[i] = wordlist::ENGLISH[k].to_string();
                bad[j] = wordlist::ENGLISH[(k + 1000) % 2048].to_string();
                if bad[i] != good[i] && bad[j] != good[j] {
                    assert!(
                        matches!(Seed::parse(&bad.join(" ")), Err(SeedError::Checksum { .. })),
                        "substitution {i} {j}"
                    );
                }
            }
        }
    }

    #[test]
    fn entry_is_case_insensitive_and_takes_four_letter_prefixes() {
        let s = seed(5);
        let good = words(&s);
        let upper = s.words().to_ascii_uppercase();
        assert_eq!(Seed::parse(&upper).unwrap().entropy, s.entropy);
        let short: Vec<String> = good
            .iter()
            .map(|w| w.chars().take(4).collect::<String>())
            .collect();
        assert_eq!(Seed::parse(&short.join(" ")).unwrap().entropy, s.entropy);
        let spaced = format!("  {}\n", good.join(" \t "));
        assert_eq!(Seed::parse(&spaced).unwrap().entropy, s.entropy);
        // A three-letter prefix of a longer word is not enough; a typo past
        // the fourth letter is not a prefix.
        let long = good.iter().position(|w| w.len() >= 5).unwrap();
        let mut bad = good.clone();
        bad[long] = good[long][..3].to_string();
        if wordlist::index_of(&bad[long]).is_none() {
            assert_eq!(
                Seed::parse(&bad.join(" ")).err(),
                Some(SeedError::UnknownWord { position: long + 1 })
            );
        }
        let mut bad = good.clone();
        bad[long] = format!("{}q", good[long]);
        assert_eq!(
            Seed::parse(&bad.join(" ")).err(),
            Some(SeedError::UnknownWord { position: long + 1 })
        );
        let mut bad = good;
        bad[0] = "abandonné".into();
        assert!(matches!(
            Seed::parse(&bad.join(" ")),
            Err(SeedError::UnknownWord { position: 1 })
        ));
    }

    #[test]
    fn other_lengths_and_bip39_phrases_are_refused() {
        let s = seed(6);
        let good = words(&s);
        assert_eq!(
            Seed::parse(&good[..26].join(" ")).err(),
            Some(SeedError::WordCount(26))
        );
        assert_eq!(Seed::parse("").err(), Some(SeedError::WordCount(0)));
        // The BIP-39 test vector of 32 zero bytes.
        let bip39 = format!("{}art", "abandon ".repeat(23));
        let e = Seed::parse(&bip39).unwrap_err();
        assert_eq!(e, SeedError::WordCount(24));
        assert!(e.to_string().contains("not supported"));
    }

    /// Valid codewords with an unsupported version, the reserved network or
    /// reserved feature bits are refused.
    #[test]
    fn reserved_values_are_refused() {
        let with = |version: u32, network: u32, features: u32| {
            let mut sym = Zeroizing::new([0u16; SEED_WORDS]);
            let mut bits = Bits {
                symbols: &mut sym[..DATA_WORDS],
                pos: 0,
            };
            for b in 0..32u32 {
                bits.put(b, 8);
            }
            bits.put(version, 5);
            bits.put(network, 2);
            bits.put(7, 10);
            bits.put(features, 2);
            let check = check_symbols(&sym[..DATA_WORDS]);
            sym[DATA_WORDS..].copy_from_slice(&check);
            sym[DATA_WORDS] ^= TWEAK;
            let text: Vec<&str> = sym.iter().map(|&x| wordlist::ENGLISH[x as usize]).collect();
            Seed::parse(&text.join(" "))
        };
        assert!(with(1, 1, 0).is_ok());
        assert_eq!(with(0, 1, 0).err(), Some(SeedError::Version(0)));
        assert_eq!(with(2, 1, 0).err(), Some(SeedError::Version(2)));
        assert_eq!(with(1, 3, 0).err(), Some(SeedError::Network));
        assert_eq!(with(1, 1, 1).err(), Some(SeedError::Features(1)));
        assert_eq!(with(1, 1, 2).err(), Some(SeedError::Features(2)));
    }

    /// Without the tweak (another 27-symbol code with the same field and
    /// roots) the words do not check.
    #[test]
    fn the_tweak_is_required() {
        let s = seed(7);
        let mut sym = s.symbols();
        // `symbols()` has no tweak: as words, they must fail.
        let text: Vec<&str> = sym.iter().map(|&x| wordlist::ENGLISH[x as usize]).collect();
        assert!(matches!(
            Seed::parse(&text.join(" ")),
            Err(SeedError::Checksum { .. })
        ));
        sym[DATA_WORDS] ^= TWEAK;
        let text: Vec<&str> = sym.iter().map(|&x| wordlist::ENGLISH[x as usize]).collect();
        assert!(Seed::parse(&text.join(" ")).is_ok());
    }

    #[test]
    fn errors_and_debug_never_show_words() {
        let s = seed(8);
        let good = words(&s);
        assert_eq!(
            format!("{s:?}"),
            "Seed { network: Testnet, birthday: 308, .. }"
        );
        let mut bad = good.clone();
        bad[3] = "zzzzzz".into();
        assert_eq!(
            Seed::parse(&bad.join(" ")).unwrap_err().to_string(),
            "word 4 is not a seed word"
        );
        assert_eq!(
            Seed::parse(&good[..20].join(" ")).unwrap_err().to_string(),
            "20 words; a BlackSilk seed has 27"
        );
        let mut bad = good;
        bad[5] = if bad[5] == "zoo" { "abandon" } else { "zoo" }.into();
        assert_eq!(
            Seed::parse(&bad.join(" ")).unwrap_err().to_string(),
            "the check words do not match; word 6 is probably wrong. Check it and enter the seed again"
        );
    }
}
