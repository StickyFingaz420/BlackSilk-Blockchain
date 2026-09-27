//! The consensus manifest: a canonical, ordered list of the consensus-critical
//! constants, and the PX-side part of it (docs/testnet.md, operator checks).
//!
//! The node's `consensus_fingerprint(network)` (node/src/fingerprint.rs) is a
//! domain-separated hash of one [`Manifest`]: the chain-level entries it adds
//! itself (chain parameters, genesis, transaction and emission rules, RandomX
//! configuration) followed by [`px_entries`]. This crate owns the encoding and
//! the PX-side entries because it is the lowest crate that sees the kernel and
//! vault program ids, the BS-ZK-2 parameters and the BVM-1 limits.
//!
//! Two builds with the same fingerprint agree on every constant listed here.
//! They can still differ in rule *code* that no constant captures; the build
//! commit (`--version`, `/info`) covers that.

use std::fmt::Write;

/// One manifest value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Any unsigned integer (widened to 64 bits).
    U64(u64),
    /// A signed integer.
    I64(i64),
    /// UTF-8 text (program ids, parameter-set names).
    Text(String),
    /// Raw bytes (encoded blocks, ids).
    Bytes(Vec<u8>),
    /// A list of unsigned integers.
    List(Vec<u64>),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::U64(v) => write!(f, "{v}"),
            Value::I64(v) => write!(f, "{v}"),
            Value::Text(s) => write!(f, "{s:?}"),
            Value::Bytes(b) => {
                f.write_str("0x")?;
                b.iter().try_for_each(|x| write!(f, "{x:02x}"))
            }
            Value::List(l) => write!(f, "{l:?}"),
        }
    }
}

/// An ordered list of `name = value` entries with a canonical byte encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    entries: Vec<(String, Value)>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an unsigned integer (any width up to 64 bits).
    pub fn u(&mut self, name: &str, v: impl Into<u64>) -> &mut Self {
        self.push(name, Value::U64(v.into()))
    }

    /// Appends a `usize`.
    pub fn size(&mut self, name: &str, v: usize) -> &mut Self {
        self.push(name, Value::U64(v as u64))
    }

    pub fn i(&mut self, name: &str, v: impl Into<i64>) -> &mut Self {
        self.push(name, Value::I64(v.into()))
    }

    pub fn text(&mut self, name: &str, v: &str) -> &mut Self {
        self.push(name, Value::Text(v.to_string()))
    }

    pub fn bytes(&mut self, name: &str, v: &[u8]) -> &mut Self {
        self.push(name, Value::Bytes(v.to_vec()))
    }

    pub fn list(&mut self, name: &str, v: impl IntoIterator<Item = u64>) -> &mut Self {
        self.push(name, Value::List(v.into_iter().collect()))
    }

    /// Appends every entry of `other`, in order.
    pub fn extend(&mut self, other: Manifest) -> &mut Self {
        self.entries.extend(other.entries);
        self
    }

    fn push(&mut self, name: &str, value: Value) -> &mut Self {
        self.entries.push((name.to_string(), value));
        self
    }

    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }

    /// The canonical encoding: `u32le(count)`, then per entry
    /// `u32le(len) ‖ name ‖ tag ‖ value`, where the value is `u64le` (tag 0),
    /// `i64le` (tag 1), `u32le(len) ‖ utf8` (tag 2), `u32le(len) ‖ bytes`
    /// (tag 3) or `u32le(n) ‖ n × u64le` (tag 4). Every field is length- or
    /// count-prefixed, so two different manifests never share an encoding.
    pub fn encode(&self) -> Vec<u8> {
        fn len(out: &mut Vec<u8>, n: usize) {
            let n = u32::try_from(n).expect("manifest item fits in u32");
            out.extend_from_slice(&n.to_le_bytes());
        }
        let mut out = Vec::new();
        len(&mut out, self.entries.len());
        for (name, value) in &self.entries {
            len(&mut out, name.len());
            out.extend_from_slice(name.as_bytes());
            match value {
                Value::U64(v) => {
                    out.push(0);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                Value::I64(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                Value::Text(s) => {
                    out.push(2);
                    len(&mut out, s.len());
                    out.extend_from_slice(s.as_bytes());
                }
                Value::Bytes(b) => {
                    out.push(3);
                    len(&mut out, b.len());
                    out.extend_from_slice(b);
                }
                Value::List(l) => {
                    out.push(4);
                    len(&mut out, l.len());
                    for v in l {
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                }
            }
        }
        out
    }

    /// `H64(domain, encode())[..32]` ([`blacksilk_crypto::hash::Hasher64`],
    /// BLAKE2b-512 with a tagged domain).
    pub fn digest(&self, domain: &str) -> [u8; 32] {
        let mut h = blacksilk_crypto::hash::Hasher64::new(domain);
        h.update(&self.encode());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize()[..32]);
        out
    }

    /// One `name = value` line per entry (for diagnostics and test failures).
    pub fn render(&self) -> String {
        let mut s = String::new();
        for (name, value) in &self.entries {
            writeln!(s, "{name} = {value}").expect("writing to a String");
        }
        s
    }
}

/// The PX-side consensus entries: the BS-ZK-2 proof parameters and proof
/// version (zk), the BVM-1 machine limits (zkvm), the PX kernel constants and
/// hash domains (px-core), the pinned kernel and vault program ids, the PX
/// state and delivery formats (px), and the v1 ring size and hash domain
/// prefix (crypto).
pub fn px_entries() -> Manifest {
    use blacksilk_px_core::hash::domain;
    use blacksilk_zk::params as zk;
    let mut m = Manifest::new();
    // BS-ZK-2 (zk/src/params.rs) and the proof encoding version.
    m.text(
        "zk.PARAMS_ID",
        std::str::from_utf8(zk::PARAMS_ID).expect("PARAMS_ID is ASCII"),
    )
    .u("zk.PROOF_VERSION", blacksilk_zk::PROOF_VERSION)
    .size("zk.LOG_BLOWUP", zk::LOG_BLOWUP)
    .size("zk.NUM_QUERIES", zk::NUM_QUERIES)
    .size("zk.MAX_LOG_ARITY", zk::MAX_LOG_ARITY)
    .size("zk.LOG_FINAL_POLY_LEN", zk::LOG_FINAL_POLY_LEN)
    .size("zk.QUERY_POW_BITS", zk::QUERY_POW_BITS)
    .size("zk.COMMIT_POW_BITS", zk::COMMIT_POW_BITS)
    .size("zk.NUM_RANDOM_CODEWORDS", zk::NUM_RANDOM_CODEWORDS)
    .size("zk.MERKLE_SALT_ELEMS", zk::MERKLE_SALT_ELEMS)
    .size("zk.EXTENSION_DEGREE", zk::EXTENSION_DEGREE)
    .size("zk.CHALLENGE_FIELD_BITS", zk::CHALLENGE_FIELD_BITS)
    .size("zk.COLLISION_BITS", zk::COLLISION_BITS)
    .size("zk.MIN_PROVEN_BITS", zk::MIN_PROVEN_BITS)
    .size("zk.TARGET_JOHNSON_BITS", zk::TARGET_JOHNSON_BITS)
    .size("zk.MIN_LOG_HEIGHT", zk::MIN_LOG_HEIGHT)
    .size("zk.MAX_LOG_HEIGHT", zk::MAX_LOG_HEIGHT)
    .size("zk.MAX_COMMITTED_COLUMNS", zk::MAX_COMMITTED_COLUMNS)
    .size("zk.MAX_PROOF_BYTES", zk::MAX_PROOF_BYTES)
    .size("zk.MAX_ADVERSARIAL_COLUMNS", zk::MAX_ADVERSARIAL_COLUMNS)
    .size("zk.MAX_CONSTRAINT_DEGREE", zk::MAX_CONSTRAINT_DEGREE);
    // BVM-1 (zkvm/src/lib.rs, program.rs, prove.rs).
    m.text(
        "zkvm.CIRCUIT_ID",
        std::str::from_utf8(blacksilk_zkvm::prove::CIRCUIT_ID).expect("CIRCUIT_ID is ASCII"),
    )
    .u("zkvm.MEM_SIZE", blacksilk_zkvm::MEM_SIZE)
        .u("zkvm.NULL_GUARD", blacksilk_zkvm::NULL_GUARD)
        .u("zkvm.STACK_TOP", blacksilk_zkvm::STACK_TOP)
        .u("zkvm.STACK_SIZE", blacksilk_zkvm::STACK_SIZE)
        .size("zkvm.CODE_LIMIT_WORDS", blacksilk_zkvm::CODE_LIMIT_WORDS)
        .size("zkvm.DATA_LIMIT_BYTES", blacksilk_zkvm::DATA_LIMIT_BYTES)
        .u("zkvm.MAX_CYCLES", blacksilk_zkvm::MAX_CYCLES)
        .size("zkvm.MAX_INPUT_WORDS", blacksilk_zkvm::MAX_INPUT_WORDS)
        .size("zkvm.MAX_OUTPUT_WORDS", blacksilk_zkvm::MAX_OUTPUT_WORDS)
        .size(
            "zkvm.MAX_DATA_SEGMENTS",
            blacksilk_zkvm::program::MAX_DATA_SEGMENTS,
        );
    // The PX kernel (px-core) and the pinned program ids (px/kernel.id, px/vault.id).
    m.u("px_core.P", blacksilk_px_core::P)
        .u("px_core.kernel.VERSION", blacksilk_px_core::kernel::VERSION)
        .size(
            "px_core.kernel.TREE_DEPTH",
            blacksilk_px_core::kernel::TREE_DEPTH,
        )
        .size("px_core.kernel.N_IN", blacksilk_px_core::kernel::N_IN)
        .size("px_core.kernel.N_OUT", blacksilk_px_core::kernel::N_OUT)
        .size(
            "px_core.kernel.MAX_PUBLIC_WORDS",
            blacksilk_px_core::kernel::MAX_PUBLIC_WORDS,
        )
        .size("px_core.call.MAX_FN", blacksilk_px_core::call::MAX_FN)
        .list(
            "px_core.hash.domain",
            [
                domain::SK,
                domain::NK,
                domain::AK,
                domain::OWNER,
                domain::DIVERSIFIER,
                domain::RECORD,
                domain::NULLIFIER,
                domain::RHO,
                domain::IO,
                domain::NULLIFIER_CONTRACT,
            ]
            .map(u64::from),
        )
        .text(
            "px.KERNEL_PROGRAM_ID",
            crate::prove::KERNEL_PROGRAM_ID.trim(),
        )
        .text("px.VAULT_PROGRAM_ID", crate::vault::VAULT_PROGRAM_ID.trim());
    // The vault's registered row budget and entry points (px/src/vault.rs).
    let b = crate::vault::BUDGET;
    m.u("px.vault.LOCK_DOMAIN", crate::vault::LOCK_DOMAIN)
        .list(
            "px.vault.entry",
            [crate::vault::LOCK, crate::vault::CLAIM].map(u64::from),
        )
        .list(
            "px.vault.BUDGET",
            [
                b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
            ]
            .map(|v| v as u64),
        );
    // PX state and record delivery (px).
    m.size("px.state.ROOT_WINDOW", crate::state::ROOT_WINDOW)
        .u("px.tree.CAPACITY", crate::tree::CAPACITY)
        .size(
            "px.delivery.CIPHERTEXT_BYTES",
            crate::delivery::CIPHERTEXT_BYTES,
        );
    // v1 (crypto).
    m.size("crypto.RING_SIZE", blacksilk_crypto::clsag::RING_SIZE)
        .text(
            "crypto.DOMAIN_PREFIX",
            blacksilk_crypto::hash::DOMAIN_PREFIX,
        );
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_injective_on_boundaries() {
        // Moving a byte between name and value changes the encoding.
        let mut a = Manifest::new();
        a.text("ab", "c");
        let mut b = Manifest::new();
        b.text("a", "bc");
        assert_ne!(a.encode(), b.encode());
        // The same number as a different type changes it too.
        let mut c = Manifest::new();
        c.u("x", 1u8);
        let mut d = Manifest::new();
        d.i("x", 1);
        assert_ne!(c.encode(), d.encode());
    }

    #[test]
    fn digest_is_domain_separated() {
        let m = px_entries();
        assert_ne!(m.digest("a"), m.digest("b"));
        assert_eq!(m.digest("a"), px_entries().digest("a"));
    }
}
