//! The consensus manifest: a canonical, ordered list of the consensus-critical
//! constants and rule samples, and the PX-side part of it (docs/testnet.md
//! §2.1, operator checks).
//!
//! The node splits its manifest in two (node/src/fingerprint.rs): the
//! **rules** (every constant, rule sample and rule revision, the same for a
//! release-candidate build and the final build of one network) and the
//! **identity** (network id, genesis, branch ids). This crate owns the
//! encoding and the PX-side rule entries ([`px_entries`]) because it is the
//! lowest crate that sees the kernel and vault program ids, the proof-system
//! parameters (`blacksilk_zk::params`), the circuit digest and the BVM-1
//! limits.
//!
//! Besides constants, [`px_entries`] lists **rule samples** ([`px_samples`]):
//! outputs of PX rule functions on fixed inputs (the Poseidon2 permutation,
//! `Hk`, the tree node, a record commitment and a nullifier, the kernel exit
//! codes, the function prefix and the PX6 window), so a change of that code
//! moves the digest even when no constant changes. Rule code that no sample
//! reaches is named by the node's rule-revision list and, in the end, told
//! apart only by the build commit.

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

/// The PX-side consensus entries: the proof parameter set and proof version
/// (zk), the BVM-1 machine limits and circuit digest (zkvm), the PX kernel
/// constants, hash domains and call ABI (px-core), the pinned kernel and
/// vault program ids, budgets, entry points and domains, the PX state and
/// delivery formats (px), the v1 ring size and hash domain prefix (crypto),
/// and the PX rule samples ([`px_samples`]).
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
    // BVM-1 (zkvm/src/lib.rs, program.rs, prove.rs). The circuit digest is the
    // pinned digest of the constraint system `CIRCUIT_ID` names;
    // zkvm/tests/circuit_fingerprint.rs asserts that it is the last line of
    // `REVISIONS` (RTW1-6), so an AIR change moves this manifest too.
    m.text(
        "zkvm.CIRCUIT_ID",
        std::str::from_utf8(blacksilk_zkvm::prove::CIRCUIT_ID).expect("CIRCUIT_ID is ASCII"),
    )
    .text("zkvm.CIRCUIT_DIGEST", blacksilk_zkvm::prove::CIRCUIT_DIGEST)
    .u(
        "zkvm.CIRCUIT_DIGEST_METHOD",
        blacksilk_zkvm::prove::CIRCUIT_DIGEST_METHOD,
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
        // The call ABI (F-28-1): the only ABI a deploy may register, and the
        // function prefix length (abi, io_hash, contract, PX6 window).
        .u(
            "px_core.call.ABI_VERSION",
            blacksilk_px_core::call::ABI_VERSION,
        )
        .size(
            "px_core.call.PREFIX_WORDS",
            blacksilk_px_core::call::PREFIX_WORDS,
        )
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
    // The kernel's fixed row budgets (px/src/prove.rs `kernel_budget`): the
    // verifier builds the statement's table heights from them, so two nodes
    // with different budgets disagree on every PX proof (RTW1C-1).
    for n_fn in 0..=blacksilk_px_core::call::MAX_FN {
        let b = crate::prove::kernel_budget(n_fn);
        m.list(
            &format!("px.kernel.BUDGET.n_fn_{n_fn}"),
            [
                b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
            ]
            .map(|v| v as u64),
        );
    }
    // The vault's domains, entry points, output words and registered row
    // budget (px/src/vault.rs). The vault program is compiled with all of
    // them, so its id above changes with any of them too.
    let b = crate::vault::BUDGET;
    m.u("px.vault.LOCK_DOMAIN", crate::vault::LOCK_DOMAIN)
        .u("px.vault.REFUND_DOMAIN", crate::vault::REFUND_DOMAIN)
        .u("px.vault.TERMS_DOMAIN", crate::vault::TERMS_DOMAIN)
        .list(
            "px.vault.entry (LOCK, CLAIM, REFUND)",
            [
                crate::vault::LOCK,
                crate::vault::CLAIM,
                crate::vault::REFUND,
            ]
            .map(u64::from),
        )
        .u("px.vault.OUT_WORDS", crate::vault::OUT_WORDS)
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
    m.extend(px_samples());
    m
}

/// The PX rule samples: outputs of PX rule functions on fixed inputs.
///
/// - The Poseidon2 instance (R2-C6: width 16 over BabyBear with the standard
///   constants; the permutation of `Hk`, the zkVM's `POSEIDON2` table and the
///   STARK's own hashing): the permutation of `[0, 1, …, 15]`.
/// - `Hk` (the sponge with its capacity start `[domain, len, 0, …]`), the
///   tree node (truncated, without feed-forward), a record commitment and a
///   nullifier, on fixed inputs.
/// - The kernel's exit codes, in variant order (append only; F-20-1 made 18
///   `ApprovalConflict`).
/// - The function prefix (`abi ‖ io_hash ‖ contract ‖ window`; F-28-1, PX6)
///   of fixed inputs, and the PX6 window rule at its edges.
pub fn px_samples() -> Manifest {
    use blacksilk_px_core::call::{function_prefix, Window, ABI_VERSION};
    use blacksilk_px_core::hash::{domain, hash, node, Digest, Permutation};
    use blacksilk_px_core::kernel::Error;
    use blacksilk_px_core::record::{nullifier, Record};
    let mut perm = crate::perm::HostPerm::new();
    let words = |d: &[u32]| d.iter().map(|&x| u64::from(x)).collect::<Vec<_>>();
    let a: Digest = [1, 2, 3, 4, 5, 6, 7, 8];
    let b: Digest = [9, 10, 11, 12, 13, 14, 15, 16];

    let mut m = Manifest::new();
    let mut state: [u32; 16] = std::array::from_fn(|i| i as u32);
    perm.permute(&mut state);
    m.list("px.sample.poseidon2([0..16])", words(&state));
    m.list(
        "px.sample.Hk(RECORD, [1, 2, 3])",
        words(&hash(&mut perm, domain::RECORD, &[&[1, 2, 3][..]])),
    );
    m.list("px.sample.node(a, b)", words(&node(&mut perm, &a, &b)));
    let cm = Record::plain(a, 5, [7; 8], b, a).commit(&mut perm);
    m.list("px.sample.commit(plain(a, 5, [7; 8], b, a))", words(&cm));
    m.list(
        "px.sample.nullifier(a, b, cm)",
        words(&nullifier(&mut perm, &a, &b, &cm)),
    );
    m.list(
        "px.kernel.exit_codes",
        [
            Error::Version,
            Error::NonCanonical,
            Error::NotBoolean,
            Error::DummyWithValue,
            Error::NotInTree,
            Error::DuplicateNullifier,
            Error::Unbalanced,
            Error::TooManyFunctions,
            Error::ZeroContract,
            Error::Unauthorized,
            Error::ApprovalMismatch,
            Error::SpecMismatch,
            Error::SpecForeignContract,
            Error::SpecConflict,
            Error::DummyContract,
            Error::ContractOutputOwner,
            Error::ApprovalConflict,
        ]
        .map(|e| u64::from(e.exit_code())),
    );
    let w = |not_before, not_after| Window {
        not_before,
        not_after,
    };
    m.list(
        "px.sample.function_prefix(ABI_VERSION, a, b, window)",
        words(&function_prefix(
            ABI_VERSION,
            &a,
            &b,
            &w(0x1_0000_0002, 0x3_0000_0004),
        )),
    );
    // PX6 at its edges: `contains` for (window, height), then well-formedness.
    m.list(
        "px.sample.window.contains",
        [
            (Window::UNBOUNDED, 0),
            (Window::UNBOUNDED, u64::MAX),
            (w(10, 20), 9),
            (w(10, 20), 10),
            (w(10, 20), 20),
            (w(10, 20), 21),
            (w(10, 0), u64::MAX),
            (w(20, 20), 20),
        ]
        .map(|(win, h)| u64::from(win.contains(h))),
    )
    .list(
        "px.sample.window.is_well_formed",
        [w(0, 0), w(5, 0), w(5, 5), w(6, 5)].map(|win| u64::from(win.is_well_formed())),
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
