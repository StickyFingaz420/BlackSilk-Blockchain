//! Every transaction shape the PX kernel accepts, for `n_fn = 0..=MAX_FN`,
//! and an honest witness of each (RTW1C-1). Shared by
//! px/tests/kernel_budget.rs (every shape fits its kernel budget) and the
//! fuzz seed generator (fuzz/src/seeds.rs: a `kernel_diff` seed per shape,
//! W4-FUZZ2), which include this file by path.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::call::{OutSpec, MAX_FN};
use blacksilk_px_core::kernel::{FunctionWitness, Witness, N_IN, N_OUT};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Two contract ids: shapes with one or two contracts.
pub const CONTRACTS: [Digest; 2] = [[0x100, 1, 2, 3, 4, 5, 6, 7], [0x200, 1, 2, 3, 4, 5, 6, 7]];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum In {
    User,
    Dummy,
    /// A record of `CONTRACTS[k]`.
    Contract(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    User,
    /// A record of `CONTRACTS[k]`.
    Contract(usize),
}

/// A transaction shape: input and output kinds, and for each function its
/// contract, approved inputs and specified outputs.
#[derive(Clone, Debug)]
pub struct Shape {
    pub ins: [In; N_IN],
    pub outs: [Out; N_OUT],
    pub fns: Vec<(usize, [bool; N_IN], [bool; N_OUT])>,
}

impl Shape {
    /// The kernel's rules on the shape (px-core/src/kernel.rs): approvals
    /// only of records of the function's contract, exactly one per contract
    /// input; specifications only of user outputs or the function's own
    /// contract's records, at most one per output, and one for every
    /// contract output.
    pub fn is_valid(&self) -> bool {
        for (i, input) in self.ins.iter().enumerate() {
            let approvals: Vec<usize> = self.fns.iter().filter(|f| f.1[i]).map(|f| f.0).collect();
            match input {
                In::Contract(c) => {
                    if approvals.len() != 1 || approvals[0] != *c {
                        return false;
                    }
                }
                _ => {
                    if !approvals.is_empty() {
                        return false;
                    }
                }
            }
        }
        for (j, output) in self.outs.iter().enumerate() {
            let specs: Vec<usize> = self.fns.iter().filter(|f| f.2[j]).map(|f| f.0).collect();
            if specs.len() > 1 {
                return false;
            }
            match output {
                Out::Contract(c) => {
                    if specs != [*c] {
                        return false;
                    }
                }
                Out::User => {}
            }
        }
        true
    }

    /// A witness of this shape (random openings; balanced with a bridge-in
    /// when every input is a dummy).
    pub fn witness(&self, seed: u64) -> Witness {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut perm = HostPerm::new();
        let mut tree = Tree::new(&mut perm);
        let acct = Account::from_seed(&[9; 32]);
        let mut recs = Vec::new();
        let mut total = 0u64;
        for (k, kind) in self.ins.iter().enumerate() {
            let value = 1_000 + 7 * k as u64;
            let r = match kind {
                In::Dummy => {
                    recs.push(None);
                    continue;
                }
                In::User => Record::plain(
                    acct.owner(0),
                    value,
                    [0; 8],
                    wallet::random_digest(&mut rng),
                    wallet::random_digest(&mut rng),
                ),
                In::Contract(c) => Record {
                    owner: ZERO_DIGEST,
                    contract: CONTRACTS[*c],
                    asset: ZERO_DIGEST,
                    value,
                    data: wallet::random_digest(&mut rng),
                    rho: wallet::random_digest(&mut rng),
                    rcm: wallet::random_digest(&mut rng),
                },
            };
            let cm = r.commit(&mut perm);
            let pos = tree.append(&mut perm, cm).unwrap();
            total += value;
            recs.push(Some((r, pos)));
        }
        let inputs: Vec<_> = self
            .ins
            .iter()
            .zip(&recs)
            .map(|(kind, rec)| match (kind, rec) {
                (In::Dummy, _) => wallet::dummy_input(&mut rng),
                (In::User, Some((r, p))) => acct.spend(0, r, *p, tree.path(*p).unwrap()),
                (In::Contract(_), Some((r, p))) => {
                    wallet::contract_input(&mut rng, r, *p, tree.path(*p).unwrap())
                }
                _ => unreachable!(),
            })
            .collect();
        let bridge_in = if total == 0 { 500 } else { 0 };
        let all = total + bridge_in;
        let values = [all / 2, all - all / 2];
        let outs: Vec<_> = (0..N_OUT)
            .map(|j| {
                let d = wallet::random_digest(&mut rng);
                match self.outs[j] {
                    Out::User => wallet::output(&mut rng, d, values[j]),
                    Out::Contract(c) => {
                        wallet::contract_output(&mut rng, CONTRACTS[c], values[j], d)
                    }
                }
            })
            .collect();
        let mut w = wallet::witness(
            tree.root(),
            bridge_in,
            0,
            [inputs[0].clone(), inputs[1].clone()],
            [outs[0].clone(), outs[1].clone()],
        );
        w.n_fn = self.fns.len();
        for (f, (c, approve, specs)) in self.fns.iter().enumerate() {
            let spec = [0, 1].map(|j| {
                specs[j].then(|| OutSpec {
                    owner: outs[j].owner,
                    contract: outs[j].contract,
                    value: outs[j].value,
                    data: outs[j].data,
                })
            });
            w.functions[f] = Some(FunctionWitness {
                contract: CONTRACTS[*c],
                blind: wallet::random_digest(&mut rng),
                approve: *approve,
                spec,
            });
        }
        w
    }
}

/// Every shape the kernel accepts, for `n_fn = 0..=MAX_FN`.
pub fn valid_shapes() -> Vec<Shape> {
    let ins = [In::User, In::Dummy, In::Contract(0), In::Contract(1)];
    let outs = [Out::User, Out::Contract(0), Out::Contract(1)];
    let flags = |m: usize| [m & 1 == 1, m & 2 == 2];
    let mut shapes = Vec::new();
    for i0 in ins {
        for i1 in ins {
            for o0 in outs {
                for o1 in outs {
                    for n_fn in 0..=MAX_FN {
                        // Per function: contract (2) × approvals (4) × specs (4).
                        let per_fn: usize = 2 * 4 * 4;
                        for code in 0..per_fn.pow(n_fn as u32) {
                            let mut c = code;
                            let mut fns = Vec::new();
                            for _ in 0..n_fn {
                                let x = c % per_fn;
                                c /= per_fn;
                                fns.push((x % 2, flags((x / 2) % 4), flags(x / 8)));
                            }
                            let shape = Shape {
                                ins: [i0, i1],
                                outs: [o0, o1],
                                fns,
                            };
                            if shape.is_valid() {
                                shapes.push(shape);
                            }
                        }
                    }
                }
            }
        }
    }
    shapes
}
