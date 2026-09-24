//! The constraint oracle (docs/zkvm.md §9 items 2–3).
//!
//! [`check`] evaluates every table's constraints row by row on concrete
//! values, and checks that every bus balances exactly: for each
//! `(bus, message)` the signed counts of all tables sum to zero.
//!
//! It is independent of the prover: it implements Plonky3's builder traits
//! over concrete field elements, so the *same* `eval` code the STARK proves is
//! evaluated here. It is used to
//! - validate generated traces before proving (fast, precise errors);
//! - run mutation tests: flip one cell of a valid trace and require a failure.
//!   A mutation that still passes is an under-constrained column.
//!
//! Exclusive interactions are recorded with `count · flag`. Plonky3's default
//! implementation of `push_exclusive_interaction` is a no-op for builders that
//! do not override it, so this override is essential.

use blacksilk_zk::config::Val;
use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::collections::BTreeMap;

pub struct EvalBuilder<'a> {
    main: RowWindow<'a, Val>,
    prep: RowWindow<'a, Val>,
    public: &'a [Val],
    first: Val,
    last: Val,
    transition: Val,
    constraint: usize,
    failures: Vec<usize>,
    global: Vec<(String, Vec<Val>, Val)>,
    local: Vec<(Vec<Val>, Val)>,
}

impl<'a> AirBuilder for EvalBuilder<'a> {
    type F = Val;
    type Expr = Val;
    type Var = Val;
    type PreprocessedWindow = RowWindow<'a, Val>;
    type MainWindow = RowWindow<'a, Val>;
    type PublicVar = Val;
    type PeriodicVar = Val;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.prep
    }

    fn is_first_row(&self) -> Val {
        self.first
    }

    fn is_last_row(&self) -> Val {
        self.last
    }

    fn is_transition(&self) -> Val {
        self.transition
    }

    fn assert_zero<I: Into<Val>>(&mut self, x: I) {
        if x.into() != Val::ZERO {
            self.failures.push(self.constraint);
        }
        self.constraint += 1;
    }

    fn public_values(&self) -> &[Val] {
        self.public
    }

    fn periodic_values(&self) -> &[Val] {
        use p3_air::WindowAccess;
        self.prep.current_slice()
    }
}

impl InteractionBuilder for EvalBuilder<'_> {
    fn push_interaction<E: Into<Val>>(
        &mut self,
        bus_name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Val>>,
    ) {
        let (c, _) = count.into().into_parts();
        let fields = fields.into_iter().map(Into::into).collect();
        self.global.push((bus_name.to_string(), fields, c));
    }

    fn push_local_interaction(&mut self, tuples: impl IntoIterator<Item = (Vec<Val>, Count<Val>)>) {
        for (fields, count) in tuples {
            self.local.push((fields, count.into_parts().0));
        }
    }

    fn push_exclusive_interaction(
        &mut self,
        bus_name: &str,
        branches: impl IntoIterator<Item = (Val, Count<Val>, Vec<Val>)>,
    ) {
        for (flag, count, fields) in branches {
            self.global
                .push((bus_name.to_string(), fields, count.into_parts().0 * flag));
        }
    }
}

/// One violation found by [`check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    /// Constraint number `constraint` of `table` fails on `row`.
    Constraint {
        table: usize,
        row: usize,
        constraint: usize,
    },
    /// The signed counts of `message` on `bus` do not sum to zero.
    Unbalanced {
        bus: String,
        message: Vec<u32>,
        net: u32,
    },
    /// A table's local interactions do not balance.
    LocalUnbalanced { table: usize },
    /// Trace/table/public-value shapes do not match.
    Shape(String),
}

/// Evaluates all constraints and bus balances. Returns every violation (empty
/// means the traces satisfy the statement).
pub fn check<A>(airs: &[A], traces: &[RowMajorMatrix<Val>], public: &[Vec<Val>]) -> Vec<Violation>
where
    A: for<'a> Air<EvalBuilder<'a>> + BaseAir<Val>,
{
    let mut out = Vec::new();
    if airs.len() != traces.len() || airs.len() != public.len() {
        return vec![Violation::Shape(
            "tables, traces and public values differ".into(),
        )];
    }
    let mut buses: BTreeMap<(String, Vec<u32>), Val> = BTreeMap::new();
    for (t, (air, trace)) in airs.iter().zip(traces).enumerate() {
        let h = trace.height();
        let w = trace.width();
        if w != air.width() || !h.is_power_of_two() {
            out.push(Violation::Shape(format!(
                "table {t}: width {w}, height {h}"
            )));
            continue;
        }
        let prep = air.periodic_columns_matrix();
        let pw = prep.as_ref().map_or(0, |p| p.width());
        if let Some(p) = &prep {
            if p.height() != h {
                out.push(Violation::Shape(format!("table {t}: preprocessed height")));
                continue;
            }
        }
        let empty: Vec<Val> = Vec::new();
        let mut local_sum: BTreeMap<Vec<u32>, Val> = BTreeMap::new();
        for r in 0..h {
            let n = (r + 1) % h;
            let cur = &trace.values[r * w..(r + 1) * w];
            let nxt = &trace.values[n * w..(n + 1) * w];
            let (pc, pn): (&[Val], &[Val]) = match &prep {
                Some(p) => (
                    &p.values[r * pw..(r + 1) * pw],
                    &p.values[n * pw..(n + 1) * pw],
                ),
                None => (&empty, &empty),
            };
            let mut b = EvalBuilder {
                main: RowWindow::from_two_rows(cur, nxt),
                prep: RowWindow::from_two_rows(pc, pn),
                public: &public[t],
                first: Val::from_bool(r == 0),
                last: Val::from_bool(r == h - 1),
                transition: Val::from_bool(r != h - 1),
                constraint: 0,
                failures: Vec::new(),
                global: Vec::new(),
                local: Vec::new(),
            };
            air.eval(&mut b);
            for c in b.failures {
                out.push(Violation::Constraint {
                    table: t,
                    row: r,
                    constraint: c,
                });
            }
            for (bus, fields, count) in b.global {
                let key = (bus, fields.iter().map(|f| f.as_canonical_u32()).collect());
                *buses.entry(key).or_insert(Val::ZERO) += count;
            }
            for (fields, count) in b.local {
                *local_sum
                    .entry(fields.iter().map(|f| f.as_canonical_u32()).collect())
                    .or_insert(Val::ZERO) += count;
            }
        }
        if local_sum.values().any(|v| *v != Val::ZERO) {
            out.push(Violation::LocalUnbalanced { table: t });
        }
    }
    for ((bus, message), net) in buses {
        if net != Val::ZERO {
            out.push(Violation::Unbalanced {
                bus,
                message,
                net: net.as_canonical_u32(),
            });
        }
    }
    out
}

type BusKey = (String, Vec<u32>);
/// Constraint failures, global and local interactions of one row.
type RowEval = (Vec<usize>, Vec<(BusKey, Val)>, Vec<(Vec<u32>, Val)>);

/// Evaluates one row; returns its constraint failures and interactions.
fn eval_row<A>(
    air: &A,
    trace: &RowMajorMatrix<Val>,
    prep: Option<&RowMajorMatrix<Val>>,
    public: &[Val],
    r: usize,
) -> RowEval
where
    A: for<'a> Air<EvalBuilder<'a>>,
{
    let (h, w) = (trace.height(), trace.width());
    let n = (r + 1) % h;
    let empty: Vec<Val> = Vec::new();
    let (pc, pn): (&[Val], &[Val]) = match prep {
        Some(p) => {
            let pw = p.width();
            (
                &p.values[r * pw..(r + 1) * pw],
                &p.values[n * pw..(n + 1) * pw],
            )
        }
        None => (&empty, &empty),
    };
    let mut b = EvalBuilder {
        main: RowWindow::from_two_rows(
            &trace.values[r * w..(r + 1) * w],
            &trace.values[n * w..(n + 1) * w],
        ),
        prep: RowWindow::from_two_rows(pc, pn),
        public,
        first: Val::from_bool(r == 0),
        last: Val::from_bool(r == h - 1),
        transition: Val::from_bool(r != h - 1),
        constraint: 0,
        failures: Vec::new(),
        global: Vec::new(),
        local: Vec::new(),
    };
    air.eval(&mut b);
    let global = b
        .global
        .into_iter()
        .map(|(bus, f, c)| ((bus, f.iter().map(|x| x.as_canonical_u32()).collect()), c))
        .collect();
    let local = b
        .local
        .into_iter()
        .map(|(f, c)| (f.iter().map(|x| x.as_canonical_u32()).collect(), c))
        .collect();
    (b.failures, global, local)
}

/// Incremental checker for mutation testing: evaluates a valid statement
/// once, then answers "is this single-cell mutation caught?" by re-evaluating
/// only the two rows whose constraints read the cell (the row and its
/// predecessor) and adjusting the bus sums.
pub struct MutationChecker<'x, A> {
    airs: &'x [A],
    traces: Vec<RowMajorMatrix<Val>>,
    preps: Vec<Option<RowMajorMatrix<Val>>>,
    public: &'x [Vec<Val>],
    buses: BTreeMap<BusKey, Val>,
}

impl<'x, A> MutationChecker<'x, A>
where
    A: for<'a> Air<EvalBuilder<'a>> + BaseAir<Val>,
{
    /// Panics if the statement is not already valid.
    pub fn new(airs: &'x [A], traces: &[RowMajorMatrix<Val>], public: &'x [Vec<Val>]) -> Self {
        assert_eq!(
            check(airs, traces, public),
            vec![],
            "baseline must be valid"
        );
        let preps: Vec<_> = airs.iter().map(|a| a.periodic_columns_matrix()).collect();
        let mut buses = BTreeMap::new();
        for (t, air) in airs.iter().enumerate() {
            for r in 0..traces[t].height() {
                for (k, c) in eval_row(air, &traces[t], preps[t].as_ref(), &public[t], r).1 {
                    *buses.entry(k).or_insert(Val::ZERO) += c;
                }
            }
        }
        Self {
            airs,
            traces: traces.to_vec(),
            preps,
            public,
            buses,
        }
    }

    /// Whether setting `traces[table][row][col] += delta` is detected.
    pub fn caught(&mut self, table: usize, row: usize, col: usize, delta: Val) -> bool {
        let h = self.traces[table].height();
        let w = self.traces[table].width();
        let rows = [(row + h - 1) % h, row];
        let (air, prep, public) = (
            &self.airs[table],
            self.preps[table].as_ref(),
            &self.public[table],
        );
        let before: Vec<_> = rows
            .iter()
            .map(|&r| eval_row(air, &self.traces[table], prep, public, r))
            .collect();
        self.traces[table].values[row * w + col] += delta;
        let after: Vec<_> = rows
            .iter()
            .map(|&r| eval_row(air, &self.traces[table], prep, public, r))
            .collect();
        self.traces[table].values[row * w + col] -= delta;
        if after.iter().any(|(f, _, _)| !f.is_empty()) {
            return true;
        }
        // Local interactions: the mutated table's local sums must still balance.
        let mut local: BTreeMap<Vec<u32>, Val> = BTreeMap::new();
        for (x, y) in before.iter().zip(&after) {
            for (k, c) in &x.2 {
                *local.entry(k.clone()).or_insert(Val::ZERO) -= *c;
            }
            for (k, c) in &y.2 {
                *local.entry(k.clone()).or_insert(Val::ZERO) += *c;
            }
        }
        if local.values().any(|v| *v != Val::ZERO) {
            return true;
        }
        let mut delta_bus: BTreeMap<BusKey, Val> = BTreeMap::new();
        for (x, y) in before.iter().zip(&after) {
            for (k, c) in &x.1 {
                *delta_bus.entry(k.clone()).or_insert(Val::ZERO) -= *c;
            }
            for (k, c) in &y.1 {
                *delta_bus.entry(k.clone()).or_insert(Val::ZERO) += *c;
            }
        }
        delta_bus
            .iter()
            .any(|(k, d)| *self.buses.get(k).unwrap_or(&Val::ZERO) + *d != Val::ZERO)
    }
}

/// Per-table counts used for the security check of a statement's shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableShape {
    pub constraints: usize,
    pub interactions: usize,
    pub main_width: usize,
    pub prep_width: usize,
}

/// Counts every table's constraints and bus interactions (by evaluating one
/// row of the given traces).
pub fn shapes<A>(airs: &[A], traces: &[RowMajorMatrix<Val>], public: &[Vec<Val>]) -> Vec<TableShape>
where
    A: for<'a> Air<EvalBuilder<'a>> + BaseAir<Val>,
{
    airs.iter()
        .enumerate()
        .map(|(t, air)| {
            let prep = air.periodic_columns_matrix();
            let w = traces[t].width();
            let mut b = EvalBuilder {
                main: RowWindow::from_two_rows(&traces[t].values[..w], &traces[t].values[w..2 * w]),
                prep: match &prep {
                    Some(p) => RowWindow::from_two_rows(
                        &p.values[..p.width()],
                        &p.values[p.width()..2 * p.width()],
                    ),
                    None => RowWindow::from_two_rows(&[], &[]),
                },
                public: &public[t],
                first: Val::ONE,
                last: Val::ZERO,
                transition: Val::ONE,
                constraint: 0,
                failures: Vec::new(),
                global: Vec::new(),
                local: Vec::new(),
            };
            air.eval(&mut b);
            TableShape {
                constraints: b.constraint,
                interactions: b.global.len() + b.local.len(),
                main_width: w,
                prep_width: prep.map_or(0, |p| p.width()),
            }
        })
        .collect()
}
