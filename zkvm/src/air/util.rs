//! Shared constraint helpers: buses, ALU operation ids, byte range checks.

use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;

/// Byte-pair range checks: `(x, y)` with `x, y ∈ [0, 256)`.
pub const RANGE: LookupBus<'static> = LookupBus::new("bvm/byte-range");
/// Byte operations: `(op, a, b, a op b)` for `op ∈ {AND, OR, XOR}`.
pub const BYTE_OP: LookupBus<'static> = LookupBus::new("bvm/byte-op");
/// ALU requests: `(op, a0..a3, b0..b3, c0..c3)`.
pub const ALU: LookupBus<'static> = LookupBus::new("bvm/alu");
/// Instruction fetch: `(exec, pc, decoded fields…)` (see `program::f`).
pub const PROGRAM: LookupBus<'static> = LookupBus::new("bvm/program");
/// Initial image: `(exec, key, v0..v3)`, each image word exactly once.
pub const IMAGE: LookupBus<'static> = LookupBus::new("bvm/image");
/// Public output: `(exec, index, v0..v3)`, each output word exactly once.
pub const OUTPUT: LookupBus<'static> = LookupBus::new("bvm/output");
/// Syscalls served by other tables: `(exec, clk, ptr0..ptr3)` for POSEIDON2.
pub const SYSCALL: LookupBus<'static> = LookupBus::new("bvm/syscall");
/// The offline memory argument (zkvm.md §6.3): `(exec, key, v0..v3, ts)`.
/// Producing an entry counts +1, consuming it −1.
///
/// **Execution tags.** A proof may cover several executions (zkvm.md §6.5).
/// Every message on the memory, program, image, output and syscall buses
/// starts with the execution's id, so no execution can read another's
/// memory, fetch another's code or emit another's outputs. The ALU and byte
/// buses are pure functions of their operands and are shared untagged.
pub const MEMORY: &str = "bvm/memory";

/// Keys of the memory argument: memory words use their word index (< 2^26),
/// registers `REG_BASE + r`. All keys are < 2^27.
pub const REG_BASE: u32 = 1 << 26;

/// Produces `(exec, key, v, ts)` on the memory bus `count ∈ {0, 1}` times.
pub fn mem_produce<AB: InteractionBuilder>(
    b: &mut AB,
    exec: AB::Expr,
    key: AB::Expr,
    v: &[AB::Expr],
    ts: AB::Expr,
    count: AB::Expr,
) {
    let mut msg = vec![exec, key];
    msg.extend_from_slice(v);
    msg.push(ts);
    b.push_interaction(MEMORY, msg, Count::bounded(count, 1));
}

/// Consumes `(exec, key, v, ts)` from the memory bus `count ∈ {0, 1}` times.
pub fn mem_consume<AB: InteractionBuilder>(
    b: &mut AB,
    exec: AB::Expr,
    key: AB::Expr,
    v: &[AB::Expr],
    ts: AB::Expr,
    count: AB::Expr,
) {
    let mut msg = vec![exec, key];
    msg.extend_from_slice(v);
    msg.push(ts);
    b.push_interaction(MEMORY, msg, Count::bounded(-count, 1));
}

/// Operation ids on the byte-operation bus.
pub mod byte_op {
    pub const AND: u32 = 1;
    pub const OR: u32 = 2;
    pub const XOR: u32 = 3;
}

/// Operation ids on the ALU bus (zkvm.md §6.2).
pub mod alu_op {
    pub const ADD: u32 = 1;
    pub const SUB: u32 = 2;
    pub const SLL: u32 = 3;
    pub const SRL: u32 = 4;
    pub const SRA: u32 = 5;
    pub const SLT: u32 = 6;
    pub const SLTU: u32 = 7;
    pub const XOR: u32 = 8;
    pub const OR: u32 = 9;
    pub const AND: u32 = 10;
    pub const MUL: u32 = 11;
    pub const MULH: u32 = 12;
    pub const MULHSU: u32 = 13;
    pub const MULHU: u32 = 14;
    /// `c = (a == b)`.
    pub const EQ: u32 = 15;
}

/// Current-row values of a table as expressions.
pub fn row<AB: AirBuilder>(b: &AB) -> (Vec<AB::Expr>, Vec<AB::Expr>) {
    use p3_air::WindowAccess;
    let m = b.main();
    (
        m.current_slice().iter().map(|v| (*v).into()).collect(),
        m.next_slice().iter().map(|v| (*v).into()).collect(),
    )
}

pub fn prep<AB: AirBuilder>(b: &AB) -> (Vec<AB::Expr>, Vec<AB::Expr>) {
    use p3_air::WindowAccess;
    let p = b.preprocessed();
    (
        p.current_slice().iter().map(|v| (*v).into()).collect(),
        p.next_slice().iter().map(|v| (*v).into()).collect(),
    )
}

pub fn c<AB: AirBuilder>(v: u32) -> AB::Expr {
    AB::Expr::from_u32(v)
}

/// Looks up `(x, y)` in the byte-range table, `count ∈ {0, 1}` times.
pub fn range_pair<AB: InteractionBuilder>(b: &mut AB, x: AB::Expr, y: AB::Expr, count: AB::Expr) {
    RANGE.lookup_key(b, [x, y], Count::bounded(count, 1));
}

/// Range-checks `x < 2^bits` for `bits ≤ 8` with one lookup of
/// `(x, x · 2^(8 − bits))`: both components must be bytes, and for a byte `x`,
/// `x · 2^(8 − bits) < 256` holds exactly when `x < 2^bits`.
pub fn range_bits<AB: InteractionBuilder>(b: &mut AB, x: AB::Expr, bits: u32, count: AB::Expr) {
    assert!(bits <= 8);
    let scaled = x.clone() * c::<AB>(1 << (8 - bits));
    range_pair(b, x, scaled, count);
}

/// Range-checks the four bytes of a word (two pair lookups).
pub fn range_word<AB: InteractionBuilder>(b: &mut AB, w: &[AB::Expr], count: AB::Expr) {
    range_pair(b, w[0].clone(), w[1].clone(), count.clone());
    range_pair(b, w[2].clone(), w[3].clone(), count);
}

/// Little-endian bytes of `v`.
pub fn bytes(v: u32) -> [Val; 4] {
    v.to_le_bytes().map(Val::from_u8)
}

/// A zero matrix of `height` rows (rounded up to a power of two, at least
/// `min`) and `width` columns, filled row by row from `rows`.
pub fn matrix(rows: Vec<Vec<Val>>, width: usize, min: usize) -> RowMajorMatrix<Val> {
    let h = rows.len().max(min).next_power_of_two();
    let mut v = vec![Val::ZERO; h * width];
    for (i, r) in rows.into_iter().enumerate() {
        assert_eq!(r.len(), width, "row width");
        v[i * width..(i + 1) * width].copy_from_slice(&r);
    }
    RowMajorMatrix::new(v, width)
}
