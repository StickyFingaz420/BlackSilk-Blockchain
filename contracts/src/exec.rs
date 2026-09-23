//! Deterministic execution of contract calls and deploys (docs/contracts.md §9).
//!
//! [`Executor::call`] and [`Executor::deploy`] run against a read-only
//! [`ContractState`] and return a [`Receipt`] with the [`StateDiff`] to commit,
//! or an [`ExecError`]. Nothing is written on failure. Every failure makes the
//! whole transaction invalid (§9.2); there is no partial execution.
//!
//! The facts a call carries (auth keys, claims, membership proofs) must already
//! be verified by the transaction layer. This module only exposes them.

use crate::profile::{self, ENTRY_CALL, ENTRY_INIT, HOST_MODULE};
use crate::state::{code_hash, entry_size, ContractState, StateDiff};
use crate::types::{ClaimFact, Id, MemberFact, Note};
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_crypto::Point;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use wasmi::core::TrapCode;
use wasmi::{
    Caller, CompilationMode, Config, EnforcedLimits, Engine, Error, Extern, Linker, Memory, Module,
    StackLimits, Store,
};

// ---- limits (§5, §9) ----

/// Longest call input and init input.
pub const MAX_INPUT: usize = 16_384;
/// Longest return value of a contract.
pub const MAX_RETURN: usize = 4_096;
pub const MAX_KEY: usize = 64;
pub const MAX_VALUE: usize = 4_096;
/// Deepest call stack, including the top-level contract.
pub const MAX_DEPTH: usize = 4;
/// Key–value bytes per contract.
pub const MAX_CONTRACT_KV_BYTES: u64 = 4 * 1024 * 1024;
/// Key sets per contract (`set_id < MAX_KEYSETS`) and keys per set.
pub const MAX_KEYSETS: u32 = 256;
pub const MAX_KEYSET_LEN: usize = 65_536;
/// Storage accounting for notes and key-set members (§9.6).
pub const NOTE_STATE_BYTES: i64 = 200;
pub const KEYSET_MEMBER_BYTES: i64 = 36;

// ---- host fuel costs (§9.5) ----

pub mod fuel {
    pub const HOST_BASE: u64 = 100;
    pub const PER_BYTE: u64 = 1;
    pub const GET_BASE: u64 = 500;
    pub const SET_BASE: u64 = 1_000;
    pub const SET_PER_BYTE: u64 = 10;
    pub const HASH_BASE: u64 = 2_000;
    pub const HASH_PER_BYTE: u64 = 10;
    pub const KEYSET_ADD: u64 = 5_000;
    pub const CALL_BASE: u64 = 10_000;
    /// Instantiating a module (top level or nested) costs one unit per code byte.
    pub const INSTANTIATE_PER_BYTE: u64 = 1;
}

/// A contract call, with facts already verified (§5.2, §11).
#[derive(Clone, Debug, Default)]
pub struct CallRequest {
    pub target: Id,
    pub access: Vec<Id>,
    pub input: Vec<u8>,
    pub fuel_limit: u64,
    pub storage_limit: u64,
    /// Ids of consumed notes, in transaction order.
    pub consumed: Vec<Id>,
    /// New notes, in transaction order, with their ids and owners.
    pub created: Vec<Note>,
    pub auth_keys: Vec<Point>,
    pub claims: Vec<ClaimFact>,
    pub members: Vec<MemberFact>,
    pub height: u64,
    pub network_id: u32,
}

/// A deploy (§5.3).
#[derive(Clone, Debug, Default)]
pub struct DeployRequest {
    pub contract_id: Id,
    pub code: Vec<u8>,
    pub input: Vec<u8>,
    pub fuel_limit: u64,
    pub storage_limit: u64,
    pub height: u64,
    pub network_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub fuel_used: u64,
    /// Net new state bytes (≥ 0) as charged against `storage_limit` (§9.6).
    pub storage_used: u64,
    pub diff: StateDiff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    UnknownContract(Id),
    ContractExists(Id),
    /// A note owner or called contract outside `{target} ∪ access`.
    OutsideAccessList(Id),
    UnknownNote(Id),
    DuplicateNote(Id),
    InputTooLong,
    Profile(profile::ProfileError),
    Compile(String),
    OutOfFuel,
    Abort(i32),
    Trap(String),
    StorageLimit {
        used: u64,
        limit: u64,
    },
    ContractStateFull(Id),
    NoteNotApproved(Id),
    NoteNotAccepted(Id),
}

/// Engine configuration and a cache of compiled modules. Shared by all
/// executions; compiled modules are keyed by code hash.
pub struct Executor {
    engine: Engine,
    modules: Mutex<HashMap<Id, Module>>,
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    pub fn new() -> Self {
        let mut config = Config::default();
        config
            .consume_fuel(true)
            .compilation_mode(CompilationMode::Eager)
            .floats(false)
            .wasm_saturating_float_to_int(false)
            .wasm_multi_memory(false)
            .wasm_tail_call(false)
            .wasm_extended_const(false)
            .wasm_mutable_global(true)
            .wasm_sign_extension(true)
            .wasm_multi_value(true)
            .wasm_bulk_memory(true)
            .wasm_reference_types(true)
            .enforced_limits(EnforcedLimits::strict())
            .set_stack_limits(
                // 1 Mi values of value stack at most, 1024 nested Wasm frames.
                StackLimits::new(1024, 1024 * 1024, 1024).expect("valid stack limits"),
            );
        Self {
            engine: Engine::new(&config),
            modules: Mutex::new(HashMap::new()),
        }
    }

    fn module(&self, code: &[u8]) -> Result<Module, ExecError> {
        let hash = code_hash(code);
        if let Some(m) = self.modules.lock().expect("module cache").get(&hash) {
            return Ok(m.clone());
        }
        let m = Module::new(&self.engine, code).map_err(|e| ExecError::Compile(e.to_string()))?;
        self.modules
            .lock()
            .expect("module cache")
            .insert(hash, m.clone());
        Ok(m)
    }

    /// Validates a module for deploy: the profile (§9.1), then compilation.
    pub fn check_module(&self, code: &[u8]) -> Result<profile::ModuleInfo, ExecError> {
        let info = profile::check(code).map_err(ExecError::Profile)?;
        self.module(code)?;
        Ok(info)
    }

    /// Executes a call against `state`.
    pub fn call(&self, state: &ContractState, req: &CallRequest) -> Result<Receipt, ExecError> {
        if req.input.len() > MAX_INPUT {
            return Err(ExecError::InputTooLong);
        }
        let mut scope: BTreeSet<Id> = BTreeSet::new();
        for id in std::iter::once(&req.target).chain(&req.access) {
            if !state.contract_exists(id) {
                return Err(ExecError::UnknownContract(*id));
            }
            scope.insert(*id);
        }
        let mut consumed = Vec::with_capacity(req.consumed.len());
        let mut seen = BTreeSet::new();
        for id in &req.consumed {
            let note = state.note(id).ok_or(ExecError::UnknownNote(*id))?;
            if !seen.insert(*id) {
                return Err(ExecError::DuplicateNote(*id));
            }
            if !scope.contains(&note.owner) {
                return Err(ExecError::OutsideAccessList(note.owner));
            }
            consumed.push(note.clone());
        }
        for note in &req.created {
            if !scope.contains(&note.owner) {
                return Err(ExecError::OutsideAccessList(note.owner));
            }
            if state.note(&note.id).is_some() || !seen.insert(note.id) {
                return Err(ExecError::DuplicateNote(note.id));
            }
        }
        let code = state
            .contract_code(&req.target)
            .ok_or(ExecError::UnknownContract(req.target))?
            .clone();
        let env = Env {
            state,
            executor: self,
            scope,
            consumed,
            created: req.created.clone(),
            auth_keys: req.auth_keys.clone(),
            claims: req.claims.clone(),
            members: req.members.clone(),
            height: req.height,
            network_id: req.network_id,
        };
        let (mut ctx_out, fuel_used) = run(
            &env,
            req.target,
            &code,
            ENTRY_CALL,
            &req.input,
            req.fuel_limit,
        )?;
        for (i, ok) in ctx_out.approved.iter().enumerate() {
            if !ok {
                return Err(ExecError::NoteNotApproved(env.consumed[i].id));
            }
        }
        for (i, ok) in ctx_out.accepted.iter().enumerate() {
            if !ok {
                return Err(ExecError::NoteNotAccepted(env.created[i].id));
            }
        }
        let mut diff = std::mem::take(&mut ctx_out.diff);
        diff.notes_consumed = req.consumed.clone();
        diff.notes_created = req.created.clone();
        finish(state, diff, fuel_used, req.storage_limit, None)
    }

    /// Executes a deploy: stores the code, creates the contract, runs `bs_init`.
    pub fn deploy(&self, state: &ContractState, req: &DeployRequest) -> Result<Receipt, ExecError> {
        if req.input.len() > MAX_INPUT {
            return Err(ExecError::InputTooLong);
        }
        if state.contract_exists(&req.contract_id) {
            return Err(ExecError::ContractExists(req.contract_id));
        }
        let info = self.check_module(&req.code)?;
        let code = Arc::new(req.code.clone());
        let (mut diff, fuel_used) = if info.has_init {
            let env = Env {
                state,
                executor: self,
                scope: BTreeSet::from([req.contract_id]),
                consumed: Vec::new(),
                created: Vec::new(),
                auth_keys: Vec::new(),
                claims: Vec::new(),
                members: Vec::new(),
                height: req.height,
                network_id: req.network_id,
            };
            let (ctx_out, used) = run(
                &env,
                req.contract_id,
                &code,
                ENTRY_INIT,
                &req.input,
                req.fuel_limit,
            )?;
            (ctx_out.diff, used)
        } else {
            // Without init, validating and storing the code is still charged
            // like one instantiation.
            let used = req.code.len() as u64 * fuel::INSTANTIATE_PER_BYTE;
            if used > req.fuel_limit {
                return Err(ExecError::OutOfFuel);
            }
            (StateDiff::default(), used)
        };
        diff.deployed = Some((req.contract_id, code.clone()));
        let new_code = (!state.code_known(&code_hash(&code))).then_some(code.len() as i64);
        finish(state, diff, fuel_used, req.storage_limit, new_code)
    }
}

/// Storage accounting (§9.6) and per-contract caps.
fn finish(
    state: &ContractState,
    diff: StateDiff,
    fuel_used: u64,
    storage_limit: u64,
    new_code_bytes: Option<i64>,
) -> Result<Receipt, ExecError> {
    let mut used: i64 = new_code_bytes.unwrap_or(0);
    let mut per_contract: BTreeMap<Id, i64> = BTreeMap::new();
    for ((contract, key), value) in &diff.kv {
        let old = state
            .get(contract, key)
            .map_or(0, |v| entry_size(key, v) as i64);
        let new = value.as_ref().map_or(0, |v| entry_size(key, v) as i64);
        used += new - old;
        *per_contract.entry(*contract).or_default() += new - old;
    }
    used += NOTE_STATE_BYTES * (diff.notes_created.len() as i64 - diff.notes_consumed.len() as i64);
    used += KEYSET_MEMBER_BYTES
        * diff
            .keyset_appends
            .values()
            .map(|v| v.len() as i64)
            .sum::<i64>();
    for (contract, delta) in per_contract {
        if state.kv_bytes(&contract) as i64 + delta > MAX_CONTRACT_KV_BYTES as i64 {
            return Err(ExecError::ContractStateFull(contract));
        }
    }
    let used = used.max(0) as u64;
    if used > storage_limit {
        return Err(ExecError::StorageLimit {
            used,
            limit: storage_limit,
        });
    }
    Ok(Receipt {
        fuel_used,
        storage_used: used,
        diff,
    })
}

// ---- execution context ----

/// Read-only inputs of one transaction's execution.
struct Env<'a> {
    state: &'a ContractState,
    executor: &'a Executor,
    /// `{target} ∪ access`: the contracts this transaction may run.
    scope: BTreeSet<Id>,
    consumed: Vec<Note>,
    created: Vec<Note>,
    auth_keys: Vec<Point>,
    claims: Vec<ClaimFact>,
    members: Vec<MemberFact>,
    height: u64,
    network_id: u32,
}

struct Frame {
    contract: Id,
    input: Vec<u8>,
    ret: Vec<u8>,
}

/// Mutable execution state, owned by the wasmi store.
struct Ctx<'a> {
    env: &'a Env<'a>,
    linker: Rc<Linker<Ctx<'a>>>,
    stack: Vec<Frame>,
    last_result: Vec<u8>,
    approved: Vec<bool>,
    accepted: Vec<bool>,
    abort: Option<i32>,
    /// Key–value writes and key-set appends (notes are declared by the tx).
    diff: StateDiff,
}

impl Ctx<'_> {
    fn frame(&self) -> &Frame {
        self.stack.last().expect("inside a frame")
    }

    fn contract(&self) -> Id {
        self.frame().contract
    }

    fn get(&self, contract: &Id, key: &[u8]) -> Option<Vec<u8>> {
        match self.diff.kv.get(&(*contract, key.to_vec())) {
            Some(v) => v.clone(),
            None => self.env.state.get(contract, key).cloned(),
        }
    }

    fn keyset_len(&self, contract: &Id, set: u32) -> usize {
        self.env.state.keyset(contract, set).len()
            + self
                .diff
                .keyset_appends
                .get(&(*contract, set))
                .map_or(0, Vec::len)
    }

    fn keyset_get(&self, contract: &Id, set: u32, i: usize) -> Option<Point> {
        let base = self.env.state.keyset(contract, set);
        if i < base.len() {
            return Some(base[i]);
        }
        self.diff
            .keyset_appends
            .get(&(*contract, set))
            .and_then(|v| v.get(i - base.len()).copied())
    }

    /// Indices (in transaction order) of consumed notes owned by the current contract.
    fn own_consumed(&self) -> Vec<usize> {
        let me = self.contract();
        (0..self.env.consumed.len())
            .filter(|i| self.env.consumed[*i].owner == me)
            .collect()
    }

    fn own_created(&self) -> Vec<usize> {
        let me = self.contract();
        (0..self.env.created.len())
            .filter(|i| self.env.created[*i].owner == me)
            .collect()
    }

    fn own_members(&self) -> Vec<usize> {
        let me = self.contract();
        (0..self.env.members.len())
            .filter(|i| self.env.members[*i].owner == me)
            .collect()
    }
}

/// Runs `entry` of `code` as `contract` with a fresh store and `fuel_limit`.
fn run<'a>(
    env: &'a Env<'a>,
    contract: Id,
    code: &[u8],
    entry: &str,
    input: &[u8],
    fuel_limit: u64,
) -> Result<(Ctx<'a>, u64), ExecError> {
    let module = env.executor.module(code)?;
    let linker = Rc::new(host_linker(&env.executor.engine));
    let ctx = Ctx {
        env,
        linker: linker.clone(),
        stack: Vec::new(),
        last_result: Vec::new(),
        approved: vec![false; env.consumed.len()],
        accepted: vec![false; env.created.len()],
        abort: None,
        diff: StateDiff::default(),
    };
    let mut store = Store::new(&env.executor.engine, ctx);
    store
        .set_fuel(fuel_limit)
        .expect("fuel metering is enabled");
    let result = (|| {
        charge_store(&mut store, code.len() as u64 * fuel::INSTANTIATE_PER_BYTE)?;
        store.data_mut().stack.push(Frame {
            contract,
            input: input.to_vec(),
            ret: Vec::new(),
        });
        let instance = linker
            .instantiate(&mut store, &module)?
            .ensure_no_start(&mut store)?;
        instance
            .get_typed_func::<(), ()>(&store, entry)?
            .call(&mut store, ())
    })();
    let remaining = store.get_fuel().unwrap_or(0);
    let mut ctx = store.into_data();
    if let Err(e) = result {
        return Err(map_error(&ctx, e));
    }
    ctx.stack.clear();
    Ok((ctx, fuel_limit - remaining))
}

fn map_error(ctx: &Ctx<'_>, e: Error) -> ExecError {
    if let Some(code) = ctx.abort {
        return ExecError::Abort(code);
    }
    match e.as_trap_code() {
        Some(TrapCode::OutOfFuel) => ExecError::OutOfFuel,
        _ => ExecError::Trap(e.to_string()),
    }
}

fn charge_store(store: &mut Store<Ctx<'_>>, amount: u64) -> Result<(), Error> {
    let f = store.get_fuel()?;
    if f < amount {
        store.set_fuel(0)?;
        return Err(TrapCode::OutOfFuel.into());
    }
    store.set_fuel(f - amount)
}

// ---- host functions (§9.3) ----

type C<'c, 'a> = Caller<'c, Ctx<'a>>;

fn trap(msg: &str) -> Error {
    Error::new(msg.to_string())
}

fn charge(c: &mut C<'_, '_>, amount: u64) -> Result<(), Error> {
    let f = c.get_fuel()?;
    if f < amount {
        c.set_fuel(0)?;
        return Err(TrapCode::OutOfFuel.into());
    }
    c.set_fuel(f - amount)
}

fn memory(c: &C<'_, '_>) -> Result<Memory, Error> {
    c.get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| trap("module has no memory"))
}

fn read(c: &C<'_, '_>, ptr: i32, len: i32) -> Result<Vec<u8>, Error> {
    let mem = memory(c)?;
    let len = len as u32 as usize;
    // Bounded by the memory size (≤ 2 MiB), checked before allocating.
    if len > mem.data(c).len() {
        return Err(trap("read out of bounds"));
    }
    let mut buf = vec![0u8; len];
    mem.read(c, ptr as u32 as usize, &mut buf)
        .map_err(|_| trap("read out of bounds"))?;
    Ok(buf)
}

fn read32(c: &C<'_, '_>, ptr: i32) -> Result<[u8; 32], Error> {
    let v = read(c, ptr, 32)?;
    Ok(v.try_into().expect("32 bytes"))
}

fn write(c: &mut C<'_, '_>, ptr: i32, data: &[u8]) -> Result<(), Error> {
    let mem = memory(c)?;
    mem.write(c, ptr as u32 as usize, data)
        .map_err(|_| trap("write out of bounds"))
}

fn index(i: i32, len: usize) -> Result<usize, Error> {
    let i = i as u32 as usize;
    if i < len {
        Ok(i)
    } else {
        Err(trap("index out of range"))
    }
}

fn input_len(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().frame().input.len() as i32)
}

fn input_read(mut c: C<'_, '_>, ptr: i32) -> Result<(), Error> {
    let data = c.data().frame().input.clone();
    charge(&mut c, fuel::HOST_BASE + data.len() as u64 * fuel::PER_BYTE)?;
    write(&mut c, ptr, &data)
}

fn return_write(mut c: C<'_, '_>, ptr: i32, len: i32) -> Result<(), Error> {
    if len as u32 as usize > MAX_RETURN {
        return Err(trap("return value too long"));
    }
    charge(&mut c, fuel::HOST_BASE + len as u32 as u64 * fuel::PER_BYTE)?;
    let data = read(&c, ptr, len)?;
    c.data_mut().stack.last_mut().expect("frame").ret = data;
    Ok(())
}

fn abort(mut c: C<'_, '_>, code: i32) -> Result<(), Error> {
    c.data_mut().abort = Some(code);
    Err(trap("contract aborted"))
}

fn height(mut c: C<'_, '_>) -> Result<i64, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().env.height as i64)
}

fn self_id(mut c: C<'_, '_>, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 32)?;
    let id = c.data().contract();
    write(&mut c, ptr, &id)
}

fn caller(mut c: C<'_, '_>, ptr: i32) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE + 32)?;
    let stack = &c.data().stack;
    if stack.len() < 2 {
        return Ok(0);
    }
    let id = stack[stack.len() - 2].contract;
    write(&mut c, ptr, &id)?;
    Ok(1)
}

fn network_id(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().env.network_id as i32)
}

fn key_arg(c: &C<'_, '_>, kp: i32, kl: i32) -> Result<Vec<u8>, Error> {
    let len = kl as u32 as usize;
    if len == 0 || len > MAX_KEY {
        return Err(trap("key length must be 1..=64"));
    }
    read(c, kp, kl)
}

fn get(mut c: C<'_, '_>, kp: i32, kl: i32, vp: i32, cap: i32) -> Result<i32, Error> {
    charge(&mut c, fuel::GET_BASE)?;
    let key = key_arg(&c, kp, kl)?;
    let me = c.data().contract();
    let Some(value) = c.data().get(&me, &key) else {
        return Ok(-1);
    };
    charge(&mut c, value.len() as u64 * fuel::PER_BYTE)?;
    let n = value.len().min(cap as u32 as usize);
    write(&mut c, vp, &value[..n])?;
    Ok(value.len() as i32)
}

fn set(mut c: C<'_, '_>, kp: i32, kl: i32, vp: i32, vl: i32) -> Result<(), Error> {
    if vl as u32 as usize > MAX_VALUE {
        return Err(trap("value longer than 4096 bytes"));
    }
    charge(
        &mut c,
        fuel::SET_BASE + (kl as u32 as u64 + vl as u32 as u64) * fuel::SET_PER_BYTE,
    )?;
    let key = key_arg(&c, kp, kl)?;
    let value = read(&c, vp, vl)?;
    let me = c.data().contract();
    c.data_mut().diff.kv.insert((me, key), Some(value));
    Ok(())
}

fn del(mut c: C<'_, '_>, kp: i32, kl: i32) -> Result<(), Error> {
    charge(&mut c, fuel::SET_BASE)?;
    let key = key_arg(&c, kp, kl)?;
    let me = c.data().contract();
    c.data_mut().diff.kv.insert((me, key), None);
    Ok(())
}

fn consumed_count(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().own_consumed().len() as i32)
}

fn consumed(mut c: C<'_, '_>, i: i32, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 200)?;
    let own = c.data().own_consumed();
    let g = own[index(i, own.len())?];
    let rec = c.data().env.consumed[g].record(g as u16);
    write(&mut c, ptr, &rec)
}

fn created_count(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().own_created().len() as i32)
}

fn created(mut c: C<'_, '_>, i: i32, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 200)?;
    let own = c.data().own_created();
    let g = own[index(i, own.len())?];
    let rec = c.data().env.created[g].record(g as u16);
    write(&mut c, ptr, &rec)
}

fn approve(mut c: C<'_, '_>, i: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    let own = c.data().own_consumed();
    let g = own[index(i, own.len())?];
    c.data_mut().approved[g] = true;
    Ok(())
}

fn accept(mut c: C<'_, '_>, i: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    let own = c.data().own_created();
    let g = own[index(i, own.len())?];
    c.data_mut().accepted[g] = true;
    Ok(())
}

fn auth_count(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().env.auth_keys.len() as i32)
}

fn auth_key(mut c: C<'_, '_>, i: i32, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 32)?;
    let keys = &c.data().env.auth_keys;
    let key = *keys[index(i, keys.len())?].bytes();
    write(&mut c, ptr, &key)
}

fn auth_has(mut c: C<'_, '_>, ptr: i32) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE + 32)?;
    let key = read32(&c, ptr)?;
    Ok(i32::from(
        c.data().env.auth_keys.iter().any(|k| k.bytes() == &key),
    ))
}

fn claim_count(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().env.claims.len() as i32)
}

fn claim(mut c: C<'_, '_>, i: i32, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 96)?;
    let claims = &c.data().env.claims;
    let rec = claims[index(i, claims.len())?].record();
    write(&mut c, ptr, &rec)
}

fn member_count(mut c: C<'_, '_>) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    Ok(c.data().own_members().len() as i32)
}

fn member(mut c: C<'_, '_>, i: i32, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 80)?;
    let own = c.data().own_members();
    let g = own[index(i, own.len())?];
    let rec = c.data().env.members[g].record();
    write(&mut c, ptr, &rec)
}

fn set_arg(set: i32) -> Result<u32, Error> {
    let set = set as u32;
    if set < MAX_KEYSETS {
        Ok(set)
    } else {
        Err(trap("key set id out of range"))
    }
}

fn keyset_add(mut c: C<'_, '_>, set: i32, ptr: i32) -> Result<i32, Error> {
    charge(&mut c, fuel::KEYSET_ADD)?;
    let set = set_arg(set)?;
    let bytes = read32(&c, ptr)?;
    let key = Point::decode(&bytes)
        .filter(|p| !p.is_identity())
        .ok_or_else(|| trap("invalid key"))?;
    let me = c.data().contract();
    let len = c.data().keyset_len(&me, set);
    if len >= MAX_KEYSET_LEN {
        return Err(trap("key set full"));
    }
    c.data_mut()
        .diff
        .keyset_appends
        .entry((me, set))
        .or_default()
        .push(key);
    Ok(len as i32)
}

fn keyset_len(mut c: C<'_, '_>, set: i32) -> Result<i32, Error> {
    charge(&mut c, fuel::HOST_BASE)?;
    let set = set_arg(set)?;
    let me = c.data().contract();
    Ok(c.data().keyset_len(&me, set) as i32)
}

fn keyset_get(mut c: C<'_, '_>, set: i32, i: i32, ptr: i32) -> Result<(), Error> {
    charge(&mut c, fuel::HOST_BASE + 32)?;
    let set = set_arg(set)?;
    let me = c.data().contract();
    let key = c
        .data()
        .keyset_get(&me, set, i as u32 as usize)
        .ok_or_else(|| trap("index out of range"))?;
    write(&mut c, ptr, key.bytes())
}

fn hash(mut c: C<'_, '_>, ptr: i32, len: i32, out: i32) -> Result<(), Error> {
    charge(
        &mut c,
        fuel::HASH_BASE + len as u32 as u64 * fuel::HASH_PER_BYTE,
    )?;
    let data = read(&c, ptr, len)?;
    let h = h32(tags::CONTRACT_USER_HASH, &[&data]);
    write(&mut c, out, &h)
}

fn point_valid(mut c: C<'_, '_>, ptr: i32) -> Result<i32, Error> {
    charge(&mut c, fuel::HASH_BASE)?;
    let bytes = read32(&c, ptr)?;
    Ok(i32::from(
        Point::decode(&bytes).is_some_and(|p| !p.is_identity()),
    ))
}

fn call(mut c: C<'_, '_>, id_ptr: i32, in_ptr: i32, in_len: i32) -> Result<i32, Error> {
    if in_len as u32 as usize > MAX_INPUT {
        return Err(trap("call input too long"));
    }
    let target = read32(&c, id_ptr)?;
    let input = read(&c, in_ptr, in_len)?;
    let env = c.data().env;
    if !env.scope.contains(&target) {
        return Err(trap("callee not in the access list"));
    }
    if c.data().stack.iter().any(|f| f.contract == target) {
        return Err(trap("reentrant call"));
    }
    if c.data().stack.len() >= MAX_DEPTH {
        return Err(trap("call depth exceeded"));
    }
    let code = env
        .state
        .contract_code(&target)
        .ok_or_else(|| trap("unknown contract"))?
        .clone();
    charge(
        &mut c,
        fuel::CALL_BASE
            + code.len() as u64 * fuel::INSTANTIATE_PER_BYTE
            + input.len() as u64 * fuel::PER_BYTE,
    )?;
    let module = env
        .executor
        .module(&code)
        .map_err(|e| trap(&format!("{e:?}")))?;
    let linker = c.data().linker.clone();
    c.data_mut().stack.push(Frame {
        contract: target,
        input,
        ret: Vec::new(),
    });
    let instance = linker
        .instantiate(&mut c, &module)?
        .ensure_no_start(&mut c)?;
    instance
        .get_typed_func::<(), ()>(&c, ENTRY_CALL)?
        .call(&mut c, ())?;
    let frame = c.data_mut().stack.pop().expect("callee frame");
    let len = frame.ret.len() as i32;
    c.data_mut().last_result = frame.ret;
    Ok(len)
}

fn result_read(mut c: C<'_, '_>, ptr: i32) -> Result<(), Error> {
    let data = c.data().last_result.clone();
    charge(&mut c, fuel::HOST_BASE + data.len() as u64 * fuel::PER_BYTE)?;
    write(&mut c, ptr, &data)
}

/// The host API as a wasmi linker. Names must match `profile::HOST_API`.
fn host_linker<'a>(engine: &Engine) -> Linker<Ctx<'a>> {
    let mut l = Linker::new(engine);
    let m = HOST_MODULE;
    macro_rules! wrap {
        ($($name:ident),* $(,)?) => {
            $( l.func_wrap(m, stringify!($name), $name).expect("unique host function"); )*
        };
    }
    wrap!(
        input_len,
        input_read,
        return_write,
        abort,
        height,
        self_id,
        caller,
        network_id,
        get,
        set,
        del,
        consumed_count,
        consumed,
        created_count,
        created,
        approve,
        accept,
        auth_count,
        auth_key,
        auth_has,
        claim_count,
        claim,
        member_count,
        member,
        keyset_add,
        keyset_len,
        keyset_get,
        hash,
        point_valid,
        call,
        result_read,
    );
    l
}

/// Names defined by [`host_linker`], for the test that it matches the profile.
pub const HOST_FUNCTIONS: &[&str] = &[
    "input_len",
    "input_read",
    "return_write",
    "abort",
    "height",
    "self_id",
    "caller",
    "network_id",
    "get",
    "set",
    "del",
    "consumed_count",
    "consumed",
    "created_count",
    "created",
    "approve",
    "accept",
    "auth_count",
    "auth_key",
    "auth_has",
    "claim_count",
    "claim",
    "member_count",
    "member",
    "keyset_add",
    "keyset_len",
    "keyset_get",
    "hash",
    "point_valid",
    "call",
    "result_read",
];
