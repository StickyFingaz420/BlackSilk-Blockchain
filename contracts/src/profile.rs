//! The consensus module profile (docs/contracts.md §9.1), checked at deploy.
//!
//! Two passes, both on `wasmparser-nostd` 0.100.2 (the parser wasmi 0.38 uses):
//! 1. full validation with a restricted feature set: no floats, SIMD, threads,
//!    tail calls, memory64, multi-memory, exceptions, extended-const,
//!    saturating float conversions or components;
//! 2. our structural rules: imports only from `"bs"` with the exact host
//!    signatures, one bounded memory, at most one bounded funcref table,
//!    required exports, no start function, no passive segments, size limits.
//!
//! The accept/reject decision is therefore defined by this file and its tests,
//! not by whatever an engine version happens to accept.

use std::collections::HashMap;
use wasmparser::{
    DataKind, ElementKind, ExternalKind, Parser, Payload, Type, TypeRef, ValType, Validator,
    WasmFeatures,
};

/// Largest module in bytes.
pub const MAX_CODE: usize = 65_536;
/// Largest linear memory, in 64 KiB pages (2 MiB).
pub const MAX_MEMORY_PAGES: u64 = 32;
pub const MAX_FUNCTIONS: u32 = 1_024;
pub const MAX_GLOBALS: u32 = 1_024;
pub const MAX_LOCALS: u32 = 256;
pub const MAX_TABLE_ELEMENTS: u32 = 1_024;

/// Parameter/result types of the host API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    I32,
    I64,
}

use Abi::{I32, I64};

/// The host API (§9.3): name, parameters, results. `host.rs` implements exactly
/// these; a test checks the two lists agree.
pub const HOST_API: &[(&str, &[Abi], &[Abi])] = &[
    ("input_len", &[], &[I32]),
    ("input_read", &[I32], &[]),
    ("return_write", &[I32, I32], &[]),
    ("abort", &[I32], &[]),
    ("height", &[], &[I64]),
    ("self_id", &[I32], &[]),
    ("caller", &[I32], &[I32]),
    ("network_id", &[], &[I32]),
    ("get", &[I32, I32, I32, I32], &[I32]),
    ("set", &[I32, I32, I32, I32], &[]),
    ("del", &[I32, I32], &[]),
    ("consumed_count", &[], &[I32]),
    ("consumed", &[I32, I32], &[]),
    ("created_count", &[], &[I32]),
    ("created", &[I32, I32], &[]),
    ("approve", &[I32], &[]),
    ("accept", &[I32], &[]),
    ("auth_count", &[], &[I32]),
    ("auth_key", &[I32, I32], &[]),
    ("auth_has", &[I32], &[I32]),
    ("claim_count", &[], &[I32]),
    ("claim", &[I32, I32], &[]),
    ("member_count", &[], &[I32]),
    ("member", &[I32, I32], &[]),
    ("keyset_add", &[I32, I32], &[I32]),
    ("keyset_len", &[I32], &[I32]),
    ("keyset_get", &[I32, I32, I32], &[]),
    ("hash", &[I32, I32, I32], &[]),
    ("point_valid", &[I32], &[I32]),
    ("call", &[I32, I32, I32], &[I32]),
    ("result_read", &[I32], &[]),
];

pub const HOST_MODULE: &str = "bs";
pub const ENTRY_CALL: &str = "bs_call";
pub const ENTRY_INIT: &str = "bs_init";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    TooLarge(usize),
    /// Rejected by validation with the restricted feature set (includes floats).
    Invalid(String),
    ForeignImport(String),
    WrongImportSignature(String),
    ImportedNonFunction(String),
    Memory(&'static str),
    Table(&'static str),
    TooManyFunctions,
    TooManyGlobals,
    TooManyLocals,
    StartFunction,
    PassiveSegment,
    MissingExport(&'static str),
    WrongExportType(&'static str),
    Unsupported(&'static str),
}

/// What the engine needs to know about an accepted module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleInfo {
    pub has_init: bool,
}

fn features() -> WasmFeatures {
    WasmFeatures {
        mutable_global: true,
        saturating_float_to_int: false,
        sign_extension: true,
        reference_types: true,
        multi_value: true,
        bulk_memory: true,
        simd: false,
        relaxed_simd: false,
        threads: false,
        tail_call: false,
        floats: false,
        multi_memory: false,
        exceptions: false,
        memory64: false,
        extended_const: false,
        component_model: false,
        memory_control: false,
    }
}

fn abi(v: &ValType) -> Option<Abi> {
    match v {
        ValType::I32 => Some(I32),
        ValType::I64 => Some(I64),
        _ => None,
    }
}

fn signature_matches(params: &[ValType], results: &[ValType], want: (&[Abi], &[Abi])) -> bool {
    let conv = |vs: &[ValType]| vs.iter().map(abi).collect::<Option<Vec<_>>>();
    conv(params).as_deref() == Some(want.0) && conv(results).as_deref() == Some(want.1)
}

/// Checks `code` against the profile.
pub fn check(code: &[u8]) -> Result<ModuleInfo, ProfileError> {
    if code.len() > MAX_CODE {
        return Err(ProfileError::TooLarge(code.len()));
    }
    Validator::new_with_features(features())
        .validate_all(code)
        .map_err(|e| ProfileError::Invalid(e.message().to_string()))?;

    let host: HashMap<&str, (&[Abi], &[Abi])> =
        HOST_API.iter().map(|(n, p, r)| (*n, (*p, *r))).collect();
    let mut types: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
    // Type index of every function (imports first, then defined functions).
    let mut func_types: Vec<u32> = Vec::new();
    let mut memories = 0u32;
    let mut tables = 0u32;
    let mut globals = 0u32;
    let mut exports: HashMap<String, (ExternalKind, u32)> = HashMap::new();

    for payload in Parser::new(0).parse_all(code) {
        let payload = payload.map_err(|e| ProfileError::Invalid(e.message().to_string()))?;
        let invalid =
            |e: wasmparser::BinaryReaderError| ProfileError::Invalid(e.message().to_string());
        match payload {
            Payload::Version { .. } | Payload::CustomSection(_) | Payload::End(_) => {}
            Payload::TypeSection(reader) => {
                for ty in reader {
                    let Type::Func(f) = ty.map_err(invalid)?;
                    types.push((f.params().to_vec(), f.results().to_vec()));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(invalid)?;
                    let name = format!("{}::{}", import.module, import.name);
                    if import.module != HOST_MODULE {
                        return Err(ProfileError::ForeignImport(name));
                    }
                    let TypeRef::Func(idx) = import.ty else {
                        return Err(ProfileError::ImportedNonFunction(name));
                    };
                    let want = host
                        .get(import.name)
                        .ok_or_else(|| ProfileError::ForeignImport(name.clone()))?;
                    let (p, r) = &types[idx as usize];
                    if !signature_matches(p, r, *want) {
                        return Err(ProfileError::WrongImportSignature(name));
                    }
                    func_types.push(idx);
                }
            }
            Payload::FunctionSection(reader) => {
                for f in reader {
                    func_types.push(f.map_err(invalid)?);
                }
                if func_types.len() as u32 > MAX_FUNCTIONS {
                    return Err(ProfileError::TooManyFunctions);
                }
            }
            Payload::TableSection(reader) => {
                for t in reader {
                    let t = t.map_err(invalid)?;
                    tables += 1;
                    if tables > 1 {
                        return Err(ProfileError::Table("more than one table"));
                    }
                    if t.element_type != ValType::FuncRef {
                        return Err(ProfileError::Table("only funcref tables"));
                    }
                    match t.maximum {
                        Some(max) if max <= MAX_TABLE_ELEMENTS && t.initial <= max => {}
                        Some(_) => return Err(ProfileError::Table("table too large")),
                        None => return Err(ProfileError::Table("table maximum missing")),
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for m in reader {
                    let m = m.map_err(invalid)?;
                    memories += 1;
                    if memories > 1 {
                        return Err(ProfileError::Memory("more than one memory"));
                    }
                    if m.memory64 || m.shared {
                        return Err(ProfileError::Memory("memory64 or shared memory"));
                    }
                    match m.maximum {
                        Some(max) if max <= MAX_MEMORY_PAGES && m.initial <= max => {}
                        Some(_) => return Err(ProfileError::Memory("memory too large")),
                        None => return Err(ProfileError::Memory("memory maximum missing")),
                    }
                }
            }
            Payload::GlobalSection(reader) => {
                globals += reader.count();
                if globals > MAX_GLOBALS {
                    return Err(ProfileError::TooManyGlobals);
                }
            }
            Payload::ExportSection(reader) => {
                for e in reader {
                    let e = e.map_err(invalid)?;
                    exports.insert(e.name.to_string(), (e.kind, e.index));
                }
            }
            Payload::StartSection { .. } => return Err(ProfileError::StartFunction),
            Payload::ElementSection(reader) => {
                for el in reader {
                    if matches!(el.map_err(invalid)?.kind, ElementKind::Passive) {
                        return Err(ProfileError::PassiveSegment);
                    }
                }
            }
            Payload::DataCountSection { .. } => {}
            Payload::DataSection(reader) => {
                for d in reader {
                    if matches!(d.map_err(invalid)?.kind, DataKind::Passive) {
                        return Err(ProfileError::PassiveSegment);
                    }
                }
            }
            Payload::CodeSectionStart { .. } => {}
            Payload::CodeSectionEntry(body) => {
                let mut locals = 0u32;
                let mut reader = body.get_locals_reader().map_err(invalid)?;
                for _ in 0..reader.get_count() {
                    let (n, _) = reader.read().map_err(invalid)?;
                    locals = locals.saturating_add(n);
                }
                if locals > MAX_LOCALS {
                    return Err(ProfileError::TooManyLocals);
                }
            }
            Payload::TagSection(_) => return Err(ProfileError::Unsupported("tags")),
            _ => return Err(ProfileError::Unsupported("component or unknown section")),
        }
    }

    if memories != 1 {
        return Err(ProfileError::Memory("exactly one defined memory required"));
    }
    match exports.get("memory") {
        Some((ExternalKind::Memory, 0)) => {}
        Some(_) => return Err(ProfileError::WrongExportType("memory")),
        None => return Err(ProfileError::MissingExport("memory")),
    }
    let entry_ok = |name: &'static str| -> Result<bool, ProfileError> {
        match exports.get(name) {
            None => Ok(false),
            Some((ExternalKind::Func, idx)) => {
                let (p, r) = &types[func_types[*idx as usize] as usize];
                if p.is_empty() && r.is_empty() {
                    Ok(true)
                } else {
                    Err(ProfileError::WrongExportType(name))
                }
            }
            Some(_) => Err(ProfileError::WrongExportType(name)),
        }
    };
    if !entry_ok(ENTRY_CALL)? {
        return Err(ProfileError::MissingExport(ENTRY_CALL));
    }
    Ok(ModuleInfo {
        has_init: entry_ok(ENTRY_INIT)?,
    })
}
