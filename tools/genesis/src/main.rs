//! `blacksilk-genesis`: builds or verifies a genesis block from its announced
//! inputs and a Bitcoin block-hash beacon (docs/testnet-v3-genesis.md).
//!
//! ```text
//! blacksilk-genesis generate --final --network-id 0x0001D673 --timestamp <T_g> \
//!                            --difficulty <D0> --btc-height <H> --btc-hash <hex, display order>
//! blacksilk-genesis generate --rehearsal --network-id 0x0001D6E0 ...
//! blacksilk-genesis verify   (the same inputs, no flag) --expected-id <hex>
//! blacksilk-genesis difficulty --hashrate-mhs <milli-hashes/s> [--target 120]
//! ```

#![forbid(unsafe_code)]

// W4-GUARD: a fuzz build (`--cfg fuzzing`) compiles fuzz-only code into the
// libraries (the transport's fixed ephemeral secrets on request), and no fuzz
// target links this binary (fuzz/Cargo.toml), so it refuses to build. A
// `compile_error!`, not a build script: a build script would be more
// build-time code, and cargo-deny then scans every dependency's files.
#[cfg(fuzzing)]
compile_error!(
    "refusing to build blacksilk-genesis with `--cfg fuzzing`: no fuzz target links it; build it with a plain `cargo build --release`"
);

use blacksilk_genesis::{
    build, generate, parse_beacon_hex, report, rust_constants, starting_difficulty, verify,
    GenesisInputs, Purpose,
};
use std::collections::HashMap;
use std::process::ExitCode;

const USAGE: &str = "usage:
  blacksilk-genesis --version
  blacksilk-genesis generate [--final | --rehearsal] --network-id <id> --timestamp <unix s> --difficulty <D0> --btc-height <H> --btc-hash <hex>
  blacksilk-genesis verify   --network-id <id> --timestamp <unix s> --difficulty <D0> --btc-height <H> --btc-hash <hex> --expected-id <hex>
  blacksilk-genesis difficulty --hashrate-mhs <milli-hashes per second> [--target <seconds, default 120>]
The Bitcoin hash is given in display order (as `bitcoin-cli getblockhash H` prints it).
`generate` refuses a timestamp later than the current time, a registered network id,
and a reserved one outside its purpose: `--final` only for the testnet v3 id 0x0001D673,
`--rehearsal` only for 0x0001D6E0..=0x0001D6EF, never the test-vector id 0xFFFFFF00.
`verify` accepts a registered id only for a built-in network's own compiled genesis
(docs/testnet-v3-genesis.md).";

/// Flags without a value.
const SWITCHES: [&str; 2] = ["final", "rehearsal"];

/// The markers of test-only code compiled into this binary (W4-GUARD). Only
/// a fuzz build (`cfg(fuzzing)`) can add one: blacksilk-consensus, the one
/// dependency, has no test-hooks feature. The crate root refuses to compile a
/// fuzz build (`compile_error!`), and
/// [`check_build`] refuses to run one anyway.
#[cfg(fuzzing)]
const BUILD_MARKERS: &[&str] = &["+fuzzing:genesis"];
/// See the `cfg(fuzzing)` variant: none.
#[cfg(not(fuzzing))]
const BUILD_MARKERS: &[&str] = &[];

/// Exit status of a refused build (test-only code compiled in).
const BUILD_EXIT_CODE: u8 = 2;

/// `build flags: none`, or the markers: printed by `--version`.
fn build_flags_line(markers: &[&str]) -> String {
    if markers.is_empty() {
        "build flags: none".to_string()
    } else {
        format!("build flags: {}", markers.join(" "))
    }
}

/// Genesis material is never made or checked by a binary with test-only code,
/// on any network (W4-GUARD): unconditional, unlike the node's regtest
/// exception.
fn check_build(markers: &[&str]) -> Result<(), String> {
    if markers.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "refusing to run: this blacksilk-genesis was built with test-only code ({}); \
             rebuild it with a plain `cargo build --release` from a clean commit",
            markers.join(" ")
        ))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "--version" || a == "-V") {
        println!(
            "blacksilk-genesis {}\n{}",
            env!("CARGO_PKG_VERSION"),
            build_flags_line(BUILD_MARKERS)
        );
        return ExitCode::SUCCESS;
    }
    if let Err(e) = check_build(BUILD_MARKERS) {
        eprintln!("error: {e}");
        return ExitCode::from(BUILD_EXIT_CODE);
    }
    match run(&args) {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    let (cmd, rest) = args.split_first().ok_or("no command")?;
    let flags = parse_flags(rest)?;
    let switch = |name: &str| flags.contains_key(name);
    if cmd != "generate" && SWITCHES.iter().any(|s| switch(s)) {
        return Err("--final and --rehearsal apply to generate only".into());
    }
    match cmd.as_str() {
        "generate" => {
            let purpose = match (switch("final"), switch("rehearsal")) {
                (true, true) => return Err("--final and --rehearsal exclude each other".into()),
                (true, false) => Purpose::Final,
                (false, true) => Purpose::Rehearsal,
                (false, false) => Purpose::Other,
            };
            let inputs = inputs(&flags)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let g = generate(&inputs, now, purpose).map_err(|e| e.to_string())?;
            Ok(format!(
                "{}\nconstants to paste:\n{}",
                report(&inputs, &g),
                rust_constants(&inputs, &g)
            ))
        }
        "verify" => {
            let inputs = inputs(&flags)?;
            let expected = parse_beacon_hex(get(&flags, "expected-id")?)
                .map_err(|_| "--expected-id must be 64 hex characters")?;
            match verify(&inputs, &expected) {
                Ok(g) => Ok(format!(
                    "{}OK: the genesis id matches\n",
                    report(&inputs, &g)
                )),
                Err(e) => {
                    let detail = build(&inputs)
                        .map(|g| report(&inputs, &g))
                        .unwrap_or_default();
                    Err(format!("{detail}{e}"))
                }
            }
        }
        "difficulty" => {
            let mhs: u64 = num(get(&flags, "hashrate-mhs")?)?;
            let target: u64 = match flags.get("target") {
                Some(t) => num(t)?,
                None => 120,
            };
            Ok(format!(
                "starting difficulty D0 = {}\n",
                starting_difficulty(mhs, target)
            ))
        }
        other => Err(format!("unknown command {other}")),
    }
}

fn parse_flags(rest: &[String]) -> Result<HashMap<String, String>, String> {
    let mut flags = HashMap::new();
    let mut it = rest.iter();
    while let Some(k) = it.next() {
        let name = k
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {k}"))?;
        if SWITCHES.contains(&name) {
            if flags.insert(name.to_string(), String::new()).is_some() {
                return Err(format!("--{name} given twice"));
            }
            continue;
        }
        let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
        if flags.insert(name.to_string(), v.clone()).is_some() {
            return Err(format!("--{name} given twice"));
        }
    }
    Ok(flags)
}

fn get<'a>(flags: &'a HashMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing --{name}"))
}

/// A decimal number, or hexadecimal with a `0x` prefix.
fn num<T: TryFrom<u64>>(s: &str) -> Result<T, String> {
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(&h.replace('_', ""), 16),
        None => s.replace('_', "").parse::<u64>(),
    }
    .map_err(|_| format!("not a number: {s}"))?;
    T::try_from(v).map_err(|_| format!("out of range: {s}"))
}

fn inputs(flags: &HashMap<String, String>) -> Result<GenesisInputs, String> {
    Ok(GenesisInputs {
        network_id: num(get(flags, "network-id")?)?,
        timestamp: num(get(flags, "timestamp")?)?,
        difficulty: num(get(flags, "difficulty")?)?,
        btc_height: num(get(flags, "btc-height")?)?,
        btc_hash: parse_beacon_hex(get(flags, "btc-hash")?).map_err(|e| e.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any marker refuses the run; none allows it, and `--version` names
    /// what is compiled in.
    #[test]
    fn a_marked_genesis_tool_refuses_to_run() {
        assert_eq!(check_build(&[]), Ok(()));
        let e = check_build(&["+fuzzing:genesis"]).unwrap_err();
        assert!(e.contains("+fuzzing:genesis"), "{e}");
        assert_eq!(build_flags_line(&[]), "build flags: none");
        assert_eq!(
            build_flags_line(&["+fuzzing:genesis"]),
            "build flags: +fuzzing:genesis"
        );
        assert_eq!(check_build(BUILD_MARKERS).is_ok(), !cfg!(fuzzing));
    }
}
