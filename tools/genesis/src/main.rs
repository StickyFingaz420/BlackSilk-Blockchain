//! `blacksilk-genesis`: builds or verifies a genesis block from its announced
//! inputs and a Bitcoin block-hash beacon (docs/testnet-v3-genesis.md).
//!
//! ```text
//! blacksilk-genesis generate --network-id 0x0001D673 --timestamp <T_g> --difficulty <D0> \
//!                            --btc-height <H> --btc-hash <hex, display order>
//! blacksilk-genesis verify   (the same inputs) --expected-id <hex>
//! blacksilk-genesis difficulty --hashrate-mhs <milli-hashes/s> [--target 120]
//! ```

#![forbid(unsafe_code)]

use blacksilk_genesis::{
    build, generate, parse_beacon_hex, report, rust_constants, starting_difficulty, verify,
    GenesisInputs,
};
use std::collections::HashMap;
use std::process::ExitCode;

const USAGE: &str = "usage:
  blacksilk-genesis generate --network-id <id> --timestamp <unix s> --difficulty <D0> --btc-height <H> --btc-hash <hex>
  blacksilk-genesis verify   --network-id <id> --timestamp <unix s> --difficulty <D0> --btc-height <H> --btc-hash <hex> --expected-id <hex>
  blacksilk-genesis difficulty --hashrate-mhs <milli-hashes per second> [--target <seconds, default 120>]
The Bitcoin hash is given in display order (as `bitcoin-cli getblockhash H` prints it).
`generate` refuses a timestamp later than the current time (docs/testnet-v3-genesis.md).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
    match cmd.as_str() {
        "generate" => {
            let inputs = inputs(&flags)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let g = generate(&inputs, now).map_err(|e| e.to_string())?;
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
                Ok(g) => Ok(format!("{}OK: the genesis id matches\n", report(&inputs, &g))),
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
