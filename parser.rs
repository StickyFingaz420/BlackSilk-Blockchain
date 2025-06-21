//! Parser for Dilithium2 C reference output to Rust-friendly JSON KATs
//! Place in build.rs as `mod parser;`

use std::fs;

/// Parse the C reference output and return JSON string
pub fn parse_ref_output(path: &str) -> String {
    let text = fs::read_to_string(path).expect("Failed to read ref_dilithium2.txt");
    let mut tests = Vec::new();
    let mut seed = String::new();
    let mut pk = String::new();
    let mut sk = String::new();
    let mut sig = String::new();
    let mut msg = String::new();
    let mut tcid = 0;
    for line in text.lines() {
        if line.starts_with("seed = ") {
            seed = line[7..].trim().to_string();
        } else if line.starts_with("pk = ") {
            pk = line[5..].trim().to_string();
        } else if line.starts_with("sk = ") {
            sk = line[5..].trim().to_string();
        } else if line.starts_with("msg = ") {
            msg = line[6..].trim().to_string();
        } else if line.starts_with("sm = ") {
            // sm = <sig||msg>, sig is first SIGNATURE_BYTES*2 hex chars
            let sm = line[5..].trim();
            let sig_len = 2420 * 2; // Dilithium2 signature length in hex
            sig = sm[..sig_len].to_string();
            // Save test vector
            tests.push(format!(
                "{{\"tcId\":{},\"seed\":\"{}\",\"pk\":\"{}\",\"sk\":\"{}\",\"msg\":\"{}\",\"sig\":\"{}\"}}",
                tcid, seed, pk, sk, msg, sig
            ));
            tcid += 1;
        }
    }
    format!("{{\"testGroups\":[{{\"tests\":[{}]}}]}}", tests.join(","))
}
