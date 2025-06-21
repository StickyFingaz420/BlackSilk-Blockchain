use std::fs;
use std::path::Path;
use reqwest::blocking::get;

const BASE: &str = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files";
const URLS: &[(&str, &str)] = &[
    ("ML-DSA-keyGen-FIPS204", "kats/ML-DSA-keyGen-FIPS204.json"),
    ("ML-DSA-sigGen-FIPS204", "kats/ML-DSA-sigGen-FIPS204.json"),
    ("ML-DSA-sigVer-FIPS204", "kats/ML-DSA-sigVer-FIPS204.json"),
];

fn fetch() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("kats")?;
    for (src, dst) in URLS {
        let url = format!("{}/{}", BASE, src);
        let dst = Path::new(dst);
        if !dst.exists() {
            println!("Downloading {}", &url);
            let bytes = get(&url)?.bytes()?;
            fs::write(dst, bytes)?;
        }
    }
    Ok(())
}

mod parser;
use std::process::Command;

fn main() {
    // Path to the KAT JSON file
    let kat_json = "kats/ML-DSA-sigGen-FIPS204.json";
    if Path::new(kat_json).exists() {
        println!("cargo:rerun-if-changed={}", kat_json);
        return;
    }

    // Clone the reference repo if not present
    if !Path::new("dilithium").exists() {
        let status = Command::new("git")
            .args(["clone", "https://github.com/pq-crystals/dilithium.git"])
            .status()
            .expect("Failed to clone dilithium repo");
        assert!(status.success(), "Git clone failed");
    }

    // Build the reference implementation
    let status = Command::new("make")
        .current_dir("dilithium/ref")
        .status()
        .expect("Failed to build dilithium reference");
    assert!(status.success(), "Make failed");

    // Run the test vector generator
    let output = Command::new("./test_vectors2")
        .current_dir("dilithium/ref")
        .output()
        .expect("Failed to run test_vectors2");
    assert!(output.status.success(), "test_vectors2 failed");
    fs::write("ref_dilithium2.txt", &output.stdout).expect("Failed to write ref_dilithium2.txt");

    // Parse and convert to JSON
    let parsed = parser::parse_ref_output("ref_dilithium2.txt");
    fs::create_dir_all("kats").ok();
    fs::write(kat_json, parsed).expect("Failed to write KAT JSON");
    fetch().unwrap();
}
