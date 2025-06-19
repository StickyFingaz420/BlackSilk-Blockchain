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

fn main() {
    fetch().unwrap();
}
