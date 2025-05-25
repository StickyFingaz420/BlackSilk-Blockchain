use std::path::Path;
use std::process;

fn main() {
    // Check for header file existence
    let wrapper = Path::new("wrapper.h");
    let randomx = Path::new("randomx.h");
    if !wrapper.exists() {
        eprintln!("[build.rs] ERROR: wrapper.h not found in miner directory. Please ensure it is present.");
        process::exit(1);
    }
    if !randomx.exists() {
        eprintln!("[build.rs] ERROR: randomx.h not found in miner directory. Please ensure it is present.");
        process::exit(1);
    }
    // Tell cargo to tell rustc to link the system randomx
    println!("cargo:rustc-link-lib=dylib=randomx");
    // If you build static, use: println!("cargo:rustc-link-lib=static=randomx");
    // Tell cargo to invalidate the built crate whenever the headers change
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=randomx.h");
}
