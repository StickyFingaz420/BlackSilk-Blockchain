use std::env;
use std::path::PathBuf;

fn main() {
    // Build libbitcoinpqc C library via CMake
    let dst = cmake::Config::new("../libbitcoinpqc").build();
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    // Link to the libbitcoinpqc static library (Debug build on Windows)
    println!("cargo:rustc-link-search=native=../libbitcoinpqc/build/lib/Debug");
    println!("cargo:rustc-link-lib=static=bitcoinpqc");

    println!("cargo:rerun-if-changed=../libbitcoinpqc/include/libbitcoinpqc/bitcoinpqc.h");
    let header_path = std::fs::canonicalize("../libbitcoinpqc/include/libbitcoinpqc/bitcoinpqc.h").expect("Header not found");
    println!("cargo:warning=Using header: {}", header_path.display());
    // Generate Rust bindings
    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .clang_arg("-I../libbitcoinpqc/include")
        .clang_arg("-v")
        .allowlist_function("bitcoin_pqc_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap_or_else(|e| panic!("[build.rs] bindgen failed: {:?}", e));
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pqc_bindings.rs"))
        .expect("Couldn't write bindings!");
}
