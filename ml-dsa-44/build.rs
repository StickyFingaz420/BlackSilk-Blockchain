fn main() {
    // C source files in crate root
    let c_files = [
        "ntt.c",
        "packing.c", 
        "poly.c",
        "polyvec.c",
        "reduce.c",
        "rounding.c",
        "sign.c",
        "symmetric-shake.c",
        "fips202.c",
        "randombytes.c",
        "memory_cleanse.c",
    ];

    // Build C library from crate root
    cc::Build::new()
        .files(&c_files)
        .include(".")
        .flag_if_supported("-O3")
        .flag_if_supported("-std=c99")
        .compile("ml-dsa-44-clean");

    // Tell cargo to link the library
    println!("cargo:rustc-link-lib=static=ml-dsa-44-clean");

    // Tell cargo to rerun build script if C files change
    for file in &c_files {
        println!("cargo:rerun-if-changed={}", file);
    }
    println!("cargo:rerun-if-changed=api.h");
}