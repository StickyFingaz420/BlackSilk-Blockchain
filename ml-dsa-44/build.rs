fn main() {
    // C source files based on Makefile
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

    // Build C library
    cc::Build::new()
        .files(&c_files)
        .include("c")
        .flag("-O3")
        .flag("-std=c99")
        .compile("ml-dsa-44-clean");

    // Tell cargo to link the library
    println!("cargo:rustc-link-lib=static=ml-dsa-44-clean");

    // Tell cargo to rerun build script if C files change
    for file in &c_files {
        println!("cargo:rerun-if-changed={}", file);
    }
    println!("cargo:rerun-if-changed=c/api.h");
}