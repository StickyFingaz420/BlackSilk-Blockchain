use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=randomx.dll");
    println!("cargo:rerun-if-changed=randomx.h");
    
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let _target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    
    // Set up proper linking for RandomX
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=dylib=randomx");
        println!("cargo:rustc-link-search=native=.");
    } else if target_os == "linux" {
        // For Linux, we'll need to build RandomX from source or use system library
        println!("cargo:rustc-link-lib=randomx");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-search=native=/usr/lib");
    }
    
    // Generate bindings for RandomX C API
    let bindings = bindgen::Builder::default()
        .header("randomx.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate RandomX bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("randomx_bindings.rs"))
        .expect("Couldn't write RandomX bindings!");
        
    println!("cargo:warning=RandomX bindings generated successfully");
}
