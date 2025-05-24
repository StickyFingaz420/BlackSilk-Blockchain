fn main() {
    // Tell cargo to tell rustc to link the system randomx
    println!("cargo:rustc-link-lib=dylib=randomx");
    // If you build static, use: println!("cargo:rustc-link-lib=static=randomx");
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");
}
