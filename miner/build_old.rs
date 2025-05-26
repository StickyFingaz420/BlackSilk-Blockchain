use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=randomx.dll");
    println!("cargo:rerun-if-changed=randomx.h");
    println!("cargo:rerun-if-changed=RandomX/");
    
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    
    // Set up proper linking for RandomX
    if target_os == "windows" {
        setup_windows_build();
    } else if target_os == "linux" {
        setup_linux_build();
    } else {
        println!("cargo:warning=Target OS {} not explicitly supported, trying generic setup", target_os);
        setup_generic_build();
    }
    
    // Generate bindings for RandomX C API
    generate_bindings();
}

fn setup_windows_build() {
    println!("cargo:warning=Setting up Windows build for RandomX");
    
    // Check for RandomX library files
    let dll_exists = std::path::Path::new("randomx.dll").exists();
    let lib_exists = std::path::Path::new("randomx.lib").exists();
    
    if !dll_exists {
        println!("cargo:warning=randomx.dll not found in miner directory");
    }
    
    if !lib_exists {
        println!("cargo:warning=randomx.lib not found in miner directory");
        println!("cargo:warning=Windows builds require both randomx.dll and randomx.lib");
        println!("cargo:warning=Build RandomX using Visual Studio and copy both files to miner/");
        
        // Try to find in common build directories
        let possible_paths = [
            "../RandomX/build/Release/randomx.lib",
            "../RandomX/build/Debug/randomx.lib",
            "RandomX/build/Release/randomx.lib",
            "RandomX/build/Debug/randomx.lib",
        ];
        
        for path in &possible_paths {
            if std::path::Path::new(path).exists() {
                println!("cargo:warning=Found RandomX library at: {}", path);
                println!("cargo:rustc-link-search=native={}", std::path::Path::new(path).parent().unwrap().display());
                break;
            }
        }
    } else {
        println!("cargo:warning=Found randomx.lib, proceeding with build");
    }
    
    // Link with RandomX as dynamic library
    println!("cargo:rustc-link-lib=dylib=randomx");
    println!("cargo:rustc-link-search=native=.");
    
    // Additional Windows libraries that might be needed
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=kernel32");
}

fn setup_linux_build() {
    println!("cargo:warning=Setting up Linux build for RandomX");
    
    // Check for system-installed RandomX
    let system_paths = [
        "/usr/local/lib/librandomx.so",
        "/usr/lib/librandomx.so",
        "/usr/lib/x86_64-linux-gnu/librandomx.so",