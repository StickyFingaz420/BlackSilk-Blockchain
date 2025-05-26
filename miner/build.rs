use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=randomx.dll");
    println!("cargo:rerun-if-changed=randomx.h");
    println!("cargo:rerun-if-changed=RandomX/");
    
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let _target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    
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
        println!("cargo:warning=");
        println!("cargo:warning=❌ Windows RandomX Setup Required");
        println!("cargo:warning=");
        println!("cargo:warning=🚀 EASIEST SOLUTION: Run the easy build script:");
        println!("cargo:warning=   .\\easy_build.ps1   (PowerShell)");
        println!("cargo:warning=");
        println!("cargo:warning=📋 ALTERNATIVE: Run automated RandomX build:");
        println!("cargo:warning=   .\\build_randomx_windows.ps1   (PowerShell)");
        println!("cargo:warning=   or");
        println!("cargo:warning=   build_randomx_windows.bat      (Command Prompt)");
        println!("cargo:warning=");
        println!("cargo:warning=🔧 MANUAL BUILD: Build RandomX with Visual Studio 2022:");
        println!("cargo:warning=   1. Open 'RandomX' directory");
        println!("cargo:warning=   2. mkdir build && cd build");
        println!("cargo:warning=   3. cmake .. -G \"Visual Studio 17 2022\" -A x64");
        println!("cargo:warning=   4. cmake --build . --config Release");
        println!("cargo:warning=   5. Copy Release\\randomx.lib and Release\\randomx.dll to miner\\");
        println!("cargo:warning=");
        println!("cargo:warning=📖 See EASY_BUILD.md for complete instructions");
        println!("cargo:warning=");
        
        // Try to find in common build directories
        let possible_paths = [
            "../RandomX/build/Release/randomx.lib",
            "../RandomX/build/Debug/randomx.lib",
            "RandomX/build/Release/randomx.lib",
            "RandomX/build/Debug/randomx.lib",
            "../RandomX/vcxproj/x64/Release/randomx.lib",
            "../RandomX/vcxproj/x64/Debug/randomx.lib",
        ];
        
        for path in &possible_paths {
            if std::path::Path::new(path).exists() {
                println!("cargo:warning=💡 Found RandomX library at: {}", path);
                println!("cargo:warning=   You can copy it manually: copy {} randomx.lib", path);
                println!("cargo:rustc-link-search=native={}", std::path::Path::new(path).parent().unwrap().display());
                break;
            }
        }
    } else {
        println!("cargo:warning=✅ Found randomx.lib, proceeding with Windows build");
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
    
    // Check for local build first (highest priority)
    let local_static = std::path::Path::new("librandomx.a");
    let local_dynamic = std::path::Path::new("librandomx.so");
    
    if local_static.exists() {
        println!("cargo:warning=✅ Found local RandomX static library: librandomx.a");
        // Get absolute path to ensure linker can find it
        let absolute_path = std::fs::canonicalize(".").unwrap();
        println!("cargo:rustc-link-search=native={}", absolute_path.display());
        println!("cargo:rustc-link-lib=static=randomx");
        // Link C++ standard library for static RandomX
        println!("cargo:rustc-link-lib=stdc++");
        return;
    }
    
    if local_dynamic.exists() {
        println!("cargo:warning=✅ Found local RandomX dynamic library: librandomx.so");
        // Get absolute path to ensure linker can find it
        let absolute_path = std::fs::canonicalize(".").unwrap();
        println!("cargo:rustc-link-search=native={}", absolute_path.display());
        println!("cargo:rustc-link-lib=randomx");
        return;
    }
    
    // Check for RandomX build directory
    let build_paths = [
        "../RandomX/build/librandomx.a",
        "RandomX/build/librandomx.a",
        "../RandomX/build/librandomx.so",
        "RandomX/build/librandomx.so",
    ];
    
    for path in &build_paths {
        if std::path::Path::new(path).exists() {
            println!("cargo:warning=✅ Found RandomX at: {}", path);
            let dir = std::path::Path::new(path).parent().unwrap().display();
            println!("cargo:rustc-link-search=native={}", dir);
            if path.ends_with(".a") {
                println!("cargo:rustc-link-lib=static=randomx");
                println!("cargo:rustc-link-lib=stdc++");
            } else {
                println!("cargo:rustc-link-lib=randomx");
            }
            return;
        }
    }
    
    // Check for system-installed RandomX
    let system_paths = [
        "/usr/local/lib/librandomx.so",
        "/usr/lib/librandomx.so",
        "/usr/lib/x86_64-linux-gnu/librandomx.so",
        "/usr/local/lib/librandomx.a",
        "/usr/lib/librandomx.a",
        "/usr/lib/x86_64-linux-gnu/librandomx.a",
    ];
    
    for path in &system_paths {
        if std::path::Path::new(path).exists() {
            println!("cargo:warning=✅ Found system RandomX at: {}", path);
            if path.ends_with(".a") {
                println!("cargo:rustc-link-lib=static=randomx");
                println!("cargo:rustc-link-lib=stdc++");
            } else {
                println!("cargo:rustc-link-lib=randomx");
            }
            let dir = std::path::Path::new(path).parent().unwrap().display();
            println!("cargo:rustc-link-search=native={}", dir);
            return;
        }
    }
    
    // If no RandomX library found, provide helpful guidance
    println!("cargo:warning=");
    println!("cargo:warning=❌ RandomX library not found!");
    println!("cargo:warning=");
    println!("cargo:warning=🚀 EASIEST SOLUTION: Run the easy build script:");
    println!("cargo:warning=   ./easy_build.sh");
    println!("cargo:warning=");
    println!("cargo:warning=🔧 MANUAL SOLUTION: Build RandomX manually:");
    println!("cargo:warning=   ./setup_randomx.sh");
    println!("cargo:warning=   OR");
    println!("cargo:warning=   git clone https://github.com/tevador/RandomX.git");
    println!("cargo:warning=   cd RandomX && mkdir build && cd build");
    println!("cargo:warning=   cmake .. && make -j$(nproc)");
    println!("cargo:warning=   cp librandomx.a ../miner/");
    println!("cargo:warning=");
    println!("cargo:warning=📖 See EASY_BUILD.md for complete instructions");
    
    // Fallback: try to link with RandomX and hope it's in system paths
    println!("cargo:warning=⚠️ Attempting fallback linking, may fail");
    println!("cargo:rustc-link-lib=randomx");
    
    // Standard library search paths
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
}

fn setup_generic_build() {
    println!("cargo:rustc-link-lib=randomx");
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/lib");
}

fn generate_bindings() {
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
