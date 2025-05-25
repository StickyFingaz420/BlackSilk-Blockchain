//! Runtime check for RandomX DLL loading and symbol resolution

#[cfg(target_os = "windows")]
pub fn check_randomx_dll() {
    use std::os::raw::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    use std::mem;
    use std::io::Error;
    use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress, FreeLibrary};
    use winapi::shared::minwindef::HMODULE;

    let dll_path = OsStr::new("randomx.dll").encode_wide().chain(Some(0)).collect::<Vec<_>>();
    unsafe {
        let handle: HMODULE = LoadLibraryW(dll_path.as_ptr());
        if handle.is_null() {
            eprintln!("[RandomX DLL] randomx.dll could not be loaded!\n\
  - Ensure randomx.dll is present in the same directory as blacksilk-miner.exe.\n\
  - If you just built RandomX, copy the DLL from RandomX/build/Release/randomx.dll.\n\
  - If you see this error after copying, ensure the DLL is not blocked by Windows (right-click > Properties > Unblock).\n\
  - If you are on Windows, ensure you have the correct architecture (x64 DLL for x64 miner).\n\
  - If the problem persists, rebuild RandomX as described in the README.\n");
            panic!("[RandomX DLL] randomx.dll could not be loaded!");
        }
        let symbol = CString::new("randomx_get_flags").unwrap();
        let sym_ptr = GetProcAddress(handle, symbol.as_ptr());
        if sym_ptr.is_null() {
            FreeLibrary(handle);
            eprintln!("[RandomX DLL] randomx_get_flags symbol not found in randomx.dll!\n\
  - This usually means the DLL is outdated or not built with all features.\n\
  - Rebuild RandomX using CMake and Visual Studio, then copy the new DLL.\n\
  - See the BlackSilk README for build instructions.\n\
  - You can check exported symbols with: dumpbin /EXPORTS randomx.dll | findstr randomx_get_flags\n");
            panic!("[RandomX DLL] randomx_get_flags symbol not found in randomx.dll!");
        }
        FreeLibrary(handle);
    }
    println!("[RandomX DLL] randomx.dll loaded and symbol found.");
}

#[cfg(not(target_os = "windows"))]
pub fn check_randomx_dll() {
    // No-op on non-Windows
}
