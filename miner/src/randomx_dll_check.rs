//! Runtime check for RandomX DLL loading and symbol resolution
use std::ffi::CString;
use std::ptr;

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
            panic!("[RandomX DLL] randomx.dll could not be loaded! Make sure it is present in the miner directory.");
        }
        let symbol = CString::new("randomx_get_flags").unwrap();
        let sym_ptr = GetProcAddress(handle, symbol.as_ptr());
        if sym_ptr.is_null() {
            FreeLibrary(handle);
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
