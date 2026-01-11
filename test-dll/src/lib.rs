#![allow(non_snake_case)]

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE};
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut core::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe { DisableThreadLibraryCalls(hinst_dll) };
        let msg = to_wide("test-dll: DLL_PROCESS_ATTACH\n");
        unsafe {
            OutputDebugStringW(msg.as_ptr());
        }
    }

    1
}
