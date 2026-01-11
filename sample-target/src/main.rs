use clap::Parser;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

#[derive(Parser, Debug)]
#[command(
    name = "sample-target",
    about = "Sample process that watches for a specific DLL to be injected."
)]
struct Args {
    #[arg(long, default_value = "test_dll.dll")]
    dll_name: String,

    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
}

fn wide_cstr_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn last_error() -> std::io::Error {
    let code = unsafe { GetLastError() } as i32;
    std::io::Error::from_raw_os_error(code)
}

fn has_module(pid: u32, dll_name_lower: &str) -> Result<bool, String> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(format!("CreateToolhelp32Snapshot failed: {}", last_error()));
    }

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut found = false;
    let mut ok = unsafe { Module32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        let name = wide_cstr_to_string(&entry.szModule);
        if name.to_lowercase() == dll_name_lower {
            found = true;
            break;
        }
        ok = unsafe { Module32NextW(snapshot, &mut entry) };
    }

    unsafe {
        CloseHandle(snapshot);
    }

    Ok(found)
}

fn main() {
    let args = Args::parse();
    let dll_name_lower = args.dll_name.to_lowercase();
    let pid = unsafe { GetCurrentProcessId() };

    println!("sample-target pid: {pid}");
    println!(
        "Watching for DLL named '{}' (case-insensitive). Inject using the injector and this PID.",
        args.dll_name
    );
    println!(
        "Polling every {} ms. Press Ctrl+C to exit.",
        args.interval_ms
    );

    let mut last_state: Option<bool> = None;
    loop {
        match has_module(pid, &dll_name_lower) {
            Ok(is_loaded) => {
                if last_state != Some(is_loaded) {
                    if is_loaded {
                        println!("Detected DLL '{}' loaded into this process.", args.dll_name);
                    } else if last_state.is_some() {
                        println!("DLL '{}' is no longer loaded.", args.dll_name);
                    } else {
                        println!("DLL '{}' not loaded yet.", args.dll_name);
                    }
                    last_state = Some(is_loaded);
                }
            }
            Err(err) => {
                eprintln!("Error checking modules: {err}");
                break;
            }
        }

        thread::sleep(Duration::from_millis(args.interval_ms));
    }
}
